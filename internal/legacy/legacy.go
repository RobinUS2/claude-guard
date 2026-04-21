// Package legacy implements tier 5: the migrated allow list from
// Claude Code's settings.json permissions.allow array.
//
// The format of those entries is Claude Code's: each entry is a
// string like Bash(<pattern>:*) or Bash(<pattern>) where the pattern
// is a literal command prefix that may contain * wildcards. Examples
// from a real settings.json:
//
//	Bash(ls:*)
//	Bash(git status:*)
//	Bash(make test*:*)
//	Bash(gcloud builds list:*)
//	Bash(npm run test:unit:*)
//
// We extract Bash() entries and convert them to glob-style prefix
// matchers. Non-Bash entries (Read, Write, WebFetch, mcp__*) are
// skipped because the guard's tier 4 LLM only handles Bash for v1.
//
// Tier 5 is the safety net during phase 4 of the rollout: any command
// the smarter tiers don't recognize but that was previously allowed
// in settings.json continues to flow through. Once shadow-mode shows
// the legacy list isn't catching anything new, it can be retired.
package legacy

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Pattern is one parsed legacy allow entry.
type Pattern struct {
	// Source is the original settings.json string (e.g. "Bash(ls:*)"),
	// kept verbatim so users editing the migrated YAML have a stable
	// reference to grep for.
	Source string `yaml:"source"`
	// Prefix is the cleaned-up Bash command pattern (e.g. "ls",
	// "git status", "make test*").
	Prefix string `yaml:"prefix"`
	// regex is the compiled matcher built from Prefix. * wildcards in
	// Prefix become .* in the regex; everything else is literal-quoted.
	regex *regexp.Regexp
}

// File is the on-disk YAML shape produced by claude-guard migrate.
type File struct {
	Version  int       `yaml:"version"`
	Source   string    `yaml:"source"`
	Patterns []Pattern `yaml:"patterns"`
	// Skipped is a count + sample of entries we didn't migrate, kept
	// for migration-debugging purposes only.
	Skipped []string `yaml:"skipped,omitempty"`
}

const SchemaVersion = 1

// AllowList is the in-memory, ready-to-match form of File.
// Construct via Load. Safe for concurrent use after construction.
type AllowList struct {
	Patterns []Pattern
}

// unsafeLegacyPrograms are first-word programs whose blanket tier-5
// allow would undo tighter tier-2 / tier-1 rules added in the 2026-04
// hardening. Patterns whose Prefix starts with any of these are
// silently dropped at Load time and at migration time. Defense in
// depth: even if `claude-guard migrate` re-runs against an old
// settings.json, these entries never materialize into tier-5 allows.
//
// Rationale per program:
//   - awk/sed/find/env — system() / getline / -exec / wrapper shapes
//     with built-in shell escapes (red-team C-1, C-2; plan steps 8-9)
//   - make — target names are user-defined; target body is arbitrary
//     shell (red-team C-6; plan step 10)
//   - bash/sh/zsh/… — `<shell> -c '…'` opaque script (plan step 13)
//   - python/python3/perl/ruby/node — same `-c`/`-e` opaque-script
//     shape (red-team C-7 #12 found python3 escaped legacy)
var unsafeLegacyPrograms = map[string]struct{}{
	"awk": {}, "sed": {}, "find": {}, "env": {},
	"make": {},
	"bash": {}, "sh": {}, "zsh": {}, "fish": {}, "dash": {},
	"ksh": {}, "tcsh": {}, "csh": {},
	"python": {}, "python3": {}, "perl": {}, "ruby": {}, "node": {},
}

// unsafeLegacyPrefixes are multi-word Prefix starts that should be
// dropped. Used for shapes like `docker exec <container> sh` where
// the program (`docker`) is legitimate in isolation but the (noun,
// verb) combo in legacy subsumes a tier-1-enforced deny.
var unsafeLegacyPrefixes = []string{
	"docker exec",      // shell into running container
	"docker run",       // arbitrary image execution (red-team)
	"terraform init",   // also handled by tier-1 state rules
	"terraform import", // mutates state; tier-1 denies now
}

// isUnsafeLegacy reports whether the given legacy prefix should be
// filtered out. Called from both parseEntry (fresh migration) and
// Load (existing YAML), so old migrations get sanitized without
// requiring users to re-run `claude-guard migrate`.
func isUnsafeLegacy(prefix string) bool {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return true
	}
	// First-word program check.
	first := prefix
	if i := strings.IndexByte(prefix, ' '); i >= 0 {
		first = prefix[:i]
	}
	if _, bad := unsafeLegacyPrograms[first]; bad {
		return true
	}
	// Multi-word prefix check.
	for _, up := range unsafeLegacyPrefixes {
		if prefix == up || strings.HasPrefix(prefix, up+" ") {
			return true
		}
	}
	return false
}

// Load reads a migrated legacy YAML file from disk and compiles its
// patterns. Returns an empty (matches-nothing) AllowList if the file
// is missing — that's the desired fail-open behavior, not an error.
//
// Patterns matching isUnsafeLegacy are dropped at load time, even if
// the file was generated before the 2026-04 hardening. This means the
// live binary applies the post-hardening tier-5 shape regardless of
// when the legacy YAML was last migrated.
func Load(path string) (*AllowList, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &AllowList{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read legacy file: %w", err)
	}
	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse legacy yaml: %w", err)
	}
	out := make([]Pattern, 0, len(f.Patterns))
	for _, p := range f.Patterns {
		if isUnsafeLegacy(p.Prefix) {
			continue
		}
		if err := p.compile(); err == nil {
			out = append(out, p)
		}
	}
	return &AllowList{Patterns: out}, nil
}

// TrustedPrograms returns the deduplicated, lexically-sorted set of
// first-word programs appearing in the allow list. Used as a hint for
// the LLM classifier: "these CLIs are pre-approved for bare calls, so
// reason about compound shapes (loops, pipelines) with that context".
//
// Shells and script-interpreters are already filtered out of Patterns
// at Load/migrate time via isUnsafeLegacy, so the output is safe to
// embed in the classifier prompt.
//
// maxPrograms caps the returned slice — the prompt has a finite budget
// and a very long list dilutes signal. 0 or negative = no cap.
func (a *AllowList) TrustedPrograms(maxPrograms int) []string {
	if a == nil || len(a.Patterns) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(a.Patterns))
	out := make([]string, 0, len(a.Patterns))
	for _, p := range a.Patterns {
		prefix := strings.TrimSpace(p.Prefix)
		if prefix == "" {
			continue
		}
		first, _, _ := strings.Cut(prefix, " ")
		// Strip any trailing glob-star so e.g. "make*" → "make" would
		// collapse together. That case is already filtered by
		// isUnsafeLegacy, but be defensive.
		first = strings.TrimRight(first, "*")
		if first == "" {
			continue
		}
		if _, dup := seen[first]; dup {
			continue
		}
		seen[first] = struct{}{}
		out = append(out, first)
	}
	sort.Strings(out)
	if maxPrograms > 0 && len(out) > maxPrograms {
		out = out[:maxPrograms]
	}
	return out
}

// Match returns the first matching pattern, or nil if none match.
// The check is a regex anchored at the start of the command — i.e.
// "did the user's command start with one of the allowed prefixes?".
func (a *AllowList) Match(command string) *Pattern {
	if a == nil {
		return nil
	}
	command = strings.TrimSpace(command)
	for i := range a.Patterns {
		if a.Patterns[i].regex != nil && a.Patterns[i].regex.MatchString(command) {
			return &a.Patterns[i]
		}
	}
	return nil
}

// compile builds the regex from the Prefix.
func (p *Pattern) compile() error {
	if p.Prefix == "" {
		return fmt.Errorf("empty prefix")
	}
	// Quote everything literally, then unquote the * wildcards.
	quoted := regexp.QuoteMeta(p.Prefix)
	expanded := strings.ReplaceAll(quoted, `\*`, `.*`)
	// Anchor at start; the entry is a prefix match.
	//
	// Trailing-char class deliberately does NOT include `<` or `>`:
	// a legacy allow like `Bash(echo:*)` must NOT match
	// `echo evil > /etc/hosts` — redirects change semantics by
	// writing/reading a path, which needs fresh safety evaluation.
	// Step 5's redir-aware PathAccess + step 6's extended-credentials
	// rules catch the dangerous targets. Pipes (`|`), sequences
	// (`;`), and background (`&`) stay in the class to preserve
	// benign shapes like `ls | head`.
	re, err := regexp.Compile(`^` + expanded + `($|[\s|;&])`)
	if err != nil {
		return fmt.Errorf("compile pattern %q: %w", p.Prefix, err)
	}
	p.regex = re
	return nil
}

// --- Migration ---

// ParseSettingsAllowList walks the strings from settings.json
// permissions.allow and returns parsed Bash patterns plus the entries
// that were skipped (non-Bash, malformed, etc.). It does not touch
// the filesystem; callers handle loading and writing.
func ParseSettingsAllowList(entries []string) (patterns []Pattern, skipped []string) {
	for _, entry := range entries {
		p, ok := parseEntry(entry)
		if ok {
			patterns = append(patterns, p)
		} else {
			skipped = append(skipped, entry)
		}
	}
	// Stable order so migrations are reproducible.
	sort.SliceStable(patterns, func(i, j int) bool {
		return patterns[i].Prefix < patterns[j].Prefix
	})
	return patterns, skipped
}

// parseEntry converts a single settings.json string into a Pattern.
// Returns (pattern, true) on success or (zero, false) on a non-Bash
// or unparseable entry.
func parseEntry(entry string) (Pattern, bool) {
	entry = strings.TrimSpace(entry)
	if !strings.HasPrefix(entry, "Bash(") || !strings.HasSuffix(entry, ")") {
		return Pattern{}, false
	}
	inner := entry[len("Bash(") : len(entry)-1]
	// Strip trailing :*  meaning "any args after the prefix".
	inner = strings.TrimSuffix(inner, ":*")
	inner = strings.TrimSpace(inner)
	if inner == "" {
		return Pattern{}, false
	}
	p := Pattern{
		Source: entry,
		Prefix: inner,
	}
	// Drop programs / prefixes that the 2026-04 hardening moved out
	// of tier 2 — keeping them in tier 5 would undo the hardening.
	if isUnsafeLegacy(inner) {
		return Pattern{}, false
	}
	// Reject patterns that contain shell metachars we can't safely
	// match prefix-style — e.g. complete commands with embedded
	// quotes/redirects/pipes. These are usually one-off entries that
	// the LLM tier should re-evaluate anyway.
	if hasUnsupported(inner) {
		return Pattern{}, false
	}
	if err := p.compile(); err != nil {
		return Pattern{}, false
	}
	return p, true
}

// hasUnsupported returns true for patterns we deliberately skip during
// migration. These include patterns with shell quoting, redirection,
// pipes, command substitution, or literal newlines.
//
// Why so strict: tier 5 patterns are matched as prefix allows. If we
// migrated `Bash(curl URL | sh)` from settings.json, we'd be granting
// future curl|sh commands a free pass — defeating tier 1's whole
// point. Better to skip metachar-bearing entries during migration; if
// they're commands the user really wants, they'll re-encounter the
// prompt and can re-add to the new config or be classified by the LLM.
func hasUnsupported(s string) bool {
	for _, ch := range []string{
		"\n", "\\\"",
		"<<", ">>", ">", "<",
		"$(", "${", "`",
		"&&", "||", "|", ";", "&",
	} {
		if strings.Contains(s, ch) {
			return true
		}
	}
	return false
}

// WriteFile serializes the migration result to disk.
func WriteFile(path string, f *File) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	data, err := yaml.Marshal(f)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	return os.Rename(tmp, path)
}

// MigrateSettingsJSON reads ~/.claude/settings.json, extracts the
// permissions.allow array, parses every Bash entry, and returns a
// File ready to be written to disk.
//
// Returns an empty File if the input has no permissions.allow key.
func MigrateSettingsJSON(jsonData []byte) (*File, error) {
	var raw struct {
		Permissions struct {
			Allow []string `json:"allow"`
		} `json:"permissions"`
	}
	if err := yamlJSONUnmarshal(jsonData, &raw); err != nil {
		return nil, fmt.Errorf("parse settings.json: %w", err)
	}
	patterns, skipped := ParseSettingsAllowList(raw.Permissions.Allow)
	return &File{
		Version:  SchemaVersion,
		Source:   "claude-guard migrate from settings.json",
		Patterns: patterns,
		Skipped:  skipped,
	}, nil
}

// yamlJSONUnmarshal accepts JSON and decodes it into a struct. We use
// yaml.v3 here (not encoding/json) because settings.json sometimes
// contains real JSON comments via inline strings, and yaml.v3's parser
// is more forgiving on those edge cases.
func yamlJSONUnmarshal(data []byte, dst any) error {
	return yaml.Unmarshal(data, dst)
}
