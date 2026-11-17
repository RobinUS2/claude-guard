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
// Matching is per call on the parsed shell AST (MatchParsed): a command
// is allowed only when it is one call, or a plain pipeline of calls, and
// every call matches an entry by itself. Compound commands and anything
// that carries code the patterns cannot see fall through to the prompt.
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
	"mvdan.cc/sh/v3/syntax"

	"github.com/RobinUS2/claude-guard/internal/shellparse"
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
	// Wrappers whose arguments are another command. A per-call match
	// on the wrapper would approve whatever command it runs.
	"xargs": {}, "eval": {}, "exec": {}, "command": {}, "builtin": {},
	"source": {}, ".": {}, "nohup": {}, "nice": {}, "timeout": {},
	"gtimeout": {}, "time": {}, "watch": {}, "parallel": {},
	"sudo": {}, "doas": {}, "su": {},
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

// Match parses command and returns the pattern that allowed it, or nil.
// Convenience wrapper around MatchParsed for callers that only have the
// raw string; a parse failure never matches.
func (a *AllowList) Match(command string) *Pattern {
	if a == nil || len(a.Patterns) == 0 {
		return nil
	}
	p, err := shellparse.Parse(command)
	if err != nil {
		return nil
	}
	return a.MatchParsed(p)
}

// MatchParsed is the tier-5 matcher. It returns a non-nil pattern only
// when the parsed command is a single statement made of one simple call,
// or a plain pipeline of simple calls, and EVERY call matches a legacy
// pattern on its own. The returned pattern is the one that matched the
// first call (used for the decision log).
//
// Settings.json entries are prefix patterns whose `*` matches anything,
// so matching them against the raw command string would let a prefix
// that is allowed carry along whatever follows it after a separator.
// Here each pattern only ever sees the words of one call.
//
// Anything outside the narrow accepted shape returns nil so the command
// falls through to the user prompt. Rejected, regardless of patterns:
//   - more than one statement (`;`, newline), `&&`, `||`, background `&`,
//     negation, coprocesses
//   - subshells, groups, loops, conditionals, function and variable
//     declarations: any command node other than a call or a pipe
//   - command, process and arithmetic substitution anywhere in the AST
//   - heredocs, here-strings, input redirects and output redirects other
//     than fd duplication (`2>&1`) or writes to /dev/null
//   - env-var assignments in front of a call (`X=y prog`)
//   - a command word that is not one plain literal: quoted, escaped,
//     expanded, globbed or brace-expanded program names
//   - a program that runs a script or another command (shells,
//     interpreters, exec wrappers), even if a pattern would match it
//   - argument words with expansions other than plain `$NAME`/`${NAME}`
func (a *AllowList) MatchParsed(p *shellparse.Parsed) *Pattern {
	if a == nil || len(a.Patterns) == 0 || p == nil || p.File == nil {
		return nil
	}
	calls, ok := legacyCalls(p.File)
	if !ok || len(calls) == 0 {
		return nil
	}
	var first *Pattern
	for _, ce := range calls {
		text, ok := callText(p.Raw, ce)
		if !ok {
			return nil
		}
		m := a.matchCallText(text)
		if m == nil {
			return nil
		}
		if first == nil {
			first = m
		}
	}
	return first
}

// matchCallText runs the compiled patterns against the text of one call.
func (a *AllowList) matchCallText(text string) *Pattern {
	for i := range a.Patterns {
		if a.Patterns[i].regex != nil && a.Patterns[i].regex.MatchString(text) {
			return &a.Patterns[i]
		}
	}
	return nil
}

// legacyCalls returns the simple calls of a command the legacy tier is
// allowed to judge, in order, or ok=false when the shape is outside what
// it may auto-allow (see MatchParsed).
func legacyCalls(f *syntax.File) (calls []*syntax.CallExpr, ok bool) {
	if len(f.Stmts) != 1 {
		return nil, false
	}
	// No substitution of any kind may appear anywhere: each one runs or
	// evaluates code that no pattern has seen.
	clean := true
	syntax.Walk(f, func(n syntax.Node) bool {
		switch n.(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst, *syntax.ArithmExp,
			*syntax.ArithmCmd, *syntax.Subshell, *syntax.Block:
			clean = false
		}
		return clean
	})
	if !clean {
		return nil, false
	}
	var walk func(s *syntax.Stmt) bool
	walk = func(s *syntax.Stmt) bool {
		if s == nil || s.Cmd == nil || s.Negated || s.Background || s.Coprocess || s.Disown {
			return false
		}
		if !redirsAllowed(s.Redirs) {
			return false
		}
		switch c := s.Cmd.(type) {
		case *syntax.CallExpr:
			if len(c.Assigns) > 0 || len(c.Args) == 0 {
				return false
			}
			calls = append(calls, c)
			return true
		case *syntax.BinaryCmd:
			if c.Op != syntax.Pipe && c.Op != syntax.PipeAll {
				return false
			}
			return walk(c.X) && walk(c.Y)
		default:
			return false
		}
	}
	if !walk(f.Stmts[0]) {
		return nil, false
	}
	return calls, true
}

// redirsAllowed accepts only redirections that cannot read a file into
// the command or write one: fd duplication to a numbered fd (`2>&1`,
// `>&2`, `<&0`) and output to /dev/null. Heredocs and here-strings feed
// a script body to the program, so they are always rejected.
func redirsAllowed(rs []*syntax.Redirect) bool {
	for _, r := range rs {
		if r == nil || r.Word == nil {
			return false
		}
		w, ok := plainLit(r.Word)
		if !ok {
			return false
		}
		switch r.Op {
		case syntax.DplOut, syntax.DplIn:
			if !isFdNumber(w) {
				return false
			}
		case syntax.RdrOut, syntax.AppOut, syntax.RdrAll, syntax.AppAll:
			if w != "/dev/null" {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func isFdNumber(s string) bool {
	if s == "-" {
		return true
	}
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// plainLit returns the value of a word that is exactly one unquoted
// literal, or ok=false.
func plainLit(w *syntax.Word) (string, bool) {
	if w == nil || len(w.Parts) != 1 {
		return "", false
	}
	lit, ok := w.Parts[0].(*syntax.Lit)
	if !ok {
		return "", false
	}
	return lit.Value, true
}

// callText renders one call as the text the patterns match against: the
// source of each word joined by single spaces, so redirections between
// words are dropped. ok=false when the program word or an argument word
// is a shape the legacy tier must not judge.
func callText(raw string, ce *syntax.CallExpr) (string, bool) {
	prog, ok := plainLit(ce.Args[0])
	if !ok || prog == "" || strings.ContainsAny(prog, "\\*?[]{}$`'\"") {
		return "", false
	}
	if programRunsOtherCode(prog) {
		return "", false
	}
	parts := make([]string, 0, len(ce.Args))
	parts = append(parts, prog)
	for _, w := range ce.Args[1:] {
		if !argWordAllowed(w) {
			return "", false
		}
		start, end := int(w.Pos().Offset()), int(w.End().Offset())
		if start < 0 || end > len(raw) || start > end {
			return "", false
		}
		parts = append(parts, raw[start:end])
	}
	return strings.Join(parts, " "), true
}

// programRunsOtherCode reports whether the program (by basename, so an
// absolute path does not hide it) is one the legacy tier never allows
// because its arguments are themselves a command or a script.
func programRunsOtherCode(prog string) bool {
	_, bad := unsafeLegacyPrograms[filepath.Base(prog)]
	return bad
}

// argWordAllowed accepts literals, quoted strings and plain variable
// references. Indirect, subscripted or operator expansions can evaluate
// arbitrary code through the variable's value, so they are rejected.
func argWordAllowed(w *syntax.Word) bool {
	if w == nil {
		return false
	}
	for _, part := range w.Parts {
		if !argPartAllowed(part) {
			return false
		}
	}
	return true
}

func argPartAllowed(part syntax.WordPart) bool {
	switch p := part.(type) {
	case *syntax.Lit, *syntax.SglQuoted:
		return true
	case *syntax.ParamExp:
		return simpleParam(p)
	case *syntax.DblQuoted:
		for _, inner := range p.Parts {
			switch ip := inner.(type) {
			case *syntax.Lit:
			case *syntax.ParamExp:
				if !simpleParam(ip) {
					return false
				}
			default:
				return false
			}
		}
		return true
	default:
		return false
	}
}

func simpleParam(p *syntax.ParamExp) bool {
	return p.Param != nil && p.Flags == nil && !p.Excl && !p.Length &&
		!p.Width && !p.IsSet && p.NestedParam == nil && p.Index == nil &&
		len(p.Modifiers) == 0 && p.Slice == nil && p.Repl == nil &&
		p.Names == 0 && p.Exp == nil
}

// compile builds the regex from the Prefix.
func (p *Pattern) compile() error {
	if p.Prefix == "" {
		return fmt.Errorf("empty prefix")
	}
	// Quote everything literally, then unquote the * wildcards.
	quoted := regexp.QuoteMeta(p.Prefix)
	expanded := strings.ReplaceAll(quoted, `\*`, `.*`)
	// Anchor at start; the entry is a prefix match on the text of ONE
	// call (see MatchParsed), never on the whole command string, so the
	// trailing `.*` of a `foo *` entry cannot reach past a separator.
	// The word-boundary class keeps `ls` from matching `lsof`. Redirects
	// and separators never appear in the call text: MatchParsed rejects
	// or strips them before matching.
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

// FromEntries builds an AllowList from settings.json-style entries, one
// per line in text; blank lines and `#` comments are skipped. Used for
// the embedded fixture list of the legacy corpora (tests and `lint`).
func FromEntries(text string) *AllowList {
	var entries []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entries = append(entries, line)
	}
	patterns, _ := ParseSettingsAllowList(entries)
	return &AllowList{Patterns: patterns}
}
