// Package rules implements AST-based matchers for the instant_block (tier 1)
// and instant_allow (tier 2) evaluators.
//
// All matchers operate on a *shellparse.Parsed, never on the raw command
// string. This is the whole point of the guard: `rm -rf /` and `R=rm; $R -rf /`
// and `/bin/rm -r -f /` must behave the same way (the first two fall through
// to the LLM / user prompt because their target resolves to $R or their
// program is unresolvable; the third is matched). Regex on the raw string
// would be trivially bypassable.
//
// Matchers are stateless and safe for concurrent use.
package rules

import (
	"path/filepath"
	"runtime"
	"strings"

	"github.com/RobinUS2/claude-guard/internal/shellparse"
)

// Verdict is the result of evaluating a single rule against a parsed script.
type Verdict int

const (
	// NoMatch means the rule did not apply. Evaluation continues.
	NoMatch Verdict = iota
	// Match means the rule applied. For block rules this is a BLOCK; for
	// allow rules this is an ALLOW. Callers know which list they evaluated.
	Match
)

// Rule is the interface every matcher implements.
type Rule interface {
	// Name is a stable identifier for logs, explain output, and tests.
	Name() string
	// Kind is the matcher family, used for config-driven instantiation.
	Kind() string
	// Eval returns (Match, reason) or (NoMatch, "").
	Eval(p *shellparse.Parsed) (Verdict, string)
}

// --- AnchoredCommand: an allow rule that matches a single, simple command
// with no shell features that change its semantics.
//
// Matches when:
//   - exactly one top-level call
//   - call is at NestTopLevel
//   - no redirections, pipes, subshells, command substitution, process
//     substitution, background, or binary operators in the script
//   - call.Program is in Programs (literal match, no regex)
//   - call is fully resolved (no variable expansion)
//   - optionally: a subcommand argument is in RequireSubcommands
//   - optionally: no flag in ForbidFlags is present
//
// This is the only matcher that AUTO-APPROVES based on command shape.
// Everything else is belt-and-suspenders or BLOCK.

// AnchoredCommand matches read-only commands with no shell trickery.
type AnchoredCommand struct {
	RuleName         string
	Programs         []string
	RequireSubcmdAny []string // if non-empty, first positional arg must be in this list
	ForbidFlags      []string // reject if any of these flags appear
}

func (r *AnchoredCommand) Name() string { return r.RuleName }
func (r *AnchoredCommand) Kind() string { return "anchored_command" }

func (r *AnchoredCommand) Eval(p *shellparse.Parsed) (Verdict, string) {
	f := p.Features
	// Reject anything with shell trickery.
	if f.HasRedirect || f.HasPipe || f.HasSubshell || f.HasCmdSub ||
		f.HasProcSub || f.HasBackground || f.HasBinaryOp || f.HasMultiStmt {
		return NoMatch, ""
	}
	if len(p.Calls) != 1 {
		return NoMatch, ""
	}
	c := p.Calls[0]
	if c.Nesting != shellparse.NestTopLevel || c.HasUnresolved {
		return NoMatch, ""
	}
	if !stringIn(c.Program, r.Programs) {
		return NoMatch, ""
	}
	if len(r.RequireSubcmdAny) > 0 {
		if len(c.Positional) == 0 || !stringIn(c.Positional[0], r.RequireSubcmdAny) {
			return NoMatch, ""
		}
	}
	for _, forbidden := range r.ForbidFlags {
		if anchoredFlagForbidden(c.Flags, forbidden) {
			return NoMatch, ""
		}
	}
	return Match, r.RuleName
}

// anchoredFlagForbidden returns true when a ForbidFlags entry matches
// one of the call's flag tokens. Matching rules:
//
//   - Exact string match (`--force` matches `--force`).
//   - Key=value form: `--force` matches `--force=value`.
//   - Prefix form for long flags: `--force` ALSO matches any flag
//     starting with `--force-` (catches `--force-with-lease` when the
//     user wrote `--force`). This widens the config author's reach
//     without requiring them to enumerate every derivative flag.
//   - Short-flag unpacking: `-f` matches `-fR`, `-Rf`, `-rfu`, etc.
//     Required because shellparse stores combined short flags as one
//     token.
//
// The prior implementation missed points 3 and 4 — a project config
// saying `forbid_flags: ["-f"]` would silently fail for a command
// like `cmd -rf foo`, and `forbid_flags: ["--force"]` would miss
// `--force-with-lease`. Both were live security bugs.
func anchoredFlagForbidden(callFlags []string, forbidden string) bool {
	// Long flag
	if strings.HasPrefix(forbidden, "--") {
		for _, f := range callFlags {
			if f == forbidden {
				return true
			}
			if strings.HasPrefix(f, forbidden+"=") {
				return true
			}
			if strings.HasPrefix(f, forbidden+"-") {
				return true
			}
		}
		return false
	}
	// Short flag (length 2: `-x`). Check combined short flags too.
	if strings.HasPrefix(forbidden, "-") && len(forbidden) == 2 {
		want := rune(forbidden[1])
		for _, f := range callFlags {
			if f == forbidden {
				return true
			}
			if strings.HasPrefix(f, forbidden+"=") {
				return true
			}
			// Combined short flags like `-rf` or `-fR`: look at each
			// letter in the token's short-flag portion.
			if strings.HasPrefix(f, "-") && !strings.HasPrefix(f, "--") && len(f) > 2 {
				for _, ch := range f[1:] {
					if ch == want {
						return true
					}
				}
			}
		}
		return false
	}
	// Other shapes (not starting with -) — treat as exact/prefix only.
	for _, f := range callFlags {
		if f == forbidden || strings.HasPrefix(f, forbidden+"=") {
			return true
		}
	}
	return false
}

// --- ProgramIs: a block rule that fires when any top-level call's program
// matches (literal). Used for `sudo` — if sudo appears anywhere at top level,
// the command needs user approval.

// ProgramIs blocks if any top-level call's program is in Programs.
type ProgramIs struct {
	RuleName string
	Programs []string
	Reason   string
}

func (r *ProgramIs) Name() string { return r.RuleName }
func (r *ProgramIs) Kind() string { return "program_is" }

func (r *ProgramIs) Eval(p *shellparse.Parsed) (Verdict, string) {
	for _, c := range p.Calls {
		if c.Nesting != shellparse.NestTopLevel {
			continue
		}
		if stringIn(c.Program, r.Programs) {
			return Match, r.Reason
		}
	}
	return NoMatch, ""
}

// --- BlockedCommand: a block rule for destructive commands like `rm -rf /`.
// Matches when a call has:
//   - program in Programs
//   - ALL flag sets in RequireFlagsAll are present (e.g. [-r OR -R OR --recursive]
//     AND [-f OR --force])
//   - any positional arg resolves to a prefix of a blocked path

// BlockedCommand blocks destructive commands against protected targets.
type BlockedCommand struct {
	RuleName string
	Programs []string
	// RequireFlagsAny is a list of flag *groups*. Each group is a list of
	// synonymous flags. The rule matches only if at least one flag from
	// EVERY group is present in the call. Example for rm -rf /:
	//   [[-r, -R, -rf, --recursive], [-f, -rf, --force]]
	RequireFlagsAny [][]string
	// TargetPaths: positional args that start with any of these paths trigger
	// the match. Supports ~, $HOME, and filesystem prefixes.
	TargetPaths []string
	Reason      string
}

func (r *BlockedCommand) Name() string { return r.RuleName }
func (r *BlockedCommand) Kind() string { return "blocked_command" }

func (r *BlockedCommand) Eval(p *shellparse.Parsed) (Verdict, string) {
	// Does this rule's TargetPaths include a home-like token? If so,
	// we must also check for ParamExp args targeting $HOME / $PWD —
	// the positional slot is empty for unresolvable expansions and
	// would otherwise bypass the check.
	watchesHome := false
	for _, tp := range r.TargetPaths {
		n := normalizePath(tp)
		if n == "$HOME" || strings.HasPrefix(n, "$HOME/") {
			watchesHome = true
			break
		}
	}

	for _, c := range p.Calls {
		if !stringIn(baseProgram(c.Program), r.Programs) && !stringIn(c.Program, r.Programs) {
			continue
		}
		if !flagsMatchAllGroups(c.Flags, r.RequireFlagsAny) {
			continue
		}
		for _, pos := range c.Positional {
			if pos == "" {
				continue
			}
			if pathMatchesAny(pos, r.TargetPaths) {
				return Match, r.Reason
			}
		}
		// ParamExp catch: `rm -rf "$HOME"`, `rm -rf $HOME`, `rm -rf $PWD`.
		// Only consulted when the rule is actually watching a home path;
		// avoids spurious matches on unrelated rules.
		if watchesHome && c.HasEnvVarArg("HOME", "PWD") {
			return Match, r.Reason
		}
	}
	return NoMatch, ""
}

// --- PipeToShell: block rule for remote-code-execution patterns.
// Matches when a pipeline contains a source program (curl, wget, ...) followed
// by a sink program (sh, bash, zsh, ...) later in the same pipeline.

// PipeToShell blocks `curl URL | sh` and variants.
type PipeToShell struct {
	RuleName       string
	SourcePrograms []string // curl, wget, fetch, ...
	SinkPrograms   []string // sh, bash, zsh, fish, dash, /bin/sh, /bin/bash
	Reason         string
}

func (r *PipeToShell) Name() string { return r.RuleName }
func (r *PipeToShell) Kind() string { return "pipe_to_shell" }

func (r *PipeToShell) Eval(p *shellparse.Parsed) (Verdict, string) {
	for _, pipeline := range p.Pipelines {
		if len(pipeline) < 2 {
			continue
		}
		hasSource := false
		for i, call := range pipeline {
			prog := baseProgram(call.Program)
			if !hasSource && stringIn(prog, r.SourcePrograms) {
				hasSource = true
				continue
			}
			if hasSource && i > 0 && stringIn(prog, r.SinkPrograms) {
				return Match, r.Reason
			}
		}
	}
	return NoMatch, ""
}

// --- ProcSubToShell: blocks bash <(curl URL) and variants.

// ProcSubToShell blocks `bash <(curl URL)` and variants.
type ProcSubToShell struct {
	RuleName     string
	SinkPrograms []string // sh, bash, zsh, ...
	Reason       string
}

func (r *ProcSubToShell) Name() string { return r.RuleName }
func (r *ProcSubToShell) Kind() string { return "proc_sub_to_shell" }

func (r *ProcSubToShell) Eval(p *shellparse.Parsed) (Verdict, string) {
	// Fire if the script has process substitution AND any top-level call is
	// one of the shell sinks. (An arg of the sink that is a process sub is
	// how `bash <(curl ...)` is parsed by mvdan — the <(...) shows up as a
	// Word part containing a ProcSubst.)
	if !p.Features.HasProcSub {
		return NoMatch, ""
	}
	for _, c := range p.Calls {
		if c.Nesting != shellparse.NestTopLevel {
			continue
		}
		if stringIn(baseProgram(c.Program), r.SinkPrograms) {
			return Match, r.Reason
		}
	}
	return NoMatch, ""
}

// --- ShellDashC: block rule for `<shell> -c '…'` — the inner script
// string is not AST-analyzable by the outer parser, so every tier-1
// matcher looking at the wrapper sees `bash`, not the wrapped command.
// `sudo-anything` blocks sudo but not `bash -c 'sudo rm …'`; ProcSubToShell
// blocks `bash <(curl)` but not `bash -c '$(curl)'`. This rule fills
// the gap by denying `<shell> -c` with any positional script.

// ShellDashC blocks `<shell> -c '<script>'` shapes.
type ShellDashC struct {
	RuleName string
	Shells   []string
	Reason   string
}

func (r *ShellDashC) Name() string { return r.RuleName }
func (r *ShellDashC) Kind() string { return "shell_dash_c" }

func (r *ShellDashC) Eval(p *shellparse.Parsed) (Verdict, string) {
	for _, c := range p.Calls {
		if c.Nesting != shellparse.NestTopLevel {
			continue
		}
		if !stringIn(baseProgram(c.Program), r.Shells) && !stringIn(c.Program, r.Shells) {
			continue
		}
		hasC := false
		for _, f := range c.Flags {
			if f == "-c" {
				hasC = true
				break
			}
		}
		if hasC && len(c.Positional) > 0 {
			return Match, r.Reason
		}
	}
	return NoMatch, ""
}

// --- NestedSubcommand: a block rule for tools with a two-level
// subcommand tree (e.g. `gh pr merge`, `terraform state rm`,
// `git remote add`) where the outer noun is tier-2 allowed but
// specific (noun, verb) pairs need tier-1 denies.
//
// Matches when the call's program is Program AND the first positional
// matches a known noun/verb pair in Destructive. Pair formats:
//   - "noun/verb"  — exact pair; both positionals must match
//   - "noun/*"     — any verb under this noun triggers the match
//   - "noun"       — noun alone; matches when positional[0] == noun
//                    regardless of subsequent positionals (used for
//                    "terraform import <anything>")
//
// Only runs against top-level calls — a nested `$(gh pr merge)` is
// handled by the outer call's shell mechanics, not by this rule.

// NestedSubcommand matches (program, noun[, verb]) destructive triples.
type NestedSubcommand struct {
	RuleName    string
	Program     string
	Destructive []string
	Reason      string
}

func (r *NestedSubcommand) Name() string { return r.RuleName }
func (r *NestedSubcommand) Kind() string { return "nested_subcommand" }

func (r *NestedSubcommand) Eval(p *shellparse.Parsed) (Verdict, string) {
	for _, c := range p.Calls {
		if c.Nesting != shellparse.NestTopLevel {
			continue
		}
		if baseProgram(c.Program) != r.Program && c.Program != r.Program {
			continue
		}
		if len(c.Positional) == 0 {
			continue
		}
		noun := c.Positional[0]
		verb := ""
		if len(c.Positional) >= 2 {
			verb = c.Positional[1]
		}
		for _, spec := range r.Destructive {
			// "noun" alone: match on noun regardless of verb.
			if !strings.Contains(spec, "/") {
				if spec == noun {
					return Match, r.Reason
				}
				continue
			}
			// "noun/verb" or "noun/*"
			slash := strings.IndexByte(spec, '/')
			specNoun, specVerb := spec[:slash], spec[slash+1:]
			if specNoun != noun {
				continue
			}
			if specVerb == "*" {
				return Match, r.Reason
			}
			if specVerb == verb {
				return Match, r.Reason
			}
		}
	}
	return NoMatch, ""
}

// --- GhApiMutation: block rule for `gh api` calls with mutating HTTP
// verbs. Distinct from NestedSubcommand because `-X DELETE` is
// adjacency-based (two tokens) and the flag is also spellable in
// multiple shapes: `-X DELETE`, `-XDELETE`, `--method DELETE`,
// `--request DELETE`.
//
// Fires when:
//   - program is `gh` (top-level)
//   - positional[0] == "api"
//   - AND any of:
//     - a Flag equals `-X<METHOD>` (short-form concat) with METHOD in MutatingVerbs
//     - FlagValue(`-X`,`--method`,`--request`) resolves to a MutatingVerb
//
// MutatingVerbs is typically {DELETE, POST, PATCH, PUT}. GET/HEAD don't
// mutate; OPTIONS is metadata.

// GhApiMutation blocks `gh api` calls with mutating HTTP methods.
type GhApiMutation struct {
	RuleName       string
	MutatingVerbs  []string
	Reason         string
}

func (r *GhApiMutation) Name() string { return r.RuleName }
func (r *GhApiMutation) Kind() string { return "gh_api_mutation" }

func (r *GhApiMutation) Eval(p *shellparse.Parsed) (Verdict, string) {
	for _, c := range p.Calls {
		if c.Nesting != shellparse.NestTopLevel {
			continue
		}
		if baseProgram(c.Program) != "gh" && c.Program != "gh" {
			continue
		}
		if len(c.Positional) == 0 || c.Positional[0] != "api" {
			continue
		}
		// Short-form concat: `-XDELETE`, `-XPOST`, etc.
		for _, f := range c.Flags {
			if !strings.HasPrefix(f, "-X") || len(f) == 2 {
				continue
			}
			verb := f[2:]
			if stringIn(strings.ToUpper(verb), r.MutatingVerbs) {
				return Match, r.Reason
			}
		}
		// Space-separated: `-X DELETE`, `--method DELETE`, `--request DELETE`.
		if v, ok := c.FlagValue("-X", "--method", "--request"); ok {
			if stringIn(strings.ToUpper(v), r.MutatingVerbs) {
				return Match, r.Reason
			}
		}
	}
	return NoMatch, ""
}

// --- GitForcePush: block rule for force pushes to protected branches.

// GitForcePush blocks `git push --force`-family commands to protected branches.
type GitForcePush struct {
	RuleName          string
	ProtectedBranches []string
	Reason            string
}

func (r *GitForcePush) Name() string { return r.RuleName }
func (r *GitForcePush) Kind() string { return "git_force_push" }

func (r *GitForcePush) Eval(p *shellparse.Parsed) (Verdict, string) {
	for _, c := range p.Calls {
		if baseProgram(c.Program) != "git" {
			continue
		}
		// must be a push
		if len(c.Positional) == 0 || c.Positional[0] != "push" {
			continue
		}
		// must have a force-like flag
		hasForce := false
		for _, f := range c.Flags {
			if f == "-f" || f == "--force" || f == "--force-with-lease" || strings.HasPrefix(f, "--force-with-lease=") {
				hasForce = true
				break
			}
		}
		// also detect refspec-force syntax: `git push origin +main` (leading +)
		refspecForce := false
		for _, pos := range c.Positional[1:] {
			if strings.HasPrefix(pos, "+") && len(pos) > 1 {
				refspecForce = true
				break
			}
		}
		if !hasForce && !refspecForce {
			continue
		}
		// must target a protected branch — look for the branch name anywhere in
		// positional args after "push".
		for _, pos := range c.Positional[1:] {
			bare := strings.TrimPrefix(pos, "+")
			// strip refspec "src:dst" down to dst
			if idx := strings.Index(bare, ":"); idx >= 0 {
				bare = bare[idx+1:]
			}
			bare = strings.TrimPrefix(bare, "refs/heads/")
			if stringIn(bare, r.ProtectedBranches) {
				return Match, r.Reason
			}
		}
	}
	return NoMatch, ""
}

// --- PathAccess: block rule for commands that read/write specific paths.
// Conservative: only matches fully-resolved arguments. A command with
// unresolved $HOME-style expansion doesn't match (falls through to prompt).

// PathAccess blocks any call that touches a forbidden path.
// Used for ~/.ssh/id_* and /etc/shadow-style defenses.
type PathAccess struct {
	RuleName        string
	Paths           []string // glob-like; supports ~, *, **
	ExcludePrograms []string // programs allowed to access these paths (e.g. ssh, git)
	Reason          string
}

func (r *PathAccess) Name() string { return r.RuleName }
func (r *PathAccess) Kind() string { return "path_access" }

func (r *PathAccess) Eval(p *shellparse.Parsed) (Verdict, string) {
	for _, c := range p.Calls {
		if c.HasUnresolved {
			continue // conservative
		}
		if stringIn(baseProgram(c.Program), r.ExcludePrograms) {
			continue
		}
		for _, arg := range c.Positional {
			if arg == "" {
				continue
			}
			if pathMatchesAny(arg, r.Paths) {
				return Match, r.Reason
			}
		}
	}
	return NoMatch, ""
}

// --- helpers ---

func stringIn(s string, list []string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// baseProgram returns the base name of a program path, so `/bin/rm` and `rm`
// are both recognised as "rm".
func baseProgram(prog string) string {
	if prog == "" {
		return ""
	}
	return filepath.Base(prog)
}

// flagsMatchAllGroups returns true when every group in `groups` has at least
// one of its members present in `flags`. An empty groups list matches vacuously.
func flagsMatchAllGroups(flags []string, groups [][]string) bool {
	if len(groups) == 0 {
		return true
	}
	for _, group := range groups {
		if !flagsMatchGroup(flags, group) {
			return false
		}
	}
	return true
}

func flagsMatchGroup(flags, group []string) bool {
	// Also handle combined short flags like `-rf` meaning `-r` and `-f`.
	combined := map[rune]bool{}
	for _, f := range flags {
		if strings.HasPrefix(f, "-") && !strings.HasPrefix(f, "--") && len(f) > 1 {
			for _, r := range f[1:] {
				combined[r] = true
			}
		}
	}
	for _, want := range group {
		for _, f := range flags {
			if f == want {
				return true
			}
		}
		if strings.HasPrefix(want, "-") && !strings.HasPrefix(want, "--") && len(want) == 2 {
			if combined[rune(want[1])] {
				return true
			}
		}
	}
	return false
}

// pathMatchesAny returns true if arg lexically refers to any of the paths.
// Paths may use:
//   - literal prefixes: "/etc/shadow"
//   - tilde: "~/.ssh/id_"
//   - single-star globs: "~/.ssh/id_*"
//   - double-star globs: "**/.ssh/id_*"
//
// The match is conservative — it only covers paths we can resolve statically.
// A literal string starting with ~ is expanded to $HOME if set, else to /root.
func pathMatchesAny(arg string, paths []string) bool {
	normArg := normalizePath(arg)
	for _, p := range paths {
		normP := normalizePath(p)
		if matchGlobOrPrefix(normArg, normP) {
			return true
		}
	}
	return false
}

// normalizePath canonicalizes a path arg or pattern for comparison:
//   - tilde expansion: `~` and `~/foo` → `$HOME` / `$HOME/foo`
//   - lexical cleanup (absolute paths only): `/tmp/../etc` → `/etc`,
//     `/./etc` → `/etc`, `//etc` → `/etc`
//
// Relative paths and tilde-prefixed paths are not run through
// filepath.Clean because Clean strips leading `./` and can mangle
// glob-bearing patterns like `~/.ssh/id_*`.
func normalizePath(p string) string {
	if p == "" {
		return p
	}
	if strings.HasPrefix(p, "/") {
		p = filepath.Clean(p)
	}
	if strings.HasPrefix(p, "~/") {
		// Treat ~ as $HOME symbolically. Matchers compare symbolic forms.
		return "$HOME/" + p[2:]
	}
	if p == "~" {
		return "$HOME"
	}
	return p
}

func matchGlobOrPrefix(arg, pattern string) bool {
	// **/ suffix-anywhere match
	if strings.HasPrefix(pattern, "**/") {
		needle := pattern[3:]
		// Simple implementation: match against any suffix
		parts := strings.Split(arg, "/")
		for i := range parts {
			suffix := strings.Join(parts[i:], "/")
			if ok, _ := filepath.Match(needle, suffix); ok {
				return true
			}
			if strings.HasPrefix(suffix, trimStar(needle)) && !strings.ContainsAny(needle, "*?") {
				return true
			}
		}
		return false
	}
	// glob match
	if strings.ContainsAny(pattern, "*?") {
		if ok, _ := filepath.Match(pattern, arg); ok {
			return true
		}
		// Also check prefix-only (pattern ending in "*" should match all extensions)
		if strings.HasSuffix(pattern, "*") {
			if strings.HasPrefix(arg, strings.TrimSuffix(pattern, "*")) {
				return true
			}
		}
		return false
	}
	// literal prefix match. On darwin the default APFS system volume is
	// case-insensitive, so `rm -rf /Etc` and `rm -rf /ETC` resolve to
	// the same inode as `/etc` at the kernel layer — compare in lower-
	// case so our safety rules agree. On Linux, keep exact-case match
	// (ext4/xfs default to case-sensitive).
	if runtime.GOOS == "darwin" {
		la, lp := strings.ToLower(arg), strings.ToLower(pattern)
		return la == lp || strings.HasPrefix(la, lp+"/")
	}
	return arg == pattern || strings.HasPrefix(arg, pattern+"/")
}

func trimStar(s string) string {
	return strings.TrimRight(s, "*")
}
