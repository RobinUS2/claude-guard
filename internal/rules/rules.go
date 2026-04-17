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
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/RobinUS2/claude-guard/internal/shellparse"
)

// userHome is the current user's home directory, resolved at package
// init. Used by normalizePath to fold literal expansions like
// `/Users/robin/.ssh/id_rsa` back into the symbolic `$HOME/...` form
// so PathAccess rules written with `~` match both spellings.
// Empty when the lookup fails (rare; harmless — just means we skip
// the expanded-form fold-in).
var userHome = func() string {
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return ""
}()

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
			if PathMatchesAny(pos, r.TargetPaths) {
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

// --- ScriptInterpreterExec: block rule for script interpreters
// invoked with an inline-code flag. Semantically identical to
// `bash -c '…'` but with different flag conventions: Python uses
// `-c`, Perl/Ruby/Node use `-e`. The inline string is arbitrary code
// the AST can't analyze, so we treat it like ShellDashC.

// ScriptInterpreterExec blocks `<interp> <exec-flag> '<code>'` shapes.
type ScriptInterpreterExec struct {
	RuleName     string
	Interpreters []string // python, python3, perl, ruby, node, etc.
	// ExecFlags trigger the deny when present alongside a positional.
	// Common values: "-c" (python), "-e" (perl/ruby/node).
	ExecFlags []string
	Reason    string
}

func (r *ScriptInterpreterExec) Name() string { return r.RuleName }
func (r *ScriptInterpreterExec) Kind() string { return "script_interpreter_exec" }

func (r *ScriptInterpreterExec) Eval(p *shellparse.Parsed) (Verdict, string) {
	for _, c := range p.Calls {
		if c.Nesting != shellparse.NestTopLevel {
			continue
		}
		if !stringIn(baseProgram(c.Program), r.Interpreters) && !stringIn(c.Program, r.Interpreters) {
			continue
		}
		hasExecFlag := false
		for _, f := range c.Flags {
			for _, want := range r.ExecFlags {
				if f == want {
					hasExecFlag = true
					break
				}
			}
			if hasExecFlag {
				break
			}
		}
		if hasExecFlag && len(c.Positional) > 0 {
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

// --- GitConfigWrite: block rule for `git config` writes.
//
// `git config` writes to gitconfig files (setting core.hooksPath,
// user.signingkey, remote urls, etc.) — a supply-chain attack surface.
// Tier-2 `git-readonly` allows `git config` for the read shapes; this
// tier-1 rule carves out the write shapes:
//
//   Deny flags (always write): --add, --unset, --unset-all,
//     --replace-all, --rename-section, --remove-section, --edit, -e
//   Read flags (clear intent): --list, -l, --get, --get-all,
//     --get-regexp, --get-urlmatch, --show-origin, --show-scope
//   Else: count positionals after "config". 0-1 = read, 2+ = write.
//
// `--file <path>` / `-f <path>` is always-deny — the file-override
// shape is rare and adjacent-value parsing would need to skip the
// path token when counting positionals. Easier to refuse entirely;
// users needing it can get an LLM approval.
//
// Scope modifiers (--global, --system, --local, --worktree,
// --default) don't change the read/write classification; ignored.

// GitConfigWrite blocks write shapes of `git config`.
type GitConfigWrite struct {
	RuleName string
	Reason   string
}

func (r *GitConfigWrite) Name() string { return r.RuleName }
func (r *GitConfigWrite) Kind() string { return "git_config_write" }

var gitConfigDenyFlags = map[string]struct{}{
	"--add": {}, "--unset": {}, "--unset-all": {},
	"--replace-all":    {},
	"--rename-section": {}, "--remove-section": {},
	"--edit": {}, "-e": {},
}

var gitConfigReadFlags = map[string]struct{}{
	"--list": {}, "-l": {},
	"--get": {}, "--get-all": {}, "--get-regexp": {},
	"--get-urlmatch": {}, "--show-origin": {}, "--show-scope": {},
}

var gitConfigFileFlags = map[string]struct{}{
	"--file": {}, "-f": {},
}

func (r *GitConfigWrite) Eval(p *shellparse.Parsed) (Verdict, string) {
	for _, c := range p.Calls {
		if c.Nesting != shellparse.NestTopLevel {
			continue
		}
		if baseProgram(c.Program) != "git" && c.Program != "git" {
			continue
		}
		if len(c.Positional) == 0 || c.Positional[0] != "config" {
			continue
		}
		// Always-deny flags.
		for _, f := range c.Flags {
			if _, bad := gitConfigDenyFlags[f]; bad {
				return Match, r.Reason
			}
			// `--edit` / `--unset-all` etc. may appear as `--flag=…`
			// theoretically (they don't take values, but be robust).
			if idx := strings.IndexByte(f, '='); idx > 0 {
				if _, bad := gitConfigDenyFlags[f[:idx]]; bad {
					return Match, r.Reason
				}
			}
			// --file / -f — always-deny shape.
			base := f
			if idx := strings.IndexByte(f, '='); idx > 0 {
				base = f[:idx]
			}
			if _, fileForm := gitConfigFileFlags[base]; fileForm {
				return Match, r.Reason
			}
		}
		// Read-flag carve-out: if any explicit read flag is present
		// and no deny flag matched, allow tier-2 to approve.
		hasRead := false
		for _, f := range c.Flags {
			base := f
			if idx := strings.IndexByte(f, '='); idx > 0 {
				base = f[:idx]
			}
			if _, r := gitConfigReadFlags[base]; r {
				hasRead = true
				break
			}
		}
		if hasRead {
			continue
		}
		// Positional count: "config" itself is Positional[0].
		// 0 extra positionals = list intent (safe).
		// 1 extra positional = read single key (safe).
		// 2+ extra positionals = write (deny).
		if len(c.Positional) >= 3 {
			return Match, r.Reason
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

	// WriteOnly restricts the rule to fire ONLY when the path appears
	// as the TARGET of a redirection (`> path`, `>> path`, or a
	// ProcSubst target). Positional args and redirect SOURCES are
	// ignored. Used for persistence-tamper-style rules where reading
	// the path (`cat ~/.bashrc`) is harmless but writing
	// (`echo evil > ~/.bashrc`) establishes attacker persistence.
	WriteOnly bool
}

func (r *PathAccess) Name() string { return r.RuleName }
func (r *PathAccess) Kind() string { return "path_access" }

func (r *PathAccess) Eval(p *shellparse.Parsed) (Verdict, string) {
	for _, c := range p.Calls {
		if stringIn(baseProgram(c.Program), r.ExcludePrograms) {
			continue
		}
		// Positional args — existing behavior. Only consulted when
		// the call's positionals are fully resolved (conservative)
		// AND the rule is not WriteOnly (positional args are often
		// read targets for cat/grep/less etc.).
		if !r.WriteOnly && !c.HasUnresolved {
			for _, arg := range c.Positional {
				if arg == "" {
					continue
				}
				if PathMatchesAny(arg, r.Paths) {
					return Match, r.Reason
				}
			}
		}
		// Redirection words (Stmt.Redirs). `cat < ~/.ssh/id_rsa`
		// puts id_rsa here, not in Positional. In WriteOnly mode,
		// only target-direction redirs (`>`, `>>`) match — source
		// redirs (`<`) are reads.
		for _, rw := range c.RedirWords {
			if !rw.Resolved {
				continue
			}
			if r.WriteOnly && rw.Direction != shellparse.RedirTarget {
				continue
			}
			if PathMatchesAny(rw.Path, r.Paths) {
				return Match, r.Reason
			}
		}
		// ProcSubst-derived redirs. `tee >(cat > /etc/shadow)` writes
		// to /etc/shadow from inside the ProcSubst — flattened here.
		for _, rw := range c.DerivedRedirs {
			if !rw.Resolved {
				continue
			}
			if r.WriteOnly && rw.Direction != shellparse.RedirTarget {
				continue
			}
			if PathMatchesAny(rw.Path, r.Paths) {
				return Match, r.Reason
			}
		}
		// ProcSubst-derived inner calls. `diff <(cat ~/.ssh/id_rsa) /tmp/a`
		// has an inner `cat ~/.ssh/id_rsa` whose positional we need
		// to inspect. In WriteOnly mode, skip — inner positional
		// args are almost always read targets.
		if !r.WriteOnly {
			for _, dc := range c.DerivedCalls {
				if dc == nil || dc.HasUnresolved {
					continue
				}
				if stringIn(baseProgram(dc.Program), r.ExcludePrograms) {
					continue
				}
				for _, arg := range dc.Positional {
					if arg == "" {
						continue
					}
					if PathMatchesAny(arg, r.Paths) {
						return Match, r.Reason
					}
				}
			}
		}
	}
	return NoMatch, ""
}

// --- CdPrefixed: an allow rule for compound commands where the first
// pipeline is `cd <path>` and all subsequent pipelines match one of the
// provided inner allow rules.
//
// Handles the common pattern of Claude Code subagents running:
//   cd /path/to/repo && git log --oneline -5
//   cd /path/to/repo && git show e48ecd1 --stat | head -10
//
// `cd` is purely a directory context-setter with no security implications.
// The remaining commands are evaluated against the same allow rules as
// standalone commands. Pipes to safe read-only programs (head, tail, grep,
// etc.) are permitted in trailing position.
//
// Rejects when:
//   - first pipeline is not a bare `cd <path>` call
//   - any remaining pipeline's head call doesn't match an inner rule
//   - any pipe target is not in SafePipeTargets
//   - the script has subshells, command substitution, process substitution,
//     background, or redirections (those change semantics beyond cd)

// CdPrefixed matches `cd <path> && <safe-command> [| <safe-pipe-target>]`.
type CdPrefixed struct {
	RuleName        string
	InnerRules      []Rule
	SafePipeTargets []string // read-only programs allowed in pipe tails
}

func (r *CdPrefixed) Name() string { return r.RuleName }
func (r *CdPrefixed) Kind() string { return "cd_prefixed" }

func (r *CdPrefixed) Eval(p *shellparse.Parsed) (Verdict, string) {
	f := p.Features
	// Must have binary op (cd && ...). Without it, AnchoredCommand handles.
	if !f.HasBinaryOp {
		return NoMatch, ""
	}
	// Reject shell features that change semantics beyond directory context.
	if f.HasSubshell || f.HasCmdSub || f.HasProcSub || f.HasBackground || f.HasRedirect {
		return NoMatch, ""
	}
	// Need at least 2 pipelines (cd + at least one command).
	if len(p.Pipelines) < 2 {
		return NoMatch, ""
	}
	// First pipeline must be exactly `cd <path>` — single call, no trickery.
	firstPipeline := p.Pipelines[0]
	if len(firstPipeline) != 1 {
		return NoMatch, ""
	}
	cdCall := firstPipeline[0]
	if cdCall.Program != "cd" || cdCall.HasUnresolved || len(cdCall.Positional) == 0 || len(cdCall.Flags) > 0 {
		return NoMatch, ""
	}

	// Each remaining pipeline must have a head call matching an inner rule,
	// and any pipe targets must be in SafePipeTargets.
	for _, pipeline := range p.Pipelines[1:] {
		if len(pipeline) == 0 {
			return NoMatch, ""
		}
		// Check head call against inner rules via a synthetic single-call Parsed.
		headCall := pipeline[0]
		if !r.matchesInnerRule(&headCall) {
			return NoMatch, ""
		}
		// Check pipe targets are safe read-only programs.
		for _, tailCall := range pipeline[1:] {
			if !stringIn(baseProgram(tailCall.Program), r.SafePipeTargets) {
				return NoMatch, ""
			}
		}
	}
	return Match, r.RuleName
}

// matchesInnerRule creates a synthetic single-call Parsed and tests it
// against the inner allow rules. The synthetic Parsed has all Features
// cleared (single clean call) so AnchoredCommand's trickery checks pass.
func (r *CdPrefixed) matchesInnerRule(c *shellparse.Call) bool {
	if c.Nesting != shellparse.NestTopLevel || c.HasUnresolved {
		return false
	}
	miniParsed := &shellparse.Parsed{
		Calls:     []shellparse.Call{*c},
		Pipelines: [][]shellparse.Call{{*c}},
		Features:  shellparse.Features{}, // all false — single clean call
	}
	for _, rule := range r.InnerRules {
		if verdict, _ := rule.Eval(miniParsed); verdict == Match {
			return true
		}
	}
	return false
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
//
// Because normalizePath folds a literal home prefix (`/Users/robin`)
// into the symbolic `$HOME` form, a path like `/Users/robin` that
// should match a `/Users` parent-dir rule would miss. To preserve both
// intents — rules written with `~/` matching expanded literals AND
// rules written with `/Users` matching subpaths — we try the match
// against BOTH forms: the fully-normalized arg AND the arg with only
// lexical (filepath.Clean) normalization applied.
func PathMatchesAny(arg string, paths []string) bool {
	normArg := normalizePath(arg)
	lexArg := arg
	if strings.HasPrefix(lexArg, "/") {
		lexArg = filepath.Clean(lexArg)
	}
	for _, p := range paths {
		normP := normalizePath(p)
		if matchGlobOrPrefix(normArg, normP) {
			return true
		}
		// Fallback: match the lexically-cleaned (non-home-folded) arg.
		// Ensures `/Users/<user>` still matches a `/Users` pattern.
		if lexArg != normArg && matchGlobOrPrefix(lexArg, normP) {
			return true
		}
	}
	return false
}

// normalizePath canonicalizes a path arg or pattern for comparison:
//   - tilde expansion: `~` and `~/foo` → `$HOME` / `$HOME/foo`
//   - literal-home fold-in: `/Users/robin/foo` → `$HOME/foo` (when
//     the current process's home dir prefix matches). Catches shell-
//     expanded forms; a rule written as `~/.bashrc` also matches
//     `/Users/<user>/.bashrc`.
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
	// Fold-in: `/Users/robin/.bashrc` → `$HOME/.bashrc` so rules
	// written with `~/` catch shell-expanded literal paths too. Done
	// AFTER filepath.Clean so `/Users/robin/../other` has been
	// resolved to `/Users/other` first (which won't fold in).
	if userHome != "" {
		if p == userHome {
			return "$HOME"
		}
		if strings.HasPrefix(p, userHome+"/") {
			return "$HOME" + p[len(userHome):]
		}
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
