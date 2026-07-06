package freeze

import (
	"fmt"
	"strings"
	"time"

	"github.com/RobinUS2/claude-guard/internal/rules"
	"github.com/RobinUS2/claude-guard/internal/shellparse"
)

// Action is the freeze evaluator's outcome for a command.
type Action int

const (
	// Pass — no active freeze applies; normal pipeline continues.
	Pass Action = iota
	// Deny — hard block (Tier 1). Reason is shown to Claude and the user.
	Deny
	// Ask — surface the normal permission dialog; Reason names the freeze.
	Ask
)

func (a Action) String() string {
	switch a {
	case Deny:
		return "deny"
	case Ask:
		return "ask"
	default:
		return "pass"
	}
}

// Outcome is the result of evaluating a command against the active freeze(s).
type Outcome struct {
	Action Action
	Rule   string // catalog rule name that matched (empty on Pass)
	Env    string // frozen env that triggered it
	Reason string // full human-readable message for the deny/ask
}

// Evaluate decides Pass/Deny/Ask for a parsed command given the active freeze
// states, the command's origin remote URL (for project scoping), and now.
//
// Precedence: a high-confidence DENY always wins over an ASK — an over-eager
// agent must never be able to downgrade a real prod release to a click-through.
// The first state producing a DENY short-circuits; otherwise the strongest
// (deny > ask > pass) outcome across all states/entries is returned.
func Evaluate(parsed *shellparse.Parsed, remoteURL string, states []*State, now time.Time) Outcome {
	if parsed == nil || len(states) == 0 {
		return Outcome{Action: Pass}
	}
	catalog := Catalog()
	best := Outcome{Action: Pass}

	for _, s := range states {
		if !s.active(now) || !s.MatchesProject(remoteURL) {
			continue
		}

		// Compiled-in catalog entries.
		for _, e := range catalog {
			if !s.freezesAnyEnv(e.Envs) || s.IsExcluded(e.Name) {
				continue
			}
			if v, _ := e.Rule.Eval(parsed); v != rules.Match {
				continue
			}
			env := s.firstFrozenEnvFor(e.Envs)
			act := actionFor(e.Confidence)
			if act == Deny {
				return Outcome{Action: Deny, Rule: e.Name, Env: env, Reason: reason(Deny, e.Name, env, s, now)}
			}
			best = strongest(best, Outcome{Action: Ask, Rule: e.Name, Env: env, Reason: reason(Ask, e.Name, env, s, now)})
		}

		// git push to a protected branch — ambiguous (ASK) under a prod freeze.
		if !s.IsExcluded(gitPushDeployName) && s.FreezesEnv("prod") && matchesProtectedPush(parsed) {
			best = strongest(best, Outcome{
				Action: Ask, Rule: gitPushDeployName, Env: "prod",
				Reason: reason(Ask, gitPushDeployName, "prod", s, now),
			})
		}

		// Ad-hoc --include commands: extra denies for this freeze only.
		for _, inc := range s.Include {
			if s.IsExcluded(includeRuleName(inc)) || !s.freezesAnyEnv(includeEnvs(inc)) {
				continue
			}
			if matchesInclude(parsed, inc) {
				env := s.firstFrozenEnvFor(includeEnvs(inc))
				name := includeRuleName(inc)
				return Outcome{Action: Deny, Rule: name, Env: env, Reason: reason(Deny, name, env, s, now)}
			}
		}
	}
	return best
}

func actionFor(c Confidence) Action {
	if c == High {
		return Deny
	}
	return Ask
}

// strongest keeps the higher-precedence outcome (deny > ask > pass).
func strongest(a, b Outcome) Outcome {
	if b.Action > a.Action {
		return b
	}
	return a
}

// freezesAnyEnv reports whether the state freezes at least one of envs.
func (s *State) freezesAnyEnv(envs []string) bool {
	for _, e := range envs {
		if s.FreezesEnv(e) {
			return true
		}
	}
	return false
}

// firstFrozenEnvFor returns the first of the entry's envs that this state
// freezes (for display). Falls back to the entry's first env.
func (s *State) firstFrozenEnvFor(envs []string) string {
	for _, e := range envs {
		if s.FreezesEnv(e) {
			return e
		}
	}
	if len(envs) > 0 {
		return envs[0]
	}
	return ""
}

// matchesProtectedPush reports whether the parsed command is a
// `git push … <protected-branch>` with an explicitly named protected branch.
// A bare `git push` (no branch) is intentionally NOT matched — it falls to the
// normal smart-git-push tier to avoid asking on every push.
func matchesProtectedPush(p *shellparse.Parsed) bool {
	for _, c := range p.Calls {
		if c.Nesting != shellparse.NestTopLevel {
			continue
		}
		if c.Program != "git" && baseName(c.Program) != "git" {
			continue
		}
		if len(c.Positional) == 0 || c.Positional[0] != "push" {
			continue
		}
		for _, pos := range c.Positional[1:] {
			if branchIn(pos, protectedBranches) {
				return true
			}
		}
	}
	return false
}

// matchesInclude matches an --include rule (program + optional subcommand)
// against any top-level call in the command.
func matchesInclude(p *shellparse.Parsed, inc IncludeRule) bool {
	for _, c := range p.Calls {
		if c.Nesting != shellparse.NestTopLevel {
			continue
		}
		if c.Program != inc.Program && baseName(c.Program) != inc.Program {
			continue
		}
		if inc.Subcommand == "" {
			return true
		}
		if len(c.Positional) > 0 && c.Positional[0] == inc.Subcommand {
			return true
		}
	}
	return false
}

func includeEnvs(inc IncludeRule) []string {
	if len(inc.Envs) == 0 {
		return []string{"prod"}
	}
	return inc.Envs
}

func includeRuleName(inc IncludeRule) string {
	if inc.Subcommand == "" {
		return "include:" + inc.Program
	}
	return "include:" + inc.Program + ":" + inc.Subcommand
}

func branchIn(s string, list []string) bool {
	for _, b := range list {
		if strings.EqualFold(s, b) {
			return true
		}
	}
	return false
}

func baseName(prog string) string {
	if i := strings.LastIndexByte(prog, '/'); i >= 0 {
		return prog[i+1:]
	}
	return prog
}

// reason renders the deny/ask message shown to Claude and the user.
func reason(act Action, rule, env string, s *State, now time.Time) string {
	var b strings.Builder
	if act == Deny {
		fmt.Fprintf(&b, "🧊 RELEASE FREEZE ACTIVE (%s) — this command is blocked by claude-guard.\n\n", env)
	} else {
		fmt.Fprintf(&b, "⚠️ RELEASE FREEZE ACTIVE (%s) — confirm before proceeding.\n\n", env)
	}
	fmt.Fprintf(&b, "  Matched : freeze rule %q (env=%s)\n", rule, env)
	fmt.Fprintf(&b, "  Scope   : %s\n", s.ScopeLabel())
	if s.Reason != "" {
		fmt.Fprintf(&b, "  Reason  : %s\n", s.Reason)
	}
	if s.SetBy != "" {
		fmt.Fprintf(&b, "  Set by  : %s%s\n", s.SetBy, setAtSuffix(s))
	}
	fmt.Fprintf(&b, "  Lifts   : %s\n\n", liftsLabel(s, now))

	if act == Ask {
		b.WriteString("  claude-guard can't confirm this targets the frozen environment.\n")
		b.WriteString("  If it deploys to a frozen env, cancel and lift the freeze first;\n")
		b.WriteString("  if it's staging/dev, it's fine to proceed.\n\n")
	} else {
		b.WriteString("  Staging/dev deploys are NOT frozen — use the staging target instead.\n\n")
	}
	b.WriteString("  To lift the freeze:\n")
	b.WriteString("    claude-guard freeze status            # see what's frozen\n")
	fmt.Fprintf(&b, "    claude-guard freeze off --env %-8s # lift %s only\n", env, env)
	b.WriteString("    claude-guard freeze off               # lift everything\n")
	if act == Deny {
		b.WriteString("\n  (This is an explicit operator lock — no agent can bypass it.)")
	}
	return b.String()
}

func setAtSuffix(s *State) string {
	if s.SetAt.IsZero() {
		return ""
	}
	return " at " + s.SetAt.Format("2006-01-02 15:04 MST")
}

func liftsLabel(s *State, now time.Time) string {
	if s.ExpiresAt == nil {
		return "manual — no expiry set"
	}
	d := s.ExpiresAt.Sub(now)
	if d <= 0 {
		return s.ExpiresAt.Format("2006-01-02 15:04 MST") + " (expired)"
	}
	return fmt.Sprintf("%s (in %s)", s.ExpiresAt.Format("2006-01-02 15:04 MST"), humanDur(d))
}

func humanDur(d time.Duration) string {
	if d >= 24*time.Hour {
		days := int(d / (24 * time.Hour))
		hrs := int((d % (24 * time.Hour)) / time.Hour)
		return fmt.Sprintf("%dd %dh", days, hrs)
	}
	if d >= time.Hour {
		return fmt.Sprintf("%dh %dm", int(d/time.Hour), int((d%time.Hour)/time.Minute))
	}
	return fmt.Sprintf("%dm", int(d/time.Minute))
}
