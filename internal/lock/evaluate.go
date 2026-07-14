package lock

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/RobinUS2/claude-guard/internal/freeze"
	"github.com/RobinUS2/claude-guard/internal/rules"
	"github.com/RobinUS2/claude-guard/internal/shellparse"
)

// Action is the lock evaluator's outcome for a command.
type Action int

const (
	// Pass — no relevant lock, or the check couldn't determine one (fails open).
	Pass Action = iota
	// Ask — surface the normal permission dialog; Reason names the holder.
	Ask
)

// Outcome is the result of evaluating a command against any held locks.
type Outcome struct {
	Action Action
	Rule   string // catalog rule name that matched (empty on Pass)
	Env    string // env the held lock covers (empty on Pass)
	Reason string // human-readable message for the Ask dialog
}

// Evaluate checks a parsed command against the deploy-shaped catalog shared
// with the freeze package and, on a match, asks whether a release-lock is
// currently held by someone else for that env. Always active — independent
// of whether a freeze is armed; the two can both fire on the same command.
//
// resolveRepo and resolveWhoHost are lazy: they're only called after a
// catalog match, mirroring freeze.Evaluate's lazy remote resolution (a
// command that doesn't look like a deploy never pays for a git subprocess).
// resolveRepo returning ok=false (no remote, or non-GitHub) makes every
// entry Pass — there's nothing to check against.
func Evaluate(
	ctx context.Context,
	parsed *shellparse.Parsed,
	resolveRepo func() (repo string, ok bool),
	checker Checker,
	resolveWhoHost func() (who, host string),
	now time.Time,
) Outcome {
	if parsed == nil || checker == nil {
		return Outcome{Action: Pass}
	}

	for _, e := range freeze.Catalog() {
		for _, env := range e.Envs {
			if v, _ := e.Rule.Eval(parsed); v != rules.Match {
				continue
			}
			repo, ok := resolveRepo()
			if !ok {
				return Outcome{Action: Pass}
			}
			info, err := checker.Status(ctx, repo, env)
			if err != nil || info == nil {
				continue // fail open: unknown state or genuinely clear
			}
			who, host := resolveWhoHost()
			if who != "" && info.Who == who && info.Host == host {
				continue // same actor holds it — don't nag yourself
			}
			return Outcome{Action: Ask, Rule: e.Name, Env: env, Reason: reason(e.Name, env, info, now)}
		}
	}
	return Outcome{Action: Pass}
}

func reason(rule, env string, info *Info, now time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "⚠️ POSSIBLE DEPLOY IN PROGRESS (%s) — confirm before proceeding.\n\n", env)
	fmt.Fprintf(&b, "  Matched : release-lock catalog rule %q (env=%s)\n", rule, env)
	fmt.Fprintf(&b, "  Held by : %s @ %s\n", info.Who, info.Host)
	if info.Agent != "" {
		fmt.Fprintf(&b, "  Agent   : %s\n", info.Agent)
	}
	if info.Task != "" {
		fmt.Fprintf(&b, "  Task    : %s\n", info.Task)
	}
	if info.Reason != "" {
		fmt.Fprintf(&b, "  Reason  : %s\n", info.Reason)
	}
	if !info.CreatedAt.IsZero() {
		fmt.Fprintf(&b, "  Age     : %s\n", humanDur(now.Sub(info.CreatedAt)))
	}
	b.WriteString("\n  claude-guard can't confirm this is safe to run concurrently.\n")
	b.WriteString("  If it targets the same release, cancel and coordinate first;\n")
	b.WriteString("  if it's unrelated, it's fine to proceed.\n\n")
	fmt.Fprintf(&b, "  Check manually: release-lock.sh status --env %s --repo <owner/repo>\n", env)
	return b.String()
}

func humanDur(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d >= time.Hour {
		return fmt.Sprintf("%dh %dm", int(d/time.Hour), int((d%time.Hour)/time.Minute))
	}
	if d >= time.Minute {
		return fmt.Sprintf("%dm", int(d/time.Minute))
	}
	return fmt.Sprintf("%ds", int(d/time.Second))
}
