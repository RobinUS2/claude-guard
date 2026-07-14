package lock

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/RobinUS2/claude-guard/internal/shellparse"
)

var now = time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)

func mustParse(t *testing.T, cmd string) *shellparse.Parsed {
	t.Helper()
	p, err := shellparse.Parse(cmd)
	if err != nil {
		t.Fatalf("parse %q: %v", cmd, err)
	}
	return p
}

// fakeChecker returns a fixed (Info, error) for every call, recording the
// (repo, env) pairs it was asked about.
type fakeChecker struct {
	info  *Info
	err   error
	calls [][2]string
}

func (f *fakeChecker) Status(_ context.Context, repo, env string) (*Info, error) {
	f.calls = append(f.calls, [2]string{repo, env})
	return f.info, f.err
}

func repoResolver(repo string, ok bool) func() (string, bool) {
	return func() (string, bool) { return repo, ok }
}

func whoHostResolver(who, host string) func() (string, string) {
	return func() (string, string) { return who, host }
}

func TestEvaluate_NoLock_Passes(t *testing.T) {
	checker := &fakeChecker{info: nil, err: nil}
	out := Evaluate(context.Background(), mustParse(t, "make release-pr"),
		repoResolver("taufinity/ai-site-gen", true), checker, whoHostResolver("robin", "mac.home"), now)
	if out.Action != Pass {
		t.Errorf("action = %v, want Pass", out.Action)
	}
}

func TestEvaluate_NonDeployCommand_NeverChecksLock(t *testing.T) {
	checker := &fakeChecker{info: &Info{Who: "someone", Host: "elsewhere"}}
	out := Evaluate(context.Background(), mustParse(t, "ls -la"),
		repoResolver("taufinity/ai-site-gen", true), checker, whoHostResolver("robin", "mac.home"), now)
	if out.Action != Pass {
		t.Errorf("action = %v, want Pass", out.Action)
	}
	if len(checker.calls) != 0 {
		t.Errorf("expected no lock check for a non-deploy command, got %d calls", len(checker.calls))
	}
}

func TestEvaluate_LockHeldByOther_Asks(t *testing.T) {
	checker := &fakeChecker{info: &Info{
		Who: "Someone Else <se@example.com>", Host: "other-host",
		Agent: "claude-code", Task: "feat/x", Reason: "hotfix",
		CreatedAt: now.Add(-5 * time.Minute),
	}}
	out := Evaluate(context.Background(), mustParse(t, "make merge-production-pr"),
		repoResolver("taufinity/ai-site-gen", true), checker, whoHostResolver("robin", "mac.home"), now)
	if out.Action != Ask {
		t.Fatalf("action = %v, want Ask", out.Action)
	}
	if out.Rule != "make-prod-release" {
		t.Errorf("rule = %q, want make-prod-release", out.Rule)
	}
	if out.Env != "prod" {
		t.Errorf("env = %q, want prod", out.Env)
	}
	if !strings.Contains(out.Reason, "Someone Else") || !strings.Contains(out.Reason, "5m") {
		t.Errorf("reason missing holder/age info: %q", out.Reason)
	}
}

func TestEvaluate_LockHeldBySameActor_Passes(t *testing.T) {
	checker := &fakeChecker{info: &Info{Who: "Robin Verlangen <robin@taufinity.io>", Host: "mac.home"}}
	out := Evaluate(context.Background(), mustParse(t, "make merge-production-pr"),
		repoResolver("taufinity/ai-site-gen", true), checker,
		whoHostResolver("Robin Verlangen <robin@taufinity.io>", "mac.home"), now)
	if out.Action != Pass {
		t.Errorf("action = %v, want Pass (self-held lock should not nag)", out.Action)
	}
}

func TestEvaluate_CheckerError_FailsOpen(t *testing.T) {
	checker := &fakeChecker{err: context.DeadlineExceeded}
	out := Evaluate(context.Background(), mustParse(t, "make merge-production-pr"),
		repoResolver("taufinity/ai-site-gen", true), checker, whoHostResolver("robin", "mac.home"), now)
	if out.Action != Pass {
		t.Errorf("action = %v, want Pass on checker error (fail open)", out.Action)
	}
}

func TestEvaluate_NoRepo_FailsOpen(t *testing.T) {
	checker := &fakeChecker{info: &Info{Who: "someone", Host: "elsewhere"}}
	out := Evaluate(context.Background(), mustParse(t, "make merge-production-pr"),
		repoResolver("", false), checker, whoHostResolver("robin", "mac.home"), now)
	if out.Action != Pass {
		t.Errorf("action = %v, want Pass when repo can't be resolved", out.Action)
	}
	if len(checker.calls) != 0 {
		t.Errorf("expected no lock check when repo is unresolvable, got %d calls", len(checker.calls))
	}
}

func TestEvaluate_NilChecker_Passes(t *testing.T) {
	out := Evaluate(context.Background(), mustParse(t, "make merge-production-pr"),
		repoResolver("taufinity/ai-site-gen", true), nil, whoHostResolver("robin", "mac.home"), now)
	if out.Action != Pass {
		t.Errorf("action = %v, want Pass with nil checker", out.Action)
	}
}

func TestEvaluate_StagingCatalogEntry(t *testing.T) {
	checker := &fakeChecker{info: &Info{Who: "Someone Else", Host: "other-host"}}
	out := Evaluate(context.Background(), mustParse(t, "make deploy-staging"),
		repoResolver("taufinity/ai-site-gen", true), checker, whoHostResolver("robin", "mac.home"), now)
	if out.Action != Ask {
		t.Fatalf("action = %v, want Ask", out.Action)
	}
	if out.Env != "staging" {
		t.Errorf("env = %q, want staging", out.Env)
	}
}
