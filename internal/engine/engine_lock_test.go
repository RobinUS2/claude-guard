package engine

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/RobinUS2/claude-guard/internal/config"
	"github.com/RobinUS2/claude-guard/internal/lock"
	clog "github.com/RobinUS2/claude-guard/internal/log"
)

// fakeLockChecker returns a fixed (Info, error) for every call.
type fakeLockChecker struct {
	info *lock.Info
	err  error
}

func (f fakeLockChecker) Status(_ context.Context, _, _ string) (*lock.Info, error) {
	return f.info, f.err
}

func newLockEngine(t *testing.T, checker lock.Checker) *Engine {
	t.Helper()
	cfg := config.Default()
	paths := clog.DefaultPaths(t.TempDir())
	lg, err := clog.OpenDecisionLogger(paths, 10, 3)
	if err != nil {
		t.Fatalf("open logger: %v", err)
	}
	t.Cleanup(lg.Close)
	return NewWithOptions(Options{Config: cfg, DecisionLog: lg, LockChecker: checker})
}

func decideBashInCWD(t *testing.T, e *Engine, cmd string) Output {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return e.Decide(Input{ToolName: "Bash", Command: cmd, CWD: cwd})
}

func TestLock_HeldByOther_Asks(t *testing.T) {
	e := newLockEngine(t, fakeLockChecker{info: &lock.Info{
		Who: "Someone Else <se@example.com>", Host: "other-host",
		Reason: "hotfix", CreatedAt: time.Now().Add(-2 * time.Minute),
	}})
	out := decideBashInCWD(t, e, "make merge-production-pr")
	if out.Verdict != Ask {
		t.Fatalf("Verdict = %v (tier=%s rule=%s reason=%s), want Ask", out.Verdict, out.Tier, out.Rule, out.Reason)
	}
	if out.Tier != "release_lock" {
		t.Errorf("Tier = %q, want release_lock", out.Tier)
	}
	if !strings.Contains(out.Rule, "make-prod-release") {
		t.Errorf("Rule = %q, want it to name make-prod-release", out.Rule)
	}
	if !strings.Contains(out.Reason, "Someone Else") {
		t.Errorf("Reason missing holder info: %q", out.Reason)
	}
}

func TestLock_NoLock_Passes(t *testing.T) {
	e := newLockEngine(t, fakeLockChecker{info: nil, err: nil})
	out := decideBashInCWD(t, e, "make merge-production-pr")
	if out.Verdict == Ask && out.Tier == "release_lock" {
		t.Fatalf("expected no release_lock Ask when no lock is held, got %+v", out)
	}
}

func TestLock_NilChecker_NeverFires(t *testing.T) {
	e := newLockEngine(t, nil)
	out := decideBashInCWD(t, e, "make merge-production-pr")
	if out.Tier == "release_lock" {
		t.Fatalf("expected the release-lock tier to be a no-op with nil checker, got %+v", out)
	}
}

func TestLock_NonDeployCommand_Passes(t *testing.T) {
	e := newLockEngine(t, fakeLockChecker{info: &lock.Info{Who: "someone", Host: "elsewhere"}})
	out := decideBashInCWD(t, e, "ls -la")
	if out.Tier == "release_lock" {
		t.Fatalf("expected no release-lock check for a non-deploy command, got %+v", out)
	}
}

func TestLock_CheckerError_FailsOpen(t *testing.T) {
	e := newLockEngine(t, fakeLockChecker{err: context.DeadlineExceeded})
	out := decideBashInCWD(t, e, "make merge-production-pr")
	if out.Tier == "release_lock" {
		t.Fatalf("expected fail-open (no release_lock Ask) on checker error, got %+v", out)
	}
}
