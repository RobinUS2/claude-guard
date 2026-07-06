package engine

import (
	"strings"
	"testing"
	"time"

	"github.com/RobinUS2/claude-guard/internal/config"
	"github.com/RobinUS2/claude-guard/internal/freeze"
	clog "github.com/RobinUS2/claude-guard/internal/log"
)

// newFreezeEngine builds an engine wired with the given freeze states.
func newFreezeEngine(t *testing.T, shadow bool, states ...*freeze.State) *Engine {
	t.Helper()
	cfg := config.Default()
	cfg.ShadowMode = shadow
	paths := clog.DefaultPaths(t.TempDir())
	lg, err := clog.OpenDecisionLogger(paths, 10, 3)
	if err != nil {
		t.Fatalf("open logger: %v", err)
	}
	t.Cleanup(lg.Close)
	return NewWithOptions(Options{Config: cfg, DecisionLog: lg, Freeze: states})
}

func globalProdFreeze() *freeze.State {
	return &freeze.State{FrozenEnvs: []string{"prod"}, Reason: "test freeze", SetBy: "robin"}
}

func decideBash(e *Engine, cmd string) Output {
	return e.Decide(Input{ToolName: "Bash", Command: cmd})
}

func TestFreeze_DenyConfidentDeploy(t *testing.T) {
	e := newFreezeEngine(t, false, globalProdFreeze())
	out := decideBash(e, "make release")
	if out.Verdict != Deny {
		t.Fatalf("Verdict = %v (tier=%s rule=%s), want Deny", out.Verdict, out.Tier, out.Rule)
	}
	if out.Tier != "freeze" {
		t.Errorf("Tier = %q, want freeze", out.Tier)
	}
	if !strings.Contains(out.Rule, "make-prod-release") {
		t.Errorf("Rule = %q, want it to name make-prod-release", out.Rule)
	}
	if !strings.Contains(out.Reason, "RELEASE FREEZE ACTIVE") {
		t.Errorf("Reason missing freeze banner: %q", out.Reason)
	}
}

func TestFreeze_AskAmbiguousDeploy(t *testing.T) {
	e := newFreezeEngine(t, false, globalProdFreeze())
	for _, cmd := range []string{"terraform apply", "git push origin main"} {
		out := decideBash(e, cmd)
		if out.Verdict != Ask {
			t.Errorf("Decide(%q) = %v (tier=%s), want Ask", cmd, out.Verdict, out.Tier)
		}
		if out.Tier != "freeze" {
			t.Errorf("Decide(%q) tier = %q, want freeze", cmd, out.Tier)
		}
	}
}

func TestFreeze_StagingPassesUnderProdFreeze(t *testing.T) {
	e := newFreezeEngine(t, false, globalProdFreeze())
	// make deploy-staging is a staging entry; a prod freeze must not touch it.
	// It has no tier-2 allow rule either, so it falls through to Continue.
	out := decideBash(e, "make deploy-staging")
	if out.Verdict != Continue {
		t.Errorf("Verdict = %v (tier=%s rule=%s), want Continue", out.Verdict, out.Tier, out.Rule)
	}
}

func TestFreeze_DryRunPasses(t *testing.T) {
	e := newFreezeEngine(t, false, globalProdFreeze())
	out := decideBash(e, "terraform plan")
	if out.Verdict == Deny || out.Verdict == Ask {
		t.Errorf("terraform plan should not be frozen, got %v", out.Verdict)
	}
}

// TestFreeze_SecurityBlockStillWins is the critical ordering guarantee: a
// genuine tier-1 security deny must hard-DENY even under a freeze, and must NOT
// be downgraded to a freeze ASK.
func TestFreeze_SecurityBlockStillWins(t *testing.T) {
	e := newFreezeEngine(t, false, globalProdFreeze())
	out := decideBash(e, "rm -rf /")
	if out.Verdict != Deny {
		t.Fatalf("Verdict = %v, want Deny", out.Verdict)
	}
	if out.Tier != "instant_block" {
		t.Errorf("Tier = %q, want instant_block (security block must win over freeze)", out.Tier)
	}
}

// TestFreeze_PrecedesTier2Allow proves the freeze runs before the tier-2 allow
// list: an --include'd command that tier-2 would auto-approve is instead denied
// while the freeze is on.
func TestFreeze_PrecedesTier2Allow(t *testing.T) {
	s := globalProdFreeze()
	s.Include = []freeze.IncludeRule{{Program: "ls", Envs: []string{"prod"}}}

	// Sanity: without the freeze, `ls -la` is a tier-2 allow.
	base := newFreezeEngine(t, false)
	if out := decideBash(base, "ls -la"); out.Verdict != Allow {
		t.Fatalf("precondition: ls -la = %v, want Allow", out.Verdict)
	}

	e := newFreezeEngine(t, false, s)
	out := decideBash(e, "ls -la")
	if out.Verdict != Deny || out.Tier != "freeze" {
		t.Errorf("frozen include should deny before tier-2 allow, got %v (tier=%s)", out.Verdict, out.Tier)
	}
}

// TestFreeze_EnforcesInShadowMode covers D3: a freeze is an explicit operator
// action and enforces even when the guard is globally in shadow mode.
func TestFreeze_EnforcesInShadowMode(t *testing.T) {
	e := newFreezeEngine(t, true /* shadow */, globalProdFreeze())
	out := decideBash(e, "make release")
	if out.Verdict != Deny {
		t.Errorf("freeze must enforce in shadow mode, got %v (tier=%s)", out.Verdict, out.Tier)
	}
}

func TestFreeze_ExpiredDoesNotBlock(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	s := globalProdFreeze()
	s.ExpiresAt = &past
	e := newFreezeEngine(t, false, s)
	out := decideBash(e, "make release")
	if out.Verdict == Deny || out.Verdict == Ask {
		t.Errorf("expired freeze should not block, got %v", out.Verdict)
	}
}

func TestFreeze_NoStatesInert(t *testing.T) {
	e := newFreezeEngine(t, false) // no freeze states
	if out := decideBash(e, "make release"); out.Verdict == Deny || out.Verdict == Ask {
		t.Errorf("with no freeze, make release should pass, got %v", out.Verdict)
	}
}
