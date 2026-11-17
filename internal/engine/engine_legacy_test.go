package engine

import (
	"errors"
	"testing"

	"github.com/RobinUS2/claude-guard/internal/config"
	"github.com/RobinUS2/claude-guard/internal/legacy"
	"github.com/RobinUS2/claude-guard/internal/llm"
)

// Tier 5 is a fallback for when the LLM could not judge the command. It
// must never overrule an LLM that did judge it and said unsafe or unsure.
func TestEngine_Legacy_NeverOverridesLLMRefusal(t *testing.T) {
	al := legacy.FromEntries("Bash(acme-cli status:*)")
	for _, tc := range []struct {
		name    string
		stub    *stubClassifier
		want    Verdict
		wantTie string
	}{
		{"unsafe", &stubClassifier{verdict: llm.VerdictUnsafe}, Continue, "default"},
		{"unsure", &stubClassifier{verdict: llm.VerdictUnsure}, Continue, "default"},
		{"llm error falls back to legacy", &stubClassifier{err: errors.New("boom")}, Allow, "legacy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.ShadowMode = false
			e := NewWithOptions(Options{Config: cfg, LLM: tc.stub, Legacy: al})
			out := e.Decide(Input{ToolName: "Bash", Command: "acme-cli status"})
			if tc.stub.calls != 1 {
				t.Fatalf("LLM calls = %d, want 1", tc.stub.calls)
			}
			if out.Verdict != tc.want || out.Tier != tc.wantTie {
				t.Errorf("got verdict=%s tier=%s, want verdict=%s tier=%s", out.Verdict, out.Tier, tc.want, tc.wantTie)
			}
		})
	}
}

// Without an LLM, tier 5 still allows a listed call (the fallback case).
func TestEngine_Legacy_AllowsListedCallWithoutLLM(t *testing.T) {
	cfg := config.Default()
	cfg.ShadowMode = false
	e := NewWithOptions(Options{Config: cfg, Legacy: legacy.FromEntries("Bash(acme-cli status:*)")})
	if out := e.Decide(Input{ToolName: "Bash", Command: "acme-cli status"}); out.Verdict != Allow || out.Tier != "legacy" {
		t.Errorf("got verdict=%s tier=%s, want allow via legacy", out.Verdict, out.Tier)
	}
	if out := e.Decide(Input{ToolName: "Bash", Command: "acme-cli status; true"}); out.Verdict == Allow {
		t.Errorf("compound command allowed via tier %s", out.Tier)
	}
}
