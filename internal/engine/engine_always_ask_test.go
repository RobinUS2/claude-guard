package engine

import (
	"testing"

	"github.com/RobinUS2/claude-guard/internal/config"
)

// The human-visible reason must be exactly the one Robin approved.
func TestAlwaysAsk_BuildsCancelReason(t *testing.T) {
	e := goldenEngine(t)
	out := e.Decide(Input{ToolName: "Bash", Command: "gcloud builds cancel abc"})
	want := "gcloud builds cancel: read the build's trigger first; only superseded builds of the staging deploy or PR gate trigger may be cancelled, never a production trigger or a release PR build, never selected by commit match"
	if out.Verdict != Ask || out.Reason != want {
		t.Fatalf("verdict=%s reason=%q", out.Verdict, out.Reason)
	}
}

// Read-only builds verbs and mere mentions of the words must not trip the rule.
func TestAlwaysAsk_BuildsCancelNegatives(t *testing.T) {
	e := goldenEngine(t)
	for _, cmd := range []string{
		"gcloud builds list --project=p",
		"gcloud builds list --ongoing --format='value(id)'",
		"gcloud builds describe 1234-abcd --project=p",
		"gcloud builds log 1234-abcd --project=p",
		`echo "gcloud builds cancel is dangerous"`,
		`echo "builds cancel"`,
		`grep "builds cancel" notes.md`,
		`grep -r 'gcloud builds cancel' docs`,
		"gcloud builds list --filter=status=WORKING",
	} {
		out := e.Decide(Input{ToolName: "Bash", Command: cmd})
		if out.Rule == "gcloud-builds-cancel" || out.Tier == "always_ask" {
			t.Errorf("%q wrongly matched always_ask: %+v", cmd, out)
		}
	}
}

// Shadow mode must not switch the rule off.
func TestAlwaysAsk_EnforcedInShadowMode(t *testing.T) {
	cfg := config.Default()
	cfg.ShadowMode = true
	e := New(cfg, nil)
	out := e.Decide(Input{ToolName: "Bash", Command: "gcloud builds cancel abc"})
	if out.Verdict != Ask {
		t.Fatalf("shadow mode: verdict=%s, want ask", out.Verdict)
	}
}

// Tier 1 still wins over the always-ask tier.
func TestAlwaysAsk_Tier1StillWins(t *testing.T) {
	e := goldenEngine(t)
	out := e.Decide(Input{ToolName: "Bash", Command: "sudo gcloud builds cancel abc"})
	if out.Verdict != Deny {
		t.Fatalf("sudo + cancel: verdict=%s tier=%s, want deny", out.Verdict, out.Tier)
	}
	out = e.Decide(Input{ToolName: "Bash", Command: "gcloud builds cancel abc; rm -rf /"})
	if out.Verdict != Deny {
		t.Fatalf("cancel + rm -rf /: verdict=%s, want deny", out.Verdict)
	}
}

// A cached allow, a project allow rule and Monitor must not bypass it.
func TestAlwaysAsk_MonitorSameVerdict(t *testing.T) {
	e := goldenEngine(t)
	out := e.Decide(Input{ToolName: "Monitor", Command: "gcloud builds cancel abc"})
	if out.Verdict != Ask {
		t.Fatalf("monitor: verdict=%s, want ask", out.Verdict)
	}
}
