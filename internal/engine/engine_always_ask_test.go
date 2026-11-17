package engine

import (
	"os"
	"testing"
	"time"

	"github.com/RobinUS2/claude-guard/internal/cache"
	"github.com/RobinUS2/claude-guard/internal/config"
	"github.com/RobinUS2/claude-guard/internal/legacy"
	"github.com/RobinUS2/claude-guard/internal/llm"
	"github.com/RobinUS2/claude-guard/internal/projectconfig"
	"github.com/RobinUS2/claude-guard/internal/redact"
	"github.com/RobinUS2/claude-guard/internal/rules"
	"github.com/RobinUS2/claude-guard/internal/store"
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

// Extra read-only forms with variables, and unrelated REST calls, must not
// prompt.
func TestAlwaysAsk_BuildsCancelMoreNegatives(t *testing.T) {
	e := goldenEngine(t)
	for _, cmd := range []string{
		"gcloud builds list --project=$P",
		"gcloud builds list --project $P --limit 5",
		"gcloud builds describe $ID --project=p",
		"gcloud builds log $ID",
		"gcloud builds --project=$P list",
		"gcloud builds --project $P describe x",
		`echo 'gcloud builds cancel'`,
		"bash scripts/deploy.sh",
		`echo 'builds cancel' | bash`,
		"curl -s https://cloudbuild.googleapis.com/v1/projects/p/builds",
		"curl -s https://cloudbuild.googleapis.com/v1/projects/p/builds/1234-abcd",
		"curl -s https://example.com/builds/1:cancel",
	} {
		out := e.Decide(Input{ToolName: "Bash", Command: cmd})
		if out.Rule == "gcloud-builds-cancel" || out.Tier == "always_ask" {
			t.Errorf("%q wrongly matched always_ask: %+v", cmd, out)
		}
	}
}

// Multi-line forms (heredocs) cannot live in the line-based corpus.
func TestAlwaysAsk_BuildsCancelHeredoc(t *testing.T) {
	e := goldenEngine(t)
	for _, cmd := range []string{
		"bash <<EOF\ngcloud builds cancel 1234-abcd\nEOF",
		"sh <<'EOF'\ngcloud builds \\\n  cancel 1234-abcd\nEOF",
		"timeout 5 bash <<EOF\ngcloud builds cancel x\nEOF",
	} {
		for _, tool := range []string{"Bash", "Monitor"} {
			out := e.Decide(Input{ToolName: tool, Command: cmd})
			if out.Verdict != Ask || out.Rule != "gcloud-builds-cancel" {
				t.Errorf("%s %q: %+v", tool, cmd, out)
			}
		}
	}
}

// Tier 1 precedence also holds for the new forms.
func TestAlwaysAsk_Tier1StillWinsDisguised(t *testing.T) {
	e := goldenEngine(t)
	for _, cmd := range []string{
		"timeout 5 sh -c 'gcloud builds cancel x'; rm -rf /",
		"$(which gcloud) builds cancel x && sudo rm x",
		"echo 'gcloud builds cancel x' | sh; git push --force origin main",
	} {
		out := e.Decide(Input{ToolName: "Bash", Command: cmd})
		if out.Verdict != Deny {
			t.Errorf("%q: verdict=%s tier=%s, want deny", cmd, out.Verdict, out.Tier)
		}
	}
}

// The always-ask tier must beat everything that could auto-approve: a seeded
// session approval, a global cache entry, a project allow rule, an LLM that
// says safe, and a legacy allow-list entry for the whole command family.
func TestAlwaysAsk_WinsOverEveryAllowSource(t *testing.T) {
	const cmd = "gcloud builds cancel 1234-abcd --project=p"
	dir := t.TempDir()

	st, err := store.Open(dir + "/state.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	canonical := normalizeCommand(cmd)
	if err := st.WriteSessionApproval("sess", "", cache.SessionKey(canonical), canonical, cmd, "llm"); err != nil {
		t.Fatal(err)
	}

	legacyPath := dir + "/legacy.yaml"
	if err := os.WriteFile(legacyPath, []byte("version: 1\nsource: t\npatterns:\n  - {source: t, prefix: \"gcloud builds *\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	al, err := legacy.Load(legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	if al.Match(cmd) == nil {
		t.Fatal("legacy allow-list does not match the command; the test would prove nothing")
	}

	llmStub := &stubClassifier{verdict: llm.VerdictSafe}
	cfg := config.Default()
	cfg.ShadowMode = false
	e := NewWithOptions(Options{
		Config:   cfg,
		Redactor: redact.New(nil, nil),
		LLM:      llmStub,
		Cache:    cache.New(dir + "/verdicts"),
		Store:    st,
		Legacy:   al,
		ProjectConfigLoader: func(string) (*projectconfig.Config, error) {
			return &projectconfig.Config{
				Path: "/fake/.claude-guard.yml",
				Rules: []rules.Rule{&rules.AnchoredCommand{
					RuleName: "project:gcloud", Programs: []string{"gcloud"},
				}},
				Hash: "h",
			}, nil
		},
	})
	// Global cache entry marked safe for this exact command.
	key := keyForCmd(e, cmd, "/tmp")
	_ = e.cache.Put(key, cache.Entry{
		Verdict: cache.VerdictAllow, Tier: "llm", Command: cmd, StoredAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}, time.Hour)

	for _, tool := range []string{"Bash", "Monitor"} {
		out := e.Decide(Input{ToolName: tool, Command: cmd, CWD: "/tmp", SessionID: "sess"})
		if out.Verdict != Ask || out.Tier != "always_ask" {
			t.Errorf("%s: verdict=%s tier=%s rule=%s, want ask from always_ask", tool, out.Verdict, out.Tier, out.Rule)
		}
	}
	if llmStub.calls != 0 {
		t.Errorf("LLM was consulted %d times; the always-ask tier must decide first", llmStub.calls)
	}

	// Control: the same engine auto-approves a sibling read-only command, so
	// the allow sources above are really live.
	out := e.Decide(Input{ToolName: "Bash", Command: "gcloud builds list --project=p", CWD: "/tmp", SessionID: "sess"})
	if out.Verdict != Allow {
		t.Errorf("control: verdict=%s tier=%s, want allow", out.Verdict, out.Tier)
	}
}
