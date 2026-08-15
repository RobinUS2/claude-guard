package engine

import (
	"strings"
	"testing"

	"github.com/RobinUS2/claude-guard/internal/corpus"
)

// The Monitor tool takes a `command` string and runs it in the same
// shell Bash does — it is a second Bash, not a stdout reader. These
// tests pin that Monitor gets the identical tier pipeline, so widening
// the PreToolUse matcher to "Bash|Monitor" cannot become a bypass.

// TestMonitorGoldenCorpus_Adversarial is the security-critical one.
// Every known bypass attempt, wrapped in Monitor, MUST still deny.
// A regression here means Monitor is a hole around all of tier 1.
func TestMonitorGoldenCorpus_Adversarial(t *testing.T) {
	e := goldenEngine(t)
	cmds := loadCorpusString(t, corpus.Adversarial)
	if len(cmds) == 0 {
		t.Fatal("empty adversarial corpus")
	}
	var fails []string
	for _, cmd := range cmds {
		out := e.Decide(Input{ToolName: "Monitor", Command: cmd})
		if out.Verdict != Deny {
			fails = append(fails, formatGoldenFail(cmd, "Deny (adversarial via Monitor)", out))
		}
	}
	if len(fails) > 0 {
		t.Errorf("SECURITY: %d adversarial commands did NOT deny when wrapped in Monitor:\n%s",
			len(fails), strings.Join(fails, "\n"))
	}
}

// TestMonitorGoldenCorpus_Deny — the plain deny corpus must also hold
// through Monitor.
func TestMonitorGoldenCorpus_Deny(t *testing.T) {
	e := goldenEngine(t)
	cmds := loadCorpusString(t, corpus.Deny)
	if len(cmds) == 0 {
		t.Fatal("empty corpus")
	}
	var fails []string
	for _, cmd := range cmds {
		out := e.Decide(Input{ToolName: "Monitor", Command: cmd})
		if out.Verdict != Deny {
			fails = append(fails, formatGoldenFail(cmd, "Deny (via Monitor)", out))
		}
	}
	if len(fails) > 0 {
		t.Errorf("%d commands did NOT reach Deny via Monitor:\n%s", len(fails), strings.Join(fails, "\n"))
	}
}

// TestMonitorGoldenCorpus_Allow — the point of the change. Safe
// read-only watch commands auto-allow instead of prompting.
func TestMonitorGoldenCorpus_Allow(t *testing.T) {
	e := goldenEngine(t)
	cmds := loadCorpusString(t, corpus.Allow)
	if len(cmds) == 0 {
		t.Fatal("empty corpus")
	}
	var fails []string
	for _, cmd := range cmds {
		out := e.Decide(Input{ToolName: "Monitor", Command: cmd})
		if out.Verdict != Allow {
			fails = append(fails, formatGoldenFail(cmd, "Allow (via Monitor)", out))
		}
	}
	if len(fails) > 0 {
		t.Errorf("%d commands did NOT reach Allow via Monitor:\n%s", len(fails), strings.Join(fails, "\n"))
	}
}

// TestMonitorVerdictMatchesBash asserts the two tools agree command for
// command. Any divergence is a bug in one of the two paths.
func TestMonitorVerdictMatchesBash(t *testing.T) {
	e := goldenEngine(t)
	var all []string
	for _, c := range []string{corpus.Allow, corpus.Deny, corpus.Continue, corpus.Adversarial} {
		all = append(all, loadCorpusString(t, c)...)
	}
	var fails []string
	for _, cmd := range all {
		bash := e.Decide(Input{ToolName: "Bash", Command: cmd})
		mon := e.Decide(Input{ToolName: "Monitor", Command: cmd})
		if bash.Verdict != mon.Verdict || bash.Rule != mon.Rule {
			fails = append(fails, cmd+
				"\n    Bash:    "+string(bash.Verdict)+" tier="+bash.Tier+" rule="+bash.Rule+
				"\n    Monitor: "+string(mon.Verdict)+" tier="+mon.Tier+" rule="+mon.Rule)
		}
	}
	if len(fails) > 0 {
		t.Errorf("%d commands diverged between Bash and Monitor:\n%s", len(fails), strings.Join(fails, "\n"))
	}
}

// TestMonitorRealWorldWatches covers the shapes that prompted this
// change. The golden engine runs tier 1+2 only (no cache, no legacy,
// no LLM), so commands that depend on later tiers are asserted against
// Bash rather than against a fixed verdict.
func TestMonitorRealWorldWatches(t *testing.T) {
	e := goldenEngine(t)

	// Read-only watches resolve at tier 2 and auto-allow outright.
	tier2 := []string{
		"tail -f /tmp/deploy.log",
		"git status",
	}
	for _, cmd := range tier2 {
		out := e.Decide(Input{ToolName: "Monitor", Command: cmd})
		if out.Verdict != Allow {
			t.Errorf("%q: Verdict = %v (tier=%s rule=%s reason=%s), want Allow",
				cmd, out.Verdict, out.Tier, out.Rule, out.Reason)
		}
	}

	// The gcloud build poll from the screenshot resolves at tier 5
	// (legacy `Bash(gcloud builds describe *)`), which the golden engine
	// does not load. What matters is that Monitor reaches the same tier
	// Bash does — the end-to-end verdict is covered by the decide
	// integration test.
	const buildWatch = `gcloud builds describe 75766224-6b67-4c68-9fe1-eabbc0000001 --project=content-gen-484211 --region=europe-west4 --format='value(status)'`
	bash := e.Decide(Input{ToolName: "Bash", Command: buildWatch})
	mon := e.Decide(Input{ToolName: "Monitor", Command: buildWatch})
	if bash.Verdict != mon.Verdict || bash.Tier != mon.Tier {
		t.Errorf("build watch diverged: Bash=%v/%s Monitor=%v/%s",
			bash.Verdict, bash.Tier, mon.Verdict, mon.Tier)
	}
}

// TestMonitorWS covers the `ws:` variant, which carries no shell
// command at all — it opens a socket to an arbitrary URL. It must get
// the same SSRF checks WebFetch gets.
func TestMonitorWS(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want Verdict
	}{
		{"cloud metadata endpoint", "ws://169.254.169.254/latest/meta-data/", Deny},
		{"localhost", "wss://localhost:8080/stream", Deny},
		{"file scheme", "file:///etc/passwd", Deny},
		// No LLM in the golden engine, so a benign external host has no
		// tier that can approve it — it falls through to a user prompt.
		{"external host falls through", "wss://events.example.com/stream", Continue},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := goldenEngine(t)
			out := e.Decide(Input{ToolName: "Monitor", URL: tc.url})
			if out.Verdict != tc.want {
				t.Errorf("Verdict = %v (tier=%s rule=%s), want %v",
					out.Verdict, out.Tier, out.Rule, tc.want)
			}
		})
	}
}

// TestMonitorEmptyInput — neither command nor ws. Nothing to inspect,
// so there is no basis to allow: fall through to a user prompt.
func TestMonitorEmptyInput(t *testing.T) {
	e := goldenEngine(t)
	out := e.Decide(Input{ToolName: "Monitor"})
	if out.Verdict != Continue {
		t.Errorf("Verdict = %v (tier=%s rule=%s), want Continue", out.Verdict, out.Tier, out.Rule)
	}
}

// TestMonitorNotStructurallySafe pins the removal of "Monitor" from
// safeBuiltinTools. If someone re-adds it, every Monitor command
// auto-allows without inspection and this fails.
func TestMonitorNotStructurallySafe(t *testing.T) {
	if safe, rule := isStructurallySafeTool("Monitor"); safe {
		t.Errorf("Monitor is in the structural allowlist (rule=%q) — it executes arbitrary "+
			"shell commands and must go through the Bash pipeline instead", rule)
	}
}

// TestMonitorGitPushGetsRepoContext pins that the tier-2.7 git-push
// path is not skipped just because the tool is Monitor.
func TestMonitorGitPushGetsRepoContext(t *testing.T) {
	e := goldenEngine(t)
	const cmd = "git push --force origin main"
	bash := e.Decide(Input{ToolName: "Bash", Command: cmd})
	mon := e.Decide(Input{ToolName: "Monitor", Command: cmd})
	if bash.Verdict != mon.Verdict {
		t.Errorf("git push verdict diverged: Bash=%v Monitor=%v", bash.Verdict, mon.Verdict)
	}
	if mon.Verdict != Deny {
		t.Errorf("force-push via Monitor = %v, want Deny", mon.Verdict)
	}
}
