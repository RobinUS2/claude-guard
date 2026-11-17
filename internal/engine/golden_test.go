package engine

import (
	"bufio"
	"errors"
	"strings"
	"testing"

	"github.com/RobinUS2/claude-guard/internal/config"
	"github.com/RobinUS2/claude-guard/internal/corpus"
	"github.com/RobinUS2/claude-guard/internal/legacy"
	"github.com/RobinUS2/claude-guard/internal/redact"
)

// Golden corpus tests — feed every command from the embedded corpus
// (internal/corpus) through the engine and assert the verdict matches
// the file label.
//
// Run on every `make test`. Catches regressions when rule changes
// silently shift behavior. The corpus is exercise of tier 1 + tier 2
// only — no LLM, no cache, no legacy. Engine in enforce mode. The
// legacy corpora at the bottom add a fixture tier-5 list.
//
// To add a case: edit internal/corpus/testdata/bash_<verdict>.txt and
// re-run tests. The CLI `lint` subcommand runs the same corpus via the
// same embedded strings, so a green `go test` implies a green `lint`.

// loadCorpusString splits an embedded corpus string into commands,
// skipping blank lines and lines starting with '#'.
func loadCorpusString(t *testing.T, content string) []string {
	t.Helper()
	var commands []string
	scanner := bufio.NewScanner(strings.NewReader(content))
	scanner.Buffer(make([]byte, 1<<16), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		commands = append(commands, line)
	}
	return commands
}

func goldenEngine(t *testing.T) *Engine {
	t.Helper()
	cfg := config.Default()
	cfg.ShadowMode = false // enforce so verdicts are real
	return New(cfg, nil)
}

func TestGoldenCorpus_BashAllow(t *testing.T) {
	e := goldenEngine(t)
	cmds := loadCorpusString(t, corpus.Allow)
	if len(cmds) == 0 {
		t.Fatal("empty corpus")
	}
	var fails []string
	for _, cmd := range cmds {
		out := e.Decide(Input{ToolName: "Bash", Command: cmd})
		if out.Verdict != Allow {
			fails = append(fails, formatGoldenFail(cmd, "Allow", out))
		}
	}
	if len(fails) > 0 {
		t.Errorf("%d commands did NOT reach Allow:\n%s", len(fails), strings.Join(fails, "\n"))
	}
}

func TestGoldenCorpus_BashDeny(t *testing.T) {
	e := goldenEngine(t)
	cmds := loadCorpusString(t, corpus.Deny)
	if len(cmds) == 0 {
		t.Fatal("empty corpus")
	}
	var fails []string
	for _, cmd := range cmds {
		out := e.Decide(Input{ToolName: "Bash", Command: cmd})
		if out.Verdict != Deny {
			fails = append(fails, formatGoldenFail(cmd, "Deny", out))
		}
	}
	if len(fails) > 0 {
		t.Errorf("%d commands did NOT reach Deny:\n%s", len(fails), strings.Join(fails, "\n"))
	}
}

func TestGoldenCorpus_BashContinue(t *testing.T) {
	e := goldenEngine(t)
	cmds := loadCorpusString(t, corpus.Continue)
	if len(cmds) == 0 {
		t.Fatal("empty corpus")
	}
	var fails []string
	for _, cmd := range cmds {
		out := e.Decide(Input{ToolName: "Bash", Command: cmd})
		if out.Verdict != Continue {
			fails = append(fails, formatGoldenFail(cmd, "Continue", out))
		}
	}
	if len(fails) > 0 {
		t.Errorf("%d commands did NOT reach Continue:\n%s", len(fails), strings.Join(fails, "\n"))
	}
}

// TestGoldenCorpus_BashAdversarial is the security-critical one. Every
// command in this file MUST end in Deny — they're all known bypass
// attempts. A regression here is a security incident.
func TestGoldenCorpus_BashAdversarial(t *testing.T) {
	e := goldenEngine(t)
	cmds := loadCorpusString(t, corpus.Adversarial)
	if len(cmds) == 0 {
		t.Fatal("empty adversarial corpus")
	}
	var fails []string
	for _, cmd := range cmds {
		out := e.Decide(Input{ToolName: "Bash", Command: cmd})
		if out.Verdict != Deny {
			fails = append(fails, formatGoldenFail(cmd, "Deny (adversarial)", out))
		}
	}
	if len(fails) > 0 {
		t.Errorf("SECURITY: %d adversarial commands did NOT reach Deny:\n%s",
			len(fails), strings.Join(fails, "\n"))
	}
}

func formatGoldenFail(cmd, expected string, out Output) string {
	return "  command:  " + cmd + "\n" +
		"    expected: " + expected + "\n" +
		"    got:      verdict=" + string(out.Verdict) +
		" tier=" + out.Tier +
		" rule=" + out.Rule +
		" reason=" + out.Reason
}

// TestGoldenCorpus_BashAsk: every command in bash_ask.txt must end in Ask,
// from the always_ask tier, and never Allow. Includes the disguised forms.
func TestGoldenCorpus_BashAsk(t *testing.T) {
	e := goldenEngine(t)
	cmds := loadCorpusString(t, corpus.Ask)
	if len(cmds) == 0 {
		t.Fatal("empty ask corpus")
	}
	var fails []string
	for _, cmd := range cmds {
		out := e.Decide(Input{ToolName: "Bash", Command: cmd})
		if out.Verdict != Ask || out.Tier != "always_ask" || out.Rule != "gcloud-builds-cancel" {
			fails = append(fails, formatGoldenFail(cmd, "Ask (always_ask)", out))
		}
	}
	if len(fails) > 0 {
		t.Errorf("%d commands did NOT reach Ask:\n%s", len(fails), strings.Join(fails, "\n"))
	}
}

// legacyGoldenEngine is goldenEngine plus the fixture tier-5 list from
// corpus.LegacyPatterns. No LLM, no cache: tier 5 is the only thing that
// can allow a command the deterministic tiers left open.
func legacyGoldenEngine(t *testing.T) *Engine {
	t.Helper()
	cfg := config.Default()
	cfg.ShadowMode = false
	al := legacy.FromEntries(corpus.LegacyPatterns)
	if len(al.Patterns) == 0 {
		t.Fatal("legacy fixture list is empty")
	}
	return NewWithOptions(Options{Config: cfg, Legacy: al})
}

func TestGoldenCorpus_LegacyAllow(t *testing.T) {
	e := legacyGoldenEngine(t)
	cmds := loadCorpusString(t, corpus.LegacyAllow)
	if len(cmds) == 0 {
		t.Fatal("empty corpus")
	}
	var fails []string
	for _, cmd := range cmds {
		out := e.Decide(Input{ToolName: "Bash", Command: cmd})
		if out.Verdict != Allow || out.Tier != "legacy" {
			fails = append(fails, formatGoldenFail(cmd, "Allow (tier legacy)", out))
		}
	}
	if len(fails) > 0 {
		t.Errorf("%d commands did NOT reach Allow via legacy:\n%s", len(fails), strings.Join(fails, "\n"))
	}
}

// TestGoldenCorpus_LegacyNotAllow is security-critical: every line starts
// with a listed prefix and continues with something no pattern approved.
func TestGoldenCorpus_LegacyNotAllow(t *testing.T) {
	e := legacyGoldenEngine(t)
	cmds := loadCorpusString(t, corpus.LegacyNotAllow)
	if len(cmds) == 0 {
		t.Fatal("empty corpus")
	}
	var fails []string
	for _, cmd := range cmds {
		out := e.Decide(Input{ToolName: "Bash", Command: cmd})
		if out.Verdict == Allow {
			fails = append(fails, formatGoldenFail(cmd, "not Allow", out))
		}
	}
	if len(fails) > 0 {
		t.Errorf("SECURITY: %d commands were allowed past the legacy list:\n%s",
			len(fails), strings.Join(fails, "\n"))
	}
}

// TestGoldenCorpus_LegacyRedactionSkipNotAllow: listed commands that carry
// a credential-shaped string are withheld from the LLM by the redaction
// filter, and tier 5 must not allow them. The strings are fictional and
// built from pieces.
func TestGoldenCorpus_LegacyRedactionSkipNotAllow(t *testing.T) {
	cfg := config.Default()
	cfg.ShadowMode = false
	e := NewWithOptions(Options{
		Config:   cfg,
		LLM:      &stubClassifier{err: errors.New("unavailable")},
		Legacy:   legacy.FromEntries(corpus.LegacyPatterns),
		Redactor: redact.New(nil, nil),
	})
	fake := []string{
		"gh" + "p_" + strings.Repeat("Zy9", 8),
		"AK" + "IA" + strings.Repeat("Q7", 8),
		"sk-" + "ant-" + strings.Repeat("Xk2", 10),
	}
	for _, c := range fake {
		for _, cmd := range []string{"acme-cli status " + c, "acme-report --token " + c} {
			if out := e.Decide(Input{ToolName: "Bash", Command: cmd}); out.Verdict == Allow {
				t.Errorf("SECURITY: allowed via tier %s despite redaction skip: %s", out.Tier, cmd[:12]+"...")
			}
		}
	}
}
