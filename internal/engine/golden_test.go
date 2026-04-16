package engine

import (
	"bufio"
	"strings"
	"testing"

	"github.com/RobinUS2/claude-guard/internal/config"
	"github.com/RobinUS2/claude-guard/internal/corpus"
)

// Golden corpus tests — feed every command from the embedded corpus
// (internal/corpus) through the engine and assert the verdict matches
// the file label.
//
// Run on every `make test`. Catches regressions when rule changes
// silently shift behavior. The corpus is exercise of tier 1 + tier 2
// only — no LLM, no cache, no legacy. Engine in enforce mode.
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
