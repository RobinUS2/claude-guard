package engine

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/RobinUS2/claude-guard/internal/config"
)

// Golden corpus tests — feed every command from testdata/ files
// through the engine and assert the verdict matches the file label.
//
// Run on every `make test`. Catches regressions when rule changes
// silently shift behavior. The corpus is exercise of tier 1 + tier 2
// only — no LLM, no cache, no legacy. Engine in enforce mode.
//
// To add a case: edit testdata/bash_<verdict>.txt and re-run tests.
// To debug a failure: the test reports the line number, command, and
// the actual verdict + tier + rule that fired.

func loadCorpus(t *testing.T, name string) []string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	root := filepath.Dir(filepath.Dir(filepath.Dir(thisFile))) // ../../.. → repo root
	path := filepath.Join(root, "testdata", name)
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open corpus %s: %v", path, err)
	}
	defer f.Close()

	var commands []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		commands = append(commands, line)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan corpus %s: %v", path, err)
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
	cmds := loadCorpus(t, "bash_allow.txt")
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
	cmds := loadCorpus(t, "bash_deny.txt")
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
	cmds := loadCorpus(t, "bash_continue.txt")
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
	cmds := loadCorpus(t, "bash_adversarial.txt")
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
