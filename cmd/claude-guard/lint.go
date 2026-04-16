package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/RobinUS2/claude-guard/internal/config"
	"github.com/RobinUS2/claude-guard/internal/corpus"
	"github.com/RobinUS2/claude-guard/internal/engine"
	"github.com/RobinUS2/claude-guard/internal/legacy"
)

// cmdLint validates config + runs the adversarial corpus through the
// current engine as a self-test. Use before shipping a rule change
// (edit defaults.go → run lint → install).
//
//	claude-guard lint [--verbose]
//
// Exit codes:
//
//	0 — clean
//	1 — one or more checks failed
func cmdLint(args []string) int {
	fs := flag.NewFlagSet("lint", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var verbose bool
	fs.BoolVar(&verbose, "verbose", false, "print every passing check, not just failures")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	pass := true
	check := func(name string, ok bool, detail string) {
		if ok {
			if verbose {
				fmt.Printf("[ok]   %-32s %s\n", name, detail)
			}
			return
		}
		fmt.Printf("[FAIL] %-32s %s\n", name, detail)
		pass = false
	}

	// 1. Config loads without errors.
	result := config.Load("")
	if result.Warning != nil {
		// A missing file is a warning not a fail; a parse error IS a fail.
		if _, err := os.Stat(config.DefaultConfigPath()); err == nil {
			check("config:parse", false, result.Warning.Error())
		} else {
			check("config:parse", true, "using compiled defaults (no user config file)")
		}
	} else {
		check("config:parse", true, "loaded from "+config.DefaultConfigPath())
	}

	// 2. Rule counts are sane.
	cfg := result.Config
	check("rules:instant_block", len(cfg.InstantBlock) >= 5,
		fmt.Sprintf("%d rules", len(cfg.InstantBlock)))
	check("rules:instant_allow", len(cfg.InstantAllow) >= 5,
		fmt.Sprintf("%d rules", len(cfg.InstantAllow)))

	// 3. Legacy file parses if present.
	legacyPath := defaultLegacyPath()
	if _, err := os.Stat(legacyPath); err == nil {
		al, err := legacy.Load(legacyPath)
		check("legacy:parse", err == nil,
			func() string {
				if err != nil {
					return err.Error()
				}
				return fmt.Sprintf("%d patterns loaded", len(al.Patterns))
			}())
	}

	// 4-7. Corpora — every line in each file must produce the expected
	// verdict under the current deterministic rules. The corpus is
	// embedded in the binary (see internal/corpus) so it works from
	// any cwd and any install location.
	eng := engine.New(cfg, nil)
	for _, c := range []struct {
		label    string
		content  string
		expected string
	}{
		{"adversarial", corpus.Adversarial, "deny"},
		{"allow", corpus.Allow, "allow"},
		{"deny", corpus.Deny, "deny"},
		{"continue", corpus.Continue, "continue"},
	} {
		res := runCorpus(eng, c.label, c.content, c.expected, verbose)
		check("corpus:"+c.label, res.passed == res.total,
			fmt.Sprintf("%d/%d pass", res.passed, res.total))
	}

	fmt.Println()
	if pass {
		fmt.Println("lint: OK")
		return 0
	}
	fmt.Println("lint: FAIL — review the lines marked [FAIL] above")
	return 1
}

type corpusResult struct {
	total  int
	passed int
	fails  []string
}

// runCorpus runs every non-comment, non-empty line from content
// through the engine and asserts the verdict matches expected.
func runCorpus(eng *engine.Engine, label, content, expected string, verbose bool) corpusResult {
	var res corpusResult
	scanner := bufio.NewScanner(strings.NewReader(content))
	scanner.Buffer(make([]byte, 1<<16), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		res.total++
		out := eng.Decide(engine.Input{ToolName: "Bash", Command: line})
		if string(out.Verdict) == expected {
			res.passed++
			if verbose {
				fmt.Printf("  [ok]   %s\n", line)
			}
		} else {
			res.fails = append(res.fails, line+" → "+string(out.Verdict))
			fmt.Printf("  [FAIL] (%s) expected=%s got=%s  %s\n", label, expected, out.Verdict, line)
		}
	}
	return res
}
