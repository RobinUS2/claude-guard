package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/RobinUS2/claude-guard/internal/config"
	"github.com/RobinUS2/claude-guard/internal/engine"
	"github.com/RobinUS2/claude-guard/internal/legacy"
)

// cmdTest dry-runs a command through the engine and prints a trace of
// what each tier said. Useful when adding or debugging a rule.
//
//	claude-guard test "git status"
//	claude-guard test --shadow "rm -rf /"
//	claude-guard test --enforce "rm -rf /"    (default)
func cmdTest(args []string) int {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var shadow bool
	var enforce bool
	var cwd string
	fs.BoolVar(&shadow, "shadow", false, "simulate shadow mode")
	fs.BoolVar(&enforce, "enforce", false, "simulate enforce mode (default)")
	fs.StringVar(&cwd, "cwd", "", "simulated current working directory")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "usage: claude-guard test [--shadow|--enforce] [--cwd DIR] <command>")
		return 2
	}
	command := strings.Join(rest, " ")

	result := config.Load("")
	if result.Warning != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", result.Warning)
	}
	cfg := result.Config
	// --enforce wins over --shadow; if neither, default to enforce for easier testing.
	switch {
	case enforce:
		cfg.ShadowMode = false
	case shadow:
		cfg.ShadowMode = true
	default:
		cfg.ShadowMode = false
	}

	// Load tier 5 (legacy) so dry-runs reflect what the real hook
	// would do. Missing file is fine.
	legacyList, _ := legacy.Load(defaultLegacyPath())

	eng := engine.NewWithOptions(engine.Options{
		Config: cfg,
		Legacy: legacyList,
	})
	out := eng.Decide(engine.Input{
		ToolName: "Bash",
		Command:  command,
		CWD:      cwd,
	})

	mode := "enforce"
	if cfg.ShadowMode {
		mode = "shadow"
	}
	fmt.Printf("command: %s\n", command)
	fmt.Printf("mode:    %s\n", mode)
	fmt.Printf("verdict: %s\n", out.Verdict)
	fmt.Printf("tier:    %s\n", out.Tier)
	if out.Rule != "" {
		fmt.Printf("rule:    %s\n", out.Rule)
	}
	if out.Reason != "" {
		fmt.Printf("reason:  %s\n", out.Reason)
	}
	fmt.Printf("latency: %s\n", out.Latency)
	if out.Shadow.Tier1Rule != "" || out.Shadow.Tier2Rule != "" {
		fmt.Println("shadow trace:")
		if out.Shadow.Tier1Rule != "" {
			fmt.Printf("  tier1 block: %s (%s)\n", out.Shadow.Tier1Rule, out.Shadow.Tier1Reason)
		}
		if out.Shadow.Tier2Rule != "" {
			fmt.Printf("  tier2 allow: %s\n", out.Shadow.Tier2Rule)
		}
	}

	// Exit code reflects the verdict so shell scripts can branch on it.
	switch out.Verdict {
	case engine.Allow:
		return 0
	case engine.Deny:
		return 1
	default:
		return 2
	}
}
