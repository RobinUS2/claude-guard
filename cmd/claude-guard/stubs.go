package main

import (
	"fmt"
	"os"
)

// Subcommand stubs for Phase 1. Each will be filled in as its dependencies
// come online. They return exit code 64 (EX_USAGE) to signal "not yet
// implemented" clearly without pretending success.

func stub(name string) int {
	fmt.Fprintf(os.Stderr, "claude-guard: %q is not yet implemented (Phase 1 scaffolding)\n", name)
	return 64
}

// cmdTest, cmdDoctor, cmdMigrate live in their own files now.
func cmdExplain(_ []string) int    { return stub("explain") }
func cmdReplay(_ []string) int     { return stub("replay") }
func cmdStats(_ []string) int      { return stub("stats") }
func cmdLint(_ []string) int       { return stub("lint") }
func cmdEvalPrompt(_ []string) int { return stub("eval-prompt") }
func cmdBench(_ []string) int      { return stub("bench") }
