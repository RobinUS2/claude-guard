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

// cmdTest, cmdDoctor, cmdMigrate, cmdBackup, cmdStats, cmdExplain,
// cmdLint, cmdTrust, cmdReplay, cmdCompare live in their own files.
func cmdEvalPrompt(_ []string) int { return stub("eval-prompt") }
func cmdBench(_ []string) int      { return stub("bench") }
