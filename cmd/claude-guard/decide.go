package main

import (
	"fmt"
	"os"

	"github.com/RobinUS2/claude-guard/internal/hook"
)

// cmdDecide is the PreToolUse hook entrypoint.
//
// It reads a PreToolUse request from stdin, runs it through the engine,
// and writes a hook response on stdout. It never returns non-zero for
// business-logic reasons — only for its own internal errors (which Claude
// Code ignores as non-blocking per Phase 0 verification). This ensures
// a guard bug can never block the user.
func cmdDecide(args []string) int {
	// Recover from any panic and fall through to "no verdict".
	// A crashing guard must not crash the session.
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "claude-guard: panic: %v\n", r)
			_ = hook.WriteResponse(os.Stdout, hook.Continue())
		}
	}()

	req, err := hook.ReadRequest(os.Stdin)
	if err != nil {
		// Malformed input is a bug somewhere, not a user-facing issue.
		// Log to stderr (Claude will show it), but return Continue so we never block.
		fmt.Fprintf(os.Stderr, "claude-guard: %v\n", err)
		_ = hook.WriteResponse(os.Stdout, hook.Continue())
		return 1 // non-blocking per Phase 0 verification
	}

	// Only act on Bash for v1. Other tools fall through.
	if req.ToolName != "Bash" {
		_ = hook.WriteResponse(os.Stdout, hook.Continue())
		return 0
	}

	// TODO(phase1): dispatch to internal/engine here.
	// For now: always continue (Phase 1 scaffolding stage).
	_ = hook.WriteResponse(os.Stdout, hook.Continue())
	return 0
}
