package main

import (
	"fmt"
	"os"

	"github.com/RobinUS2/claude-guard/internal/config"
	"github.com/RobinUS2/claude-guard/internal/engine"
	"github.com/RobinUS2/claude-guard/internal/hook"
	clog "github.com/RobinUS2/claude-guard/internal/log"
)

// cmdDecide is the PreToolUse hook entrypoint.
//
// Must NEVER block the user from a crash, a config bug, or a logging bug.
// Every error path returns Continue (empty JSON response) and exits with
// code 1 for telemetry — exit 1 is non-blocking per Phase 0 verification.
func cmdDecide(_ []string) int {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "claude-guard: panic: %v\n", r)
			_ = hook.WriteResponse(os.Stdout, hook.Continue())
		}
	}()

	// Load config first — if it fails, we still get defaults with tier 1/2.
	result := config.Load("")
	if result.Warning != nil {
		fmt.Fprintf(os.Stderr, "claude-guard: %v\n", result.Warning)
	}
	cfg := result.Config

	// Open logger (best-effort). Nil logger is OK — engine handles it.
	var logger *clog.Logger
	if cfg.Log.Path != "" {
		lg, err := clog.Open(cfg.Log.Path, cfg.Log.MaxSizeBytes, cfg.Log.KeepFiles)
		if err != nil {
			fmt.Fprintf(os.Stderr, "claude-guard: open log: %v\n", err)
		} else {
			logger = lg
		}
	}

	// Parse the PreToolUse payload from stdin.
	req, err := hook.ReadRequest(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "claude-guard: %v\n", err)
		_ = hook.WriteResponse(os.Stdout, hook.Continue())
		return 1
	}

	// Only act on Bash for v1.
	if req.ToolName != "Bash" {
		_ = hook.WriteResponse(os.Stdout, hook.Continue())
		return 0
	}

	// Extract the Bash command + description.
	bi, err := req.Bash()
	if err != nil {
		fmt.Fprintf(os.Stderr, "claude-guard: %v\n", err)
		_ = hook.WriteResponse(os.Stdout, hook.Continue())
		return 1
	}

	// Run the engine.
	eng := engine.New(cfg, logger)
	out := eng.Decide(engine.Input{
		ToolName:    req.ToolName,
		Command:     bi.Command,
		Description: bi.Description,
		CWD:         req.CWD,
		SessionID:   req.SessionID,
		ToolUseID:   req.ToolUseID,
		AgentID:     req.AgentID,
		AgentType:   req.AgentType,
	})

	// Translate engine verdict to hook response.
	var resp hook.Response
	switch out.Verdict {
	case engine.Allow:
		resp = hook.Allow(fmt.Sprintf("tier=%s rule=%s", out.Tier, out.Rule))
	case engine.Deny:
		resp = hook.Deny(fmt.Sprintf("%s (tier=%s rule=%s)", out.Reason, out.Tier, out.Rule))
	default:
		resp = hook.Continue()
	}

	if err := hook.WriteResponse(os.Stdout, resp); err != nil {
		fmt.Fprintf(os.Stderr, "claude-guard: write response: %v\n", err)
		return 1
	}
	return 0
}
