package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/RobinUS2/claude-guard/internal/cache"
	"github.com/RobinUS2/claude-guard/internal/config"
	"github.com/RobinUS2/claude-guard/internal/engine"
	"github.com/RobinUS2/claude-guard/internal/hook"
	"github.com/RobinUS2/claude-guard/internal/llm"
	"github.com/RobinUS2/claude-guard/internal/llm/breaker"
	clog "github.com/RobinUS2/claude-guard/internal/log"
	"github.com/RobinUS2/claude-guard/internal/redact"
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

	// Resolve log dir + open the decision logger and the app logger.
	logDir := cfg.Log.Dir
	if logDir == "" {
		logDir = config.DefaultLogDir()
	}
	paths := clog.DefaultPaths(logDir)

	var decisionLog *clog.DecisionLogger
	if lg, err := clog.OpenDecisionLogger(paths, cfg.Log.MaxSizeMB, cfg.Log.KeepFiles); err != nil {
		fmt.Fprintf(os.Stderr, "claude-guard: open decision log: %v\n", err)
	} else {
		decisionLog = lg
		defer decisionLog.Close()
	}

	appLogger, appCloser, appErr := clog.OpenAppLogger(paths.App, cfg.Log.MaxSizeMB, cfg.Log.KeepFiles)
	if appErr != nil {
		fmt.Fprintf(os.Stderr, "claude-guard: open app log: %v\n", appErr)
	} else if appCloser != nil {
		defer appCloser.Close()
	}

	// LLM tier setup: pick a provider from env, set up redactor + breaker
	// + cache. All four are optional — if any returns nil, that piece is
	// disabled and the engine simply skips it.
	classifier := llm.AutoSelect("anthropic", os.Getenv) // prefer Anthropic; fall back to Gemini
	cacheRoot := filepath.Join(os.Getenv("HOME"), ".cache", "claude-guard")
	var br *breaker.Breaker
	var cch *cache.Cache
	if classifier != nil {
		br = breaker.New(filepath.Join(cacheRoot, "llm-circuit.json"))
		cch = cache.New(filepath.Join(cacheRoot, "verdicts"))
	}
	redactor := redact.New(nil, nil)

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

	// Run the engine with the full set of components.
	eng := engine.NewWithOptions(engine.Options{
		Config:      cfg,
		DecisionLog: decisionLog,
		AppLog:      appLogger,
		Redactor:    redactor,
		LLM:         classifier,
		Breaker:     br,
		Cache:       cch,
	})
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
