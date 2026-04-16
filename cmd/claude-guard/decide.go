package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/RobinUS2/claude-guard/internal/cache"
	"github.com/RobinUS2/claude-guard/internal/config"
	"github.com/RobinUS2/claude-guard/internal/engine"
	"github.com/RobinUS2/claude-guard/internal/hook"
	"github.com/RobinUS2/claude-guard/internal/legacy"
	"github.com/RobinUS2/claude-guard/internal/llm"
	"github.com/RobinUS2/claude-guard/internal/projectconfig"
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
	// + cache + verifier. All five are optional — if any returns nil,
	// that piece is disabled and the engine simply skips it.
	//
	// Verifier is the cross-provider second opinion: when both Anthropic
	// and Gemini keys are present, the fast classifier and the verifier
	// come from different providers. Different model architectures catch
	// different failure modes, and using two providers also defends
	// against prompt injection attacks targeted at one provider's prompt
	// format.
	classifier, verifier := pickClassifierAndVerifier(os.Getenv)

	cacheRoot := filepath.Join(os.Getenv("HOME"), ".cache", "claude-guard")
	var br *breaker.Breaker
	var cch *cache.Cache
	if classifier != nil {
		br = breaker.New(filepath.Join(cacheRoot, "llm-circuit.json"))
		cch = cache.New(filepath.Join(cacheRoot, "verdicts"))
	}
	redactor := redact.New(nil, nil)

	// Tier 5: legacy allow list (migrated from settings.json). Missing
	// file is fine — it just means tier 5 is empty.
	legacyList, _ := legacy.Load(defaultLegacyPath())

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
		Config:              cfg,
		DecisionLog:         decisionLog,
		AppLog:              appLogger,
		Redactor:            redactor,
		LLM:                 classifier,
		Verifier:            verifier,
		Breaker:             br,
		Cache:               cch,
		Legacy:              legacyList,
		ProjectConfigLoader: projectconfig.Load,
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

	// Close stdout so Claude Code unblocks immediately. After this point
	// any background work (verifier goroutines) keeps running, but the
	// user is no longer waiting on us.
	_ = os.Stdout.Close()

	// Wait for any in-flight background goroutines to finish (or 50s
	// max). Two kinds of work may be pending: (1) verifier goroutines
	// (15s budget each, ~1-3s typical), and (2) async classifier
	// goroutines spawned when the tier-4 sync deadline fires — those
	// run under llmAsyncDeadline (30s) and may then spawn a verifier.
	// Cap = llmAsyncDeadline (30s) + verifierDeadline (15s) + slack (5s).
	eng.AwaitVerifications(50 * time.Second)
	return 0
}

// pickClassifierAndVerifier returns (fast, verifier). The verifier is
// always from a different provider than the fast classifier — that's
// the whole point of cross-provider verification. Returns (nil, nil)
// if no API keys are available.
func pickClassifierAndVerifier(getenv func(string) string) (llm.Classifier, llm.Classifier) {
	hasAnthropic := false
	hasGemini := false
	for _, k := range llm.AnthropicEnvKeys {
		if getenv(k) != "" {
			hasAnthropic = true
			break
		}
	}
	for _, k := range llm.GeminiEnvKeys {
		if getenv(k) != "" {
			hasGemini = true
			break
		}
	}

	switch {
	case hasAnthropic && hasGemini:
		// Both providers — Gemini Flash is fastest, Anthropic Sonnet is
		// the stronger verifier. Cross-provider, fastest-first.
		fast := llm.AutoSelect("gemini", getenv)
		ver := llm.NewAnthropic(firstNonEmpty(getenv, llm.AnthropicEnvKeys), VerifierAnthropicModel)
		return fast, ver
	case hasAnthropic:
		// Only Anthropic — fast=Haiku, verifier=Sonnet (same provider,
		// stronger model — weaker signal but still useful).
		fast := llm.AutoSelect("anthropic", getenv)
		ver := llm.NewAnthropic(firstNonEmpty(getenv, llm.AnthropicEnvKeys), VerifierAnthropicModel)
		return fast, ver
	case hasGemini:
		// Only Gemini — fast=Flash, verifier=Pro.
		fast := llm.AutoSelect("gemini", getenv)
		ver := llm.NewGemini(firstNonEmpty(getenv, llm.GeminiEnvKeys), VerifierGeminiModel)
		return fast, ver
	default:
		return nil, nil
	}
}

// VerifierAnthropicModel is the strong Anthropic model used as a
// background verifier. Sonnet 4.5 strikes the right balance: stronger
// than Haiku but not as expensive or slow as Opus.
const VerifierAnthropicModel = "claude-sonnet-4-5"

// VerifierGeminiModel is the strong Gemini model used as a verifier.
const VerifierGeminiModel = "gemini-2.5-pro"

func firstNonEmpty(getenv func(string) string, keys []string) string {
	for _, k := range keys {
		if v := getenv(k); v != "" {
			return v
		}
	}
	return ""
}
