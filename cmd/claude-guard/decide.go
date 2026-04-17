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

	// Build the engine input from the parsed tool_input.
	in := engine.Input{
		ToolName:  req.ToolName,
		CWD:       req.CWD,
		SessionID: req.SessionID,
		ToolUseID: req.ToolUseID,
		AgentID:   req.AgentID,
		AgentType: req.AgentType,
	}
	switch req.ToolName {
	case "Bash":
		bi, err := req.Bash()
		if err != nil {
			fmt.Fprintf(os.Stderr, "claude-guard: %v\n", err)
			_ = hook.WriteResponse(os.Stdout, hook.Continue())
			return 1
		}
		in.Command = bi.Command
		in.Description = bi.Description
	case "WebFetch":
		wf, err := req.WebFetch()
		if err != nil {
			fmt.Fprintf(os.Stderr, "claude-guard: webfetch parse: %v\n", err)
			_ = hook.WriteResponse(os.Stdout, hook.Continue())
			return 1
		}
		in.URL = wf.URL
		in.Command = "WebFetch: " + wf.URL
		in.Description = wf.Prompt
	case "WebSearch":
		ws, err := req.WebSearch()
		if err != nil {
			fmt.Fprintf(os.Stderr, "claude-guard: websearch parse: %v\n", err)
			_ = hook.WriteResponse(os.Stdout, hook.Continue())
			return 1
		}
		in.Query = ws.Query
		in.Command = "WebSearch: " + ws.Query
	case "Read":
		ri, err := req.Read()
		if err != nil {
			fmt.Fprintf(os.Stderr, "claude-guard: read parse: %v\n", err)
			_ = hook.WriteResponse(os.Stdout, hook.Continue())
			return 1
		}
		in.FilePath = ri.FilePath
		in.Command = "Read: " + ri.FilePath
	case "Write":
		wi, err := req.Write()
		if err != nil {
			fmt.Fprintf(os.Stderr, "claude-guard: write parse: %v\n", err)
			_ = hook.WriteResponse(os.Stdout, hook.Continue())
			return 1
		}
		in.FilePath = wi.FilePath
		in.IsWrite = true
		in.Content = wi.Content
		in.Command = "Write: " + wi.FilePath
	case "Edit":
		ei, err := req.Edit()
		if err != nil {
			fmt.Fprintf(os.Stderr, "claude-guard: edit parse: %v\n", err)
			_ = hook.WriteResponse(os.Stdout, hook.Continue())
			return 1
		}
		in.FilePath = ei.FilePath
		in.IsWrite = true
		in.Command = "Edit: " + ei.FilePath
	default:
		// MCP and unknown tools — pass serialized tool_input.
		raw := string(req.ToolInput)
		const maxMCPLen = 2048
		if len(raw) > maxMCPLen {
			raw = raw[:maxMCPLen]
		}
		in.Command = "MCP tool call (not bash) " + req.ToolName + ": " + raw
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
	out := eng.Decide(in)

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

	// Self-review stale-check: if the last review was >24h ago and
	// review is enabled, spawn `claude-guard review --apply` as a
	// separate OS process. Runs independently of this hook's
	// lifetime (CTO review CRIT-2: Opus calls take 30-60s, exceeds
	// the AwaitVerifications cap).
	maybeSpawnReview()

	return 0
}

// maybeSpawnReview checks whether enough time has elapsed since the
// last self-review and spawns a background review process if so.
// No-op when the interval hasn't elapsed or config is disabled.
func maybeSpawnReview() {
	tsPath := filepath.Join(os.Getenv("HOME"), ".cache", "claude-guard", "last-review.txt")
	data, err := os.ReadFile(tsPath)
	if err == nil {
		if ts, err := time.Parse(time.RFC3339, string(data)); err == nil {
			if time.Since(ts) < 24*time.Hour {
				return // recently reviewed
			}
		}
	}
	// Spawn detached process. Errors are best-effort — a failed
	// spawn just means the review runs on the next invocation.
	exe, err := os.Executable()
	if err != nil {
		return
	}
	// Check if ANTHROPIC_API_KEY is available (review needs Opus).
	if os.Getenv("ANTHROPIC_API_KEY") == "" && os.Getenv("CLAUDE_API_KEY") == "" {
		return
	}
	cmd := execCommand(exe, "review", "--apply")
	cmd.Stdout = nil
	cmd.Stderr = nil
	_ = cmd.Start()
}

// execCommand is a var so tests can stub it out.
var execCommand = defaultExecCommand

func defaultExecCommand(name string, args ...string) *execCmd {
	c := &execCmd{cmd: name, args: args}
	return c
}

// execCmd is a thin wrapper around os/exec.Cmd for testability.
type execCmd struct {
	cmd    string
	args   []string
	Stdout *os.File
	Stderr *os.File
}

func (c *execCmd) Start() error {
	proc := &os.ProcAttr{
		Files: []*os.File{os.Stdin, c.Stdout, c.Stderr},
	}
	p, err := os.StartProcess(c.cmd, append([]string{c.cmd}, c.args...), proc)
	if err != nil {
		return err
	}
	// Detach — don't wait.
	_ = p.Release()
	return nil
}

// pickClassifierAndVerifier returns (fast, verifier). The verifier is
// always from a different provider than the fast classifier — that's
// the whole point of cross-provider verification. Returns (nil, nil)
// if no API keys are available.
func pickClassifierAndVerifier(getenv func(string) string) (llm.Classifier, llm.Classifier) {
	hasAnthropic := false
	anthropicKey := ""
	hasGemini := false
	for _, k := range llm.AnthropicEnvKeys {
		if v := getenv(k); v != "" {
			hasAnthropic = true
			anthropicKey = v
			break
		}
	}
	// Token-vault fallback: if no env var is set, try resolving via
	// token-vault. This lets users store the key encrypted without
	// exporting to the shell environment.
	if !hasAnthropic {
		if key := llm.LookupTokenVaultAnthropic(); key != "" {
			hasAnthropic = true
			anthropicKey = key
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
		ver := llm.NewAnthropic(anthropicKey, VerifierAnthropicModel)
		return fast, ver
	case hasAnthropic:
		// Only Anthropic — fast=Haiku, verifier=Sonnet (same provider,
		// stronger model — weaker signal but still useful).
		fast := llm.AutoSelect("anthropic", getenv)
		ver := llm.NewAnthropic(anthropicKey, VerifierAnthropicModel)
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
