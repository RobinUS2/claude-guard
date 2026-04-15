// Package engine orchestrates the tier 1-6 decision pipeline.
//
// Tier 1 (BLOCK) runs first, unconditionally. Tier 2 (ALLOW) runs only if
// tier 1 did not match. Tiers 3-5 are stubs in Phase 1 and will be wired
// incrementally.
//
// The engine is stateless and safe for concurrent use. It owns a Config
// and a Logger; all other state (cache, LLM state) will be added later as
// plug-points.
package engine

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/RobinUS2/claude-guard/internal/config"
	"github.com/RobinUS2/claude-guard/internal/llm"
	"github.com/RobinUS2/claude-guard/internal/llm/breaker"
	clog "github.com/RobinUS2/claude-guard/internal/log"
	"github.com/RobinUS2/claude-guard/internal/redact"
	"github.com/RobinUS2/claude-guard/internal/rules"
	"github.com/RobinUS2/claude-guard/internal/shellparse"
	"github.com/RobinUS2/claude-guard/internal/version"
)

// Tier 4 (LLM) hard timeout. Per-call timeout. Anything longer should
// not block a synchronous hook — long retries belong in the cross-
// invocation breaker, not in the hook path.
const llmDeadline = 3 * time.Second

// Verdict is the engine's final output. Matches the three Claude Code
// outcomes: continue (fall through), allow (auto-approve), deny (block).
type Verdict string

const (
	Continue Verdict = "continue"
	Allow    Verdict = "allow"
	Deny     Verdict = "deny"
)

// Input carries the data the engine needs to decide.
type Input struct {
	ToolName    string
	Command     string
	Description string // Claude's own short description of intent
	CWD         string
	SessionID   string
	ToolUseID   string
	AgentID     string
	AgentType   string
}

// Output is the engine's decision plus metadata for logging/debugging.
type Output struct {
	Verdict  Verdict
	Tier     string // "instant_block", "instant_allow", "cache", "llm", "legacy", "default", "parse_error"
	Rule     string // matched rule name, if any
	Reason   string // human-readable reason
	Latency  time.Duration

	// Shadow-mode snapshot of each tier's (hypothetical) verdict.
	// Populated even when a tier doesn't fire, so shadow mode can be
	// analysed post-hoc.
	Shadow ShadowTrace
}

// ShadowTrace captures what each tier would say in isolation.
type ShadowTrace struct {
	Tier1Rule   string // block rule that matched, if any
	Tier1Reason string
	Tier2Rule   string // allow rule that matched, if any
	Tier4LLM    string // llm verdict ("safe"/"unsafe"/"unsure"), or "" if not called
}

// Engine evaluates Bash commands against the configured rules.
type Engine struct {
	cfg      *config.Config
	log      *clog.DecisionLogger
	app      *slog.Logger
	redactor *redact.Redactor
	llm      llm.Classifier
	breaker  *breaker.Breaker
}

// Options configures the engine. All fields are optional — nil
// dependencies disable the corresponding tier.
type Options struct {
	Config      *config.Config
	DecisionLog *clog.DecisionLogger
	AppLog      *slog.Logger
	Redactor    *redact.Redactor
	LLM         llm.Classifier
	Breaker     *breaker.Breaker
}

// New creates an engine with the given config and logger.
// Logger may be nil — engine then skips logging.
func New(cfg *config.Config, logger *clog.DecisionLogger) *Engine {
	return &Engine{cfg: cfg, log: logger}
}

// NewWithOptions creates an engine wired with optional LLM tier
// components. Pass nil for any field to disable that piece.
func NewWithOptions(opts Options) *Engine {
	e := &Engine{
		cfg:      opts.Config,
		log:      opts.DecisionLog,
		app:      opts.AppLog,
		redactor: opts.Redactor,
		llm:      opts.LLM,
		breaker:  opts.Breaker,
	}
	if e.cfg == nil {
		e.cfg = config.Default()
	}
	return e
}

// Decide runs the tier pipeline for a single input.
//
// Only ToolName == "Bash" is processed; everything else returns Continue.
// Parse failures return Continue (can't make structural decisions without
// an AST — fall through to safer tiers or user prompt).
//
// This method is the hot path — it must be fast (<10ms for deterministic
// tiers) and never panic.
func (e *Engine) Decide(in Input) Output {
	start := time.Now()
	out := Output{Verdict: Continue, Tier: "default"}

	if in.ToolName != "Bash" {
		out.Latency = time.Since(start)
		e.record(in, out)
		return out
	}

	parsed, err := shellparse.Parse(in.Command)
	if err != nil {
		// Malformed shell — can't make AST decisions. Fall through.
		out.Tier = "parse_error"
		out.Reason = fmt.Sprintf("shell parse: %v", err)
		out.Latency = time.Since(start)
		e.record(in, out)
		return out
	}

	// Tier 1: BLOCK (first, unconditional)
	for _, r := range e.cfg.InstantBlock {
		if v, reason := r.Eval(parsed); v == rules.Match {
			out.Shadow.Tier1Rule = r.Name()
			out.Shadow.Tier1Reason = reason
			if !e.cfg.ShadowMode {
				out.Verdict = Deny
				out.Tier = "instant_block"
				out.Rule = r.Name()
				out.Reason = reason
				out.Latency = time.Since(start)
				e.record(in, out)
				return out
			}
			// Shadow mode: log the would-have-blocked and continue to tier 2.
			break
		}
	}

	// Tier 2: ALLOW (only if tier 1 did NOT match — in shadow mode we still
	// run tier 2 to populate the shadow trace).
	for _, r := range e.cfg.InstantAllow {
		if v, reason := r.Eval(parsed); v == rules.Match {
			out.Shadow.Tier2Rule = r.Name()
			// In enforce mode: only allow if tier 1 didn't match.
			// In shadow mode: tier 1 block wins in real mode too, but since we
			// already broke out of the tier 1 loop above in shadow mode, we
			// only reach here if tier 1 had no match (correct behavior).
			if !e.cfg.ShadowMode && out.Shadow.Tier1Rule == "" {
				out.Verdict = Allow
				out.Tier = "instant_allow"
				out.Rule = r.Name()
				out.Reason = reason
				out.Latency = time.Since(start)
				e.record(in, out)
				return out
			}
			break
		}
	}

	// Tier 3: cache — stub in Phase 1 (will be added in a follow-up)

	// Tier 4: LLM classifier (approve-only).
	if e.llm != nil {
		llmVerdict := e.runLLMTier(in)
		out.Shadow.Tier4LLM = llmVerdict.shadow
		if !e.cfg.ShadowMode && llmVerdict.allow {
			out.Verdict = Allow
			out.Tier = "llm"
			out.Rule = e.llm.Provider() + "/" + e.llm.Model()
			out.Reason = llmVerdict.reason
			out.Latency = time.Since(start)
			e.record(in, out)
			return out
		}
	}

	// Tier 5: legacy allow list — stub in Phase 1

	// Tier 6: default (no verdict, fall through to user prompt).
	out.Latency = time.Since(start)
	e.record(in, out)
	return out
}

// llmCallResult is the engine-internal summary of a Tier 4 attempt.
type llmCallResult struct {
	allow  bool   // true only when LLM said "safe"
	shadow string // "safe", "unsafe", "unsure", "skipped:<reason>", or "error"
	reason string // human-readable reason for the decision
}

// runLLMTier handles redaction, circuit breaker check, and the actual
// LLM call. Always returns; never panics. All errors are logged to the
// app log and the engine falls through.
func (e *Engine) runLLMTier(in Input) llmCallResult {
	// Pre-LLM redaction (tier 0).
	if e.redactor != nil {
		res := e.redactor.Scan(in.Command)
		if res.Decision == redact.Skip {
			e.appLog().Info("llm_skipped",
				"reason", "redact_skip",
				"pattern", res.SkipReason,
				"tool_use_id", in.ToolUseID,
			)
			return llmCallResult{shadow: "skipped:" + res.SkipReason}
		}
		// Use the redacted command for the LLM call.
		in.Command = res.Redacted
	}

	// Circuit breaker check.
	if e.breaker != nil {
		permitted, deadline, why := e.breaker.Check()
		if !permitted {
			e.appLog().Info("llm_skipped",
				"reason", "circuit_open",
				"deadline", deadline,
				"detail", why,
				"tool_use_id", in.ToolUseID,
			)
			return llmCallResult{shadow: "skipped:circuit_open"}
		}
	}

	// Actual LLM call.
	ctx, cancel := context.WithTimeout(context.Background(), llmDeadline)
	defer cancel()
	dec, err := e.llm.Classify(ctx, llm.ClassifyInput{
		Command:     in.Command,
		Description: in.Description,
		CWD:         in.CWD,
	})
	if err != nil {
		// Record failure for the breaker; log to app.
		var newState any
		if e.breaker != nil {
			s, _ := e.breaker.RecordFailure(err)
			if s != nil {
				newState = s
			}
		}
		e.appLog().Warn("llm_error",
			"err", err.Error(),
			"provider", e.llm.Provider(),
			"model", e.llm.Model(),
			"breaker_state", newState,
			"tool_use_id", in.ToolUseID,
		)
		return llmCallResult{shadow: "error"}
	}

	// Success — close the circuit if it was tracking failures.
	if e.breaker != nil {
		_ = e.breaker.RecordSuccess()
	}

	switch dec.Verdict {
	case llm.VerdictSafe:
		return llmCallResult{
			allow:  true,
			shadow: "safe",
			reason: dec.Reason,
		}
	case llm.VerdictUnsafe:
		// LLM is approve-only — fall through. Log the would-have-been block.
		e.appLog().Info("llm_unsafe_fallthrough",
			"reason", dec.Reason,
			"category", dec.Category,
			"tool_use_id", in.ToolUseID,
		)
		return llmCallResult{shadow: "unsafe", reason: dec.Reason}
	default:
		return llmCallResult{shadow: "unsure", reason: dec.Reason}
	}
}

// appLog returns the app-level logger or a no-op if not configured.
func (e *Engine) appLog() *slog.Logger {
	if e.app != nil {
		return e.app
	}
	return slog.New(slog.DiscardHandler)
}

// record appends a log entry for this decision if a logger is attached.
func (e *Engine) record(in Input, out Output) {
	if e.log == nil {
		return
	}
	rec := clog.DecisionRecord{
		GuardVersion: version.Version,
		SessionID:    in.SessionID,
		ToolUseID:    in.ToolUseID,
		AgentID:      in.AgentID,
		AgentType:    in.AgentType,
		CWD:          in.CWD,
		ToolName:     in.ToolName,
		Command:      in.Command,
		Description:  in.Description,
		Tier:         out.Tier,
		Verdict:      string(out.Verdict),
		Rule:         out.Rule,
		Reason:       out.Reason,
		LatencyUS:    out.Latency.Microseconds(),
	}
	if out.Shadow.Tier1Rule != "" || out.Shadow.Tier2Rule != "" || out.Shadow.Tier4LLM != "" {
		rec.Shadow = &clog.ShadowFields{
			Tier1Block: out.Shadow.Tier1Rule,
			Tier2Allow: out.Shadow.Tier2Rule,
			Tier4LLM:   out.Shadow.Tier4LLM,
		}
	}
	e.log.Decision(rec)
}
