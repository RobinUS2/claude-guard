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
	"fmt"
	"time"

	"github.com/RobinUS2/claude-guard/internal/config"
	clog "github.com/RobinUS2/claude-guard/internal/log"
	"github.com/RobinUS2/claude-guard/internal/rules"
	"github.com/RobinUS2/claude-guard/internal/shellparse"
	"github.com/RobinUS2/claude-guard/internal/version"
)

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
	cfg *config.Config
	log *clog.Logger
}

// New creates an engine with the given config and logger.
// Logger may be nil — engine then skips logging.
func New(cfg *config.Config, logger *clog.Logger) *Engine {
	return &Engine{cfg: cfg, log: logger}
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

	// Tier 3: cache — stub in Phase 1
	// Tier 4: LLM — stub in Phase 1
	// Tier 5: legacy allow list — stub in Phase 1

	// Tier 6: default (no verdict, fall through to user prompt).
	out.Latency = time.Since(start)
	e.record(in, out)
	return out
}

// record appends a log entry for this decision if a logger is attached.
func (e *Engine) record(in Input, out Output) {
	if e.log == nil {
		return
	}
	rec := clog.Record{
		GuardVersion: version.Version,
		SessionID:   in.SessionID,
		ToolUseID:   in.ToolUseID,
		AgentID:     in.AgentID,
		AgentType:   in.AgentType,
		CWD:         in.CWD,
		ToolName:    in.ToolName,
		Command:     in.Command,
		Description: in.Description,
		Tier:        out.Tier,
		Verdict:     string(out.Verdict),
		Rule:        out.Rule,
		Reason:      out.Reason,
		LatencyUS:   out.Latency.Microseconds(),
		Shadow: &clog.ShadowRecord{
			Tier1Block: out.Shadow.Tier1Rule,
			Tier2Allow: out.Shadow.Tier2Rule,
			Tier4LLM:   out.Shadow.Tier4LLM,
		},
	}
	// Zero out shadow record if all fields empty (cleaner logs).
	if rec.Shadow.Tier1Block == "" && rec.Shadow.Tier2Allow == "" && rec.Shadow.Tier4LLM == "" && rec.Shadow.Tier5Legacy == "" {
		rec.Shadow = nil
	}
	_ = e.log.Write(rec)
}
