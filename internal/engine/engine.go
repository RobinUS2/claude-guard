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
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/RobinUS2/claude-guard/internal/cache"
	"github.com/RobinUS2/claude-guard/internal/config"
	"github.com/RobinUS2/claude-guard/internal/legacy"
	"github.com/RobinUS2/claude-guard/internal/llm"
	"github.com/RobinUS2/claude-guard/internal/llm/breaker"
	clog "github.com/RobinUS2/claude-guard/internal/log"
	"github.com/RobinUS2/claude-guard/internal/projectctx"
	"github.com/RobinUS2/claude-guard/internal/redact"
	"github.com/RobinUS2/claude-guard/internal/rules"
	"github.com/RobinUS2/claude-guard/internal/shellparse"
	"github.com/RobinUS2/claude-guard/internal/version"
)

// Tier 4 (LLM) hard timeout. Per-call timeout. Anything longer should
// not block a synchronous hook — long retries belong in the cross-
// invocation breaker, not in the hook path. Cache hits bypass this
// entirely (~1ms file read).
//
// 7s is the engine ceiling. The Gemini client itself has a tighter
// 6s budget for fast models so this is mostly a backstop.
const llmDeadline = 7 * time.Second

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
	verifier llm.Classifier // optional cross-provider verifier
	breaker  *breaker.Breaker
	cache    *cache.Cache
	legacy   *legacy.AllowList // tier 5: migrated allow list from settings.json

	// promptVersion + rulesHash feed the cache key. Computed once at
	// engine construction so every Decide call uses the same key shape.
	promptVersion string
	rulesHash     string

	// pendingVerifies tracks goroutines spawned to verify cached entries.
	// AwaitVerifications waits for them — called by decide.go after the
	// hook response has been written to stdout.
	pendingVerifies sync.WaitGroup
}

// Options configures the engine. All fields are optional — nil
// dependencies disable the corresponding tier.
type Options struct {
	Config      *config.Config
	DecisionLog *clog.DecisionLogger
	AppLog      *slog.Logger
	Redactor    *redact.Redactor
	LLM         llm.Classifier
	// Verifier is an optional second classifier that asynchronously
	// reviews cached LLM verdicts. Should be a different provider from
	// LLM for the strongest cross-model signal.
	Verifier llm.Classifier
	Breaker  *breaker.Breaker
	Cache    *cache.Cache
	// Legacy is the migrated allow list from settings.json. Tier 5.
	// Used as a safety net during phase 4 of the rollout — anything
	// previously auto-approved continues to flow through while the
	// smarter tiers warm up.
	Legacy *legacy.AllowList
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
		verifier: opts.Verifier,
		breaker:  opts.Breaker,
		cache:    opts.Cache,
		legacy:   opts.Legacy,
	}
	if e.cfg == nil {
		e.cfg = config.Default()
	}
	// Pre-compute the cache key inputs that don't change per call.
	e.promptVersion = cache.HashString(llm.DefaultSystemPrompt())
	e.rulesHash = computeRulesHash(e.cfg)
	return e
}

// AwaitVerifications blocks until all background verifier goroutines
// have finished, or the deadline is reached. The hook entrypoint calls
// this AFTER closing stdout (so the user is already unblocked) and
// BEFORE exiting the process. Returns true on clean completion, false
// on deadline timeout.
func (e *Engine) AwaitVerifications(deadline time.Duration) bool {
	if deadline <= 0 {
		e.pendingVerifies.Wait()
		return true
	}
	done := make(chan struct{})
	go func() {
		e.pendingVerifies.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(deadline):
		return false
	}
}

// gitBranchOf returns a coarse branch identity for cache key purposes.
// It does NOT exec `git` — that would be too slow on the hot path
// (~10ms per call) and the answer would be wrong inside subshells anyway.
// Instead we read .git/HEAD directly, walking up from cwd until we find
// one. Returns "" if there is no git repo, "DETACHED" for detached HEAD,
// or the bare branch name (e.g. "main", "feature-x").
//
// The intent is "did we move to a meaningfully different branch?", not
// "what is the exact ref?" — so categorising main/master/production into
// a single bucket would be a future optimisation if we see cache thrash
// during git bisect sessions.
func gitBranchOf(cwd string) string {
	if cwd == "" {
		return ""
	}
	dir := cwd
	for i := 0; i < 32; i++ { // bounded ascent — never walk past root
		head := filepath.Join(dir, ".git", "HEAD")
		if data, err := os.ReadFile(head); err == nil {
			s := strings.TrimSpace(string(data))
			if strings.HasPrefix(s, "ref: refs/heads/") {
				return strings.TrimPrefix(s, "ref: refs/heads/")
			}
			if len(s) == 40 || len(s) == 64 {
				return "DETACHED"
			}
			return s
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
	return ""
}

// computeRulesHash returns a stable hash of the active rule set. Cached
// LLM verdicts are invalidated when this changes — a rule update means
// the engine's behavior for the same command may differ.
func computeRulesHash(cfg *config.Config) string {
	var names []string
	for _, r := range cfg.InstantBlock {
		names = append(names, "block:"+r.Name())
	}
	for _, r := range cfg.InstantAllow {
		names = append(names, "allow:"+r.Name())
	}
	return cache.HashStrings(names)
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

	// Tier 3: cache lookup (only when there's an LLM to back it — caching
	// deterministic verdicts adds latency for no gain since they're already
	// sub-millisecond).
	//
	// We try the global cache key first, then the project-scoped key. A
	// global hit means "this command is safe in any cwd" and bypasses
	// the LLM regardless of where you are. A project hit only matches
	// the same cwd + branch.
	keyInputs := cache.KeyInputs{
		Tool:          in.ToolName,
		Command:       in.Command,
		CWD:           in.CWD,
		GitBranch:     gitBranchOf(in.CWD),
		PromptVersion: e.promptVersion,
		RulesHash:     e.rulesHash,
	}
	var globalKey, projectKey string
	if e.cache != nil && e.llm != nil {
		globalKey = cache.GlobalKey(keyInputs)
		projectKey = cache.Key(keyInputs)

		for _, attempt := range []struct {
			key   string
			scope string
		}{
			{globalKey, "global"},
			{projectKey, "project"},
		} {
			entry, hit := e.cache.Get(attempt.key)
			if !hit {
				continue
			}
			eff := entry.EffectiveVerdict()
			suffix := attempt.scope + ":" + string(eff)
			if entry.Disagreement {
				suffix = attempt.scope + ":verifier-deny:" + string(eff)
			} else if entry.Verified {
				suffix = attempt.scope + ":verified:" + string(eff)
			}
			out.Shadow.Tier4LLM = "cache:" + suffix

			if !e.cfg.ShadowMode {
				switch eff {
				case cache.VerdictAllow:
					out.Verdict = Allow
					out.Tier = "cache"
					out.Rule = entry.Tier + "/" + entry.Provider
					out.Reason = entry.Reason
					out.Latency = time.Since(start)
					e.record(in, out)
					return out
				case cache.VerdictDeny:
					// Verifier disagreement → block.
					out.Verdict = Deny
					out.Tier = "cache"
					out.Rule = "verifier:" + entry.VerifierProvider + "/" + entry.VerifierModel
					out.Reason = "verified by " + entry.VerifierProvider + " (disagreement with original): " + entry.VerifierReason
					out.Latency = time.Since(start)
					e.record(in, out)
					return out
				}
			}
			// Shadow mode or non-actionable verdict.
			out.Latency = time.Since(start)
			e.record(in, out)
			return out
		}
	}

	// Tier 4: LLM classifier (approve-only).
	if e.llm != nil {
		llmVerdict := e.runLLMTier(in)
		out.Shadow.Tier4LLM = llmVerdict.shadow
		// Cache safe verdicts so the next identical command is instant.
		// The cache key is chosen by the LLM-decided scope.
		if e.cache != nil && llmVerdict.allow {
			storeKey := projectKey
			scopeStr := "project"
			if llmVerdict.scope == llm.ScopeGlobal {
				storeKey = globalKey
				scopeStr = "global"
			}
			_ = e.cache.Put(storeKey, cache.Entry{
				Verdict:  cache.VerdictAllow,
				Reason:   llmVerdict.reason,
				Tier:     "llm",
				Provider: e.llm.Provider(),
				Model:    e.llm.Model(),
			}, 90*24*time.Hour)
			out.Shadow.Tier4LLM = "safe:" + scopeStr
			// Spawn the async verifier (cross-provider second opinion).
			e.spawnVerification(storeKey, in)
		}
		// Always populate Reason and Rule from the LLM result so the
		// decision log has the WHY, even on fall-through.
		if llmVerdict.reason != "" {
			out.Reason = llmVerdict.reason
		}
		if e.llm != nil {
			out.Rule = e.llm.Provider() + "/" + e.llm.Model()
		}
		if !e.cfg.ShadowMode && llmVerdict.allow {
			out.Verdict = Allow
			out.Tier = "llm"
			out.Latency = time.Since(start)
			e.record(in, out)
			return out
		}
	}

	// Tier 5: legacy allow list (migrated from settings.json).
	// Last-resort allow before falling through to the user prompt.
	if e.legacy != nil {
		if match := e.legacy.Match(in.Command); match != nil {
			out.Shadow.Tier1Rule = out.Shadow.Tier1Rule // unchanged
			if !e.cfg.ShadowMode {
				out.Verdict = Allow
				out.Tier = "legacy"
				out.Rule = match.Source
				out.Reason = "matched legacy allow pattern: " + match.Prefix
				out.Latency = time.Since(start)
				e.record(in, out)
				return out
			}
		}
	}

	// Tier 6: default (no verdict, fall through to user prompt).
	out.Latency = time.Since(start)
	e.record(in, out)
	return out
}

// llmCallResult is the engine-internal summary of a Tier 4 attempt.
type llmCallResult struct {
	allow  bool      // true only when LLM said "safe"
	shadow string    // "safe", "unsafe", "unsure", "skipped:<reason>", or "error"
	reason string    // human-readable reason for the decision
	scope  llm.Scope // global vs project — used for cache key choice
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

	// Actual LLM call. Pass project context so the model can reason
	// about commands like 'npm run build' that execute project scripts.
	ctx, cancel := context.WithTimeout(context.Background(), llmDeadline)
	defer cancel()
	projCtx := projectctx.Context(in.CWD, in.Command)
	dec, err := e.llm.Classify(ctx, llm.ClassifyInput{
		Command:        in.Command,
		Description:    in.Description,
		CWD:            in.CWD,
		ProjectContext: projCtx,
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
		category := categorizeLLMError(err)
		e.appLog().Warn("llm_error",
			"err", err.Error(),
			"category", category,
			"provider", e.llm.Provider(),
			"model", e.llm.Model(),
			"breaker_state", newState,
			"command_preview", previewCommand(in.Command),
			"tool_use_id", in.ToolUseID,
		)
		return llmCallResult{shadow: "error:" + category}
	}

	// Success — close the circuit if it was tracking failures.
	if e.breaker != nil {
		_ = e.breaker.RecordSuccess()
	}

	switch dec.Verdict {
	case llm.VerdictSafe:
		// Default scope is project (safer) when the LLM doesn't say.
		scope := dec.Scope
		if scope != llm.ScopeGlobal && scope != llm.ScopeProject {
			scope = llm.ScopeProject
		}
		return llmCallResult{
			allow:  true,
			shadow: "safe",
			reason: dec.Reason,
			scope:  scope,
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

// categorizeLLMError classifies an error into a short tag for shadow
// trace and stats. The full error stays in the app log; the category
// is what shows up in `monitor` output and decision records.
func categorizeLLMError(err error) string {
	if err == nil {
		return ""
	}
	var rl *breaker.RateLimitError
	if errors.As(err, &rl) {
		return "rate_limited"
	}
	var srv *breaker.ServerError
	if errors.As(err, &srv) {
		return "server_5xx"
	}
	var to *breaker.TimeoutError
	if errors.As(err, &to) {
		return "timeout"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not JSON"):
		return "parse_error"
	case strings.Contains(msg, "API "):
		return "api_4xx"
	case strings.Contains(msg, "missing API key"):
		return "missing_key"
	default:
		return "unknown"
	}
}

// previewCommand returns the first 80 chars of a command, ellipsized.
// Used in app-log entries so a quick `monitor --file app` shows what
// the LLM was being asked about without dumping the full text.
func previewCommand(cmd string) string {
	if len(cmd) <= 80 {
		return cmd
	}
	return cmd[:77] + "…"
}

// spawnVerification fires off a goroutine that calls the verifier
// classifier, compares its verdict to the original, and updates the
// cache entry. Used for cross-provider verification: a faster classifier
// (e.g. Gemini Flash) decides in real time, a slower one (e.g. Sonnet)
// audits the decision in the background.
//
// No-op when the verifier is not configured. Caller should call
// AwaitVerifications before exiting the process.
func (e *Engine) spawnVerification(cacheKey string, in Input) {
	if e.verifier == nil || e.cache == nil || cacheKey == "" {
		return
	}
	e.pendingVerifies.Add(1)
	go func() {
		defer e.pendingVerifies.Done()
		// Use a fresh redacted command for the verifier — we don't keep
		// the redacted form around from the fast path. Skip if redaction
		// flagged this command — same protection as fast path.
		cmd := in.Command
		if e.redactor != nil {
			res := e.redactor.Scan(in.Command)
			if res.Decision == redact.Skip {
				return
			}
			cmd = res.Redacted
		}

		// Verifier gets a more generous deadline than the fast path —
		// it's not in the user's critical path.
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		dec, err := e.verifier.Classify(ctx, llm.ClassifyInput{
			Command:     cmd,
			Description: in.Description,
			CWD:         in.CWD,
		})
		if err != nil {
			e.appLog().Warn("verifier_error",
				"err", err.Error(),
				"provider", e.verifier.Provider(),
				"model", e.verifier.Model(),
				"tool_use_id", in.ToolUseID,
			)
			return
		}

		// Map LLM verdict to cache verdict.
		//   safe   → agreement, mark verified
		//   unsafe → REAL disagreement, mark Disagreement, next call denies
		//   unsure → verifier abstained, original allow stands.
		//
		// `unsure` is NOT treated as disagreement because most "unsure"
		// verdicts come from the verifier being unable to see inside
		// custom binaries or project scripts. Demoting to abstain
		// reduces the false-positive deny rate on legitimate dev workflows.
		switch dec.Verdict {
		case llm.VerdictSafe:
			// agreement → mark verified
		case llm.VerdictUnsafe:
			// Real disagreement: verifier strongly believes this is dangerous.
		default:
			// VerdictUnsure: verifier abstains. Skip the cache update so the
			// original allow stays untouched and Verified=false (still pending
			// review by some other model run).
			e.appLog().Info("verifier_unsure_abstain",
				"reason", dec.Reason,
				"verifier_provider", e.verifier.Provider(),
				"verifier_model", e.verifier.Model(),
				"command_preview", previewCommand(in.Command),
				"tool_use_id", in.ToolUseID,
			)
			return
		}
		var verifierVerdict cache.Verdict
		if dec.Verdict == llm.VerdictSafe {
			verifierVerdict = cache.VerdictAllow
		} else {
			verifierVerdict = cache.VerdictDeny
		}

		updated, err := e.cache.Verify(cacheKey, cache.VerifierResult{
			Provider: e.verifier.Provider(),
			Model:    e.verifier.Model(),
			Verdict:  verifierVerdict,
			Reason:   dec.Reason,
		})
		if err != nil {
			e.appLog().Warn("verifier_cache_update_error",
				"err", err.Error(),
				"tool_use_id", in.ToolUseID,
			)
			return
		}
		if !updated {
			// Cache entry vanished between Put and Verify — possibly evicted
			// or rotated by another process. Not an error.
			return
		}

		level := slog.LevelInfo
		msg := "verifier_agree"
		if verifierVerdict != cache.VerdictAllow {
			level = slog.LevelWarn
			msg = "verifier_disagree_DENY_NEXT_CALL"
		}
		e.appLog().Log(context.Background(), level, msg,
			"verifier_provider", e.verifier.Provider(),
			"verifier_model", e.verifier.Model(),
			"verifier_verdict", string(dec.Verdict),
			"verifier_reason", dec.Reason,
			"command", in.Command,
			"tool_use_id", in.ToolUseID,
		)
	}()
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
