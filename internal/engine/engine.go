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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/RobinUS2/claude-guard/internal/budget"
	"github.com/RobinUS2/claude-guard/internal/cache"
	"github.com/RobinUS2/claude-guard/internal/config"
	"github.com/RobinUS2/claude-guard/internal/reporisk"
	"github.com/RobinUS2/claude-guard/internal/filectx"
	"github.com/RobinUS2/claude-guard/internal/legacy"
	"github.com/RobinUS2/claude-guard/internal/llm"
	"github.com/RobinUS2/claude-guard/internal/llm/breaker"
	clog "github.com/RobinUS2/claude-guard/internal/log"
	"github.com/RobinUS2/claude-guard/internal/normalize"
	"github.com/RobinUS2/claude-guard/internal/projectconfig"
	"github.com/RobinUS2/claude-guard/internal/projectctx"
	"github.com/RobinUS2/claude-guard/internal/redact"
	"github.com/RobinUS2/claude-guard/internal/review"
	"github.com/RobinUS2/claude-guard/internal/rules"
	"github.com/RobinUS2/claude-guard/internal/tokensnapshot"
	"github.com/RobinUS2/claude-guard/internal/shellparse"
	"github.com/RobinUS2/claude-guard/internal/store"
	"github.com/RobinUS2/claude-guard/internal/version"
)

// Tier 4 (LLM) sync deadline. User-visible wait — the hook blocks up
// to this long for a classifier verdict. Inner providers have tighter
// per-call caps (Anthropic 3s, Gemini Flash 6s) so this is the engine
// ceiling. Cache hits bypass it entirely (~1ms file read).
//
// Declared as var (not const) so tests can reduce it to milliseconds
// for timing-based cases. Production code never mutates it after
// package init.
var llmDeadline = 7 * time.Second

// Tier 4 async deadline. When llmDeadline fires mid-classification,
// the hook returns "continue" to unblock the user, but the in-flight
// LLM call keeps running under this longer ctx. If it eventually
// returns "safe", the verdict is written to cache so the next
// identical command hits the cache path instead of paying another
// full LLM wait. If it doesn't complete within llmAsyncDeadline, the
// goroutine is abandoned and the call counts as a breaker failure
// (matches today's sync-timeout semantics).
//
// Must be accommodated by cmd/claude-guard/decide.go's
// AwaitVerifications cap PLUS the verifier's 15s budget — otherwise
// a late async verdict lands with no time left for the verifier.
var llmAsyncDeadline = 30 * time.Second

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
	Command     string // Bash: shell command; others: prefixed summary for LLM/cache
	Description string // Claude's own short description of intent
	CWD         string
	SessionID   string
	ToolUseID   string
	AgentID     string
	AgentType   string

	// Tool-specific parsed fields (populated by decide.go).
	URL      string // WebFetch
	Query    string // WebSearch
	FilePath string // Read, Write, Edit
	IsWrite  bool   // true for Write, Edit
	Content  string // Write content (for secret scan; NOT sent to LLM)

	// FileContent and RunnerFilePath are populated by Decide() for runner
	// commands. Not set by external callers (decide.go).
	FileContent    string // file contents for LLM context
	RunnerFilePath string // path of the referenced file (distinct from FilePath used by Read/Write/Edit)
	// GitPushContext is populated by Tier 2.7 for git push commands.
	// Injected into the LLM prompt to provide repo risk context.
	GitPushContext string
	// TranscriptPath is the path to the Claude Code session transcript file.
	// Populated from the PreToolUse hook payload. Used to snapshot approximate
	// session token count at decision time. Empty when hook does not provide it.
	TranscriptPath string
}

// Output is the engine's decision plus metadata for logging/debugging.
type Output struct {
	Verdict Verdict
	Tier    string // "instant_block", "instant_allow", "cache", "llm", "legacy", "default", "parse_error"
	Rule    string // matched rule name, if any
	Reason  string // human-readable reason
	Latency time.Duration

	// UserMessage, when non-empty, is injected into Claude's conversation
	// via the hook protocol's top-level `userMessage` field. Used by the
	// BQ pre-flight tier to surface byte estimates and budget status.
	UserMessage string

	// Hint, when non-empty, is appended to the deny reason as a concrete
	// rewrite recipe so Claude can self-correct. Populated from
	// config.DefaultRewriteHints() keyed by rule name. Only set for
	// Deny verdicts; empty for Allow/Continue.
	Hint string

	// SkipReason records why a tier was skipped (e.g. "llm_budget_exhausted").
	// Empty when no tier was skipped. Logged in the decision record so
	// operators can see why a command fell through to default/prompt.
	SkipReason string

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
	budget   *budget.Budget
	cache    *cache.Cache
	legacy   *legacy.AllowList    // tier 5: migrated allow list from settings.json
	bqBudget *budget.BQBudget     // BQ pre-flight budget tracker (nil = disabled)
	store    *store.Store         // session-aware state (nil = session tier disabled)
	repoRisk *reporisk.Registry   // git push risk scoring (nil = heuristics only)

	// ProjectConfigLoader is called per-decide to look up a
	// per-project .claude-guard.yml. Can be nil (feature disabled).
	// Defaults to projectconfig.Load in production; tests stub it.
	projectConfigLoader func(cwd string) (*projectconfig.Config, error)
	// projectConfigCache memoizes (path+mtime) → *Config for the
	// lifetime of the engine. Each hook invocation spawns a fresh
	// process, so this cache never grows unbounded.
	projectConfigCache sync.Map

	// promptVersion + rulesHash feed the cache key. Computed once at
	// engine construction so every Decide call uses the same key shape.
	promptVersion string
	rulesHash     string

	// promptHintsExtra is extra context from the self-review loop,
	// appended to the LLM classifier prompt. Empty when no hints file
	// exists. Populated at engine construction, used by runLLMTier.
	promptHintsExtra string

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
	Budget   *budget.Budget
	Cache    *cache.Cache
	// Legacy is the migrated allow list from settings.json. Tier 5.
	// Used as a safety net during phase 4 of the rollout — anything
	// previously auto-approved continues to flow through while the
	// smarter tiers warm up.
	Legacy *legacy.AllowList

	// ProjectConfigLoader is called per-decide to look up a per-project
	// .claude-guard.yml. Pass projectconfig.Load in production; pass a
	// stub in tests. Nil disables per-project config entirely.
	ProjectConfigLoader func(cwd string) (*projectconfig.Config, error)

	// BQBudget tracks the rolling daily BigQuery byte estimate. When set,
	// the engine runs a `bq query --dry_run` pre-flight for real BQ
	// queries and gates on the daily limit. Nil disables BQ pre-flight.
	BQBudget *budget.BQBudget

	// Store is the SQLite-backed session state DB. When non-nil, enables
	// the session-cache tier (Tier 2.5) and workflow-sequence tier (Tier 2.6).
	// Nil disables both session tiers (engine falls back to Tier 3 global cache).
	Store *store.Store

	// RepoRisk is the loaded repo risk registry for smart git push scoring (Tier 2.7).
	// Nil disables registry-based scoring; heuristics still run.
	RepoRisk *reporisk.Registry
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
		cfg:                 opts.Config,
		log:                 opts.DecisionLog,
		app:                 opts.AppLog,
		redactor:            opts.Redactor,
		llm:                 opts.LLM,
		verifier:            opts.Verifier,
		breaker:             opts.Breaker,
		budget:              opts.Budget,
		cache:               opts.Cache,
		legacy:              opts.Legacy,
		projectConfigLoader: opts.ProjectConfigLoader,
		bqBudget:            opts.BQBudget,
		store:               opts.Store,
		repoRisk:            opts.RepoRisk,
	}
	if e.cfg == nil {
		e.cfg = config.Default()
	}

	// Load learned rules from the self-review loop. These are
	// tier-2 allow rules generated by periodic Opus analysis of
	// decision logs. Appended to cfg.InstantAllow so they evaluate
	// alongside compiled-in rules. Missing/corrupt file → empty
	// (fail-open, same as missing project config).
	learnedFile := review.LoadLearnedRules(review.DefaultConfigDir())
	for _, lr := range learnedFile.Rules {
		e.cfg.InstantAllow = append(e.cfg.InstantAllow, &rules.AnchoredCommand{
			RuleName:         lr.Name,
			Programs:         lr.Programs,
			RequireSubcmdAny: lr.Subcommands,
			ForbidFlags:      lr.ForbidFlags,
		})
	}

	// Load prompt hints from the self-review loop. Appended to the
	// LLM classifier's system prompt so the model has user-specific
	// context. Cap checked at write time (2KB); just load and append.
	hintsFile := review.LoadPromptHints(review.DefaultConfigDir())
	if len(hintsFile.Hints) > 0 {
		var extra strings.Builder
		extra.WriteString("\n\n## User-specific context (auto-generated by self-review)\n")
		for _, h := range hintsFile.Hints {
			extra.WriteString("- ")
			extra.WriteString(h.Context)
			extra.WriteString("\n")
		}
		// Stash for use by the LLM classifier. The prompt is
		// composed at classify-time, not at engine construction.
		e.promptHintsExtra = extra.String()
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

// GitBranchOf is the exported name used by cmd/claude-guard/trust.go
// so subcommand code can reconstruct the same cache key the engine
// would compute. Keeping the implementation in engine.go means the
// definition of "git branch for cache key purposes" lives with the
// rest of the cache key composition logic.
func GitBranchOf(cwd string) string { return gitBranchOf(cwd) }

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

// computeRulesHash returns a stable hash of the BLOCK rule set only.
// Only block-rule changes should invalidate cached LLM verdicts — allow-rule
// additions are purely additive (they can only add more auto-approvals, never
// flip a safe command to unsafe). Excluding allow rules prevents every
// `make install` from busting the entire project-scoped LLM cache.
func computeRulesHash(cfg *config.Config) string {
	var names []string
	for _, r := range cfg.InstantBlock {
		names = append(names, "block:"+r.Name())
	}
	// Allow rules intentionally excluded — additive, do not invalidate verdicts.
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

	switch in.ToolName {
	case "Bash":
		// Fall through to the existing Bash pipeline below.
	case "WebFetch":
		return e.decideWebFetch(in, start)
	case "WebSearch":
		return e.decideWebSearch(in, start)
	case "Read":
		return e.decideRead(in, start)
	case "Write", "Edit":
		return e.decideWrite(in, start)
	default:
		// MCP and unknown tools — generic evaluator.
		return e.decideGeneric(in, start)
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

	// Load per-project config (tier 2 additions). Always safe to call —
	// missing file returns nil config; bad file returns config with Warning
	// and zero rules, so engine behavior falls back to compiled defaults.
	projRules, projHash := e.loadProjectConfig(in.CWD)

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
				out.Hint = config.DefaultRewriteHints()[r.Name()]
				out.Latency = time.Since(start)
				e.record(in, out)
				return out
			}
			// Shadow mode: log the would-have-blocked and continue to tier 2.
			break
		}
	}

	// Tier 2: ALLOW (compiled defaults + project-config extensions + agent-type profiles).
	// Project rules are namespaced as "project:<name>" so log output
	// distinguishes them from built-in rules. Project rules CANNOT
	// weaken tier 1 — this loop runs only if tier 1 did not match.
	allowRules := make([]rules.Rule, 0, len(e.cfg.InstantAllow)+len(projRules))
	allowRules = append(allowRules, e.cfg.InstantAllow...)
	allowRules = append(allowRules, projRules...)
	for _, r := range allowRules {
		if v, reason := r.Eval(parsed); v == rules.Match {
			out.Shadow.Tier2Rule = r.Name()
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

	// Tier 2 (agent-type extension): if the request comes from a known
	// subagent type with a compiled-in trust profile, check whether the
	// command's first program is in that profile's pre-approved list.
	// Only fires for subagents (AgentID != ""); main-agent commands always
	// go through the full pipeline. Tier 1 has already run unconditionally.
	//
	// TODO(security): enforce subcommand allowlist per agent trust profile.
	// E.g. the Explore profile allows `git` but must restrict to read-only
	// subcommands (status, log, diff, show) and block `git reset --hard`,
	// `git checkout`, `echo pwned >> ~/.zshrc`, etc. Track in plan item #15.
	if in.AgentID != "" && in.AgentType != "" && out.Shadow.Tier1Rule == "" {
		if profile, ok := e.cfg.AgentTrustProfiles[in.AgentType]; ok {
			program := firstProgram(in.Command)
			for _, p := range profile.Programs {
				if p == program {
					ruleName := "agent-trust:" + in.AgentType
					out.Shadow.Tier2Rule = ruleName
					if !e.cfg.ShadowMode {
						out.Verdict = Allow
						out.Tier = "instant_allow"
						out.Rule = ruleName
						out.Reason = "agent type " + in.AgentType + " pre-approved for " + program
						out.Latency = time.Since(start)
						e.record(in, out)
						return out
					}
					break
				}
			}
		}
	}

	// Tier 2.5: session-scoped approval cache. Checked before the global/project
	// LLM cache so within-session repeated commands are instant (~1ms SQLite read).
	// Key: SessionKey(canonical_form) looked up against (session_id, agent_id).
	// Deny entries (explicit user deny this session) block the command immediately
	// by returning Continue (fall to user prompt, not hard-deny — only Tier 1 hard-denies).
	if e.store != nil && in.SessionID != "" && out.Shadow.Tier1Rule == "" {
		// Derive canonical form for session key. Use AST-based normalisation
		// if available; fall back to the raw command. Errors are safe to ignore.
		canonical := normalizeCommand(in.Command)
		sessKey := cache.SessionKey(canonical)
		verdict := e.store.ReadSessionApproval(in.SessionID, in.AgentID, sessKey)
		switch verdict {
		case "allow":
			// Before honoring the cache hit, verify the command does not
			// contain a danger flag that was absent when it was first approved.
			// A cached "terraform apply" must NOT auto-approve
			// "terraform apply -destroy" or "terraform apply --replace=...".
			if commandHasDangerFlag(in.Command) {
				break // fall through to LLM tier
			}
			if !e.cfg.ShadowMode {
				out.Verdict = Allow
				out.Tier = "session"
				out.Rule = "session-cache"
				out.Reason = "approved earlier in this session"
				out.Latency = time.Since(start)
				e.record(in, out)
				return out
			}
			// Shadow: log what tier would have fired, continue pipeline.
			out.Shadow.Tier4LLM = "session:allow"
		case "deny":
			// Explicit deny this session — forward to user (not hard-block).
			out.Verdict = Continue
			out.Tier = "session"
			out.Rule = "session-deny"
			out.Reason = "explicitly denied earlier in this session"
			out.SkipReason = "session_deny_forwarded_to_user"
			out.Latency = time.Since(start)
			e.record(in, out)
			return out
		}

		// Tier 2.6: workflow sequence detection. If the current command is the
		// next step in a known sequence whose previous step was approved within
		// the last 10 minutes, auto-allow it. Tier 1 has already run.
		if seqAllow, seqName := e.checkWorkflowSequence(in, canonical); seqAllow {
			if !e.cfg.ShadowMode {
				out.Verdict = Allow
				out.Tier = "session"
				out.Rule = "workflow-sequence:" + seqName
				out.Reason = "logical follow-up in " + seqName + " workflow"
				out.Latency = time.Since(start)
				e.record(in, out)
				// Write to session cache so subsequent identical commands are Tier 2.5 hits.
				_ = e.store.WriteSessionApproval(in.SessionID, in.AgentID, sessKey, canonical, in.Command, "sequence")
				return out
			}
		}
	}

	// Tier 2.7: smart git push risk scoring.
	// Fires only for `git push` commands. Scores 0–10 using repo registry +
	// heuristics (branch, CI/CD, diff size). Low score → instant allow.
	// Medium score → LLM with push context injected. High score → LLM with
	// strong conservative framing (user approval dialog still shown).
	// Note: this tier only fires when git-push-nonforce (Tier 2) did NOT match,
	// meaning the command is ambiguous enough to have reached this point.
	if isGitPush(in.Command) && in.ToolName == "Bash" && out.Shadow.Tier1Rule == "" {
		pushScore, pushExplanation, _ := e.evaluateGitPush(in)
		if !e.cfg.ShadowMode {
			if pushScore <= PushScoreAutoAllow {
				out.Verdict = Allow
				out.Tier = "push-safe"
				out.Rule = "git-push-risk-low"
				out.Reason = "push risk score " + itoa(pushScore) + "/10 — auto-allowed"
				out.Latency = time.Since(start)
				e.record(in, out)
				return out
			}
			// Medium or high score: inject context into LLM prompt, continue pipeline.
			// The LLM will use pushExplanation to make a smarter decision.
			in.GitPushContext = pushExplanation
		}
	}

	// BQ pre-flight tier: runs between tier 2 and tier 3 for real `bq query`
	// commands (i.e., without --dry_run). Spawns `bq query --dry_run` as a
	// subprocess to get a byte estimate, checks the daily budget, and either
	// auto-allows (with a userMessage hint) or falls through to the user
	// prompt with a rewrite suggestion.
	if e.bqBudget != nil {
		pf := runBQPreflight(in.Command, e.bqBudget)
		if !pf.skipped {
			out.UserMessage = pf.userMessage
			if pf.allow && !e.cfg.ShadowMode {
				out.Verdict = Allow
				out.Tier = "bq_preflight"
				out.Rule = "bq-budget"
				out.Reason = pf.userMessage
				out.Latency = time.Since(start)
				e.record(in, out)
				return out
			}
			if !pf.allow && !e.cfg.ShadowMode {
				// Over budget — fall through to user prompt with hint already set.
				out.Tier = "bq_preflight"
				out.Rule = "bq-budget-exceeded"
				out.Latency = time.Since(start)
				e.record(in, out)
				return out
			}
		}
	}

	// File content extraction for runner commands. Must happen before
	// cache lookup so the FileContentHash participates in the cache key.
	var fileContent, filePath, fileContentHash string
	if parsed != nil {
		for _, call := range parsed.Calls {
			fc := filectx.Extract(call)
			if fc == nil {
				continue
			}
			if fc.Skipped {
				break
			}
			// Check file-analysis budget.
			if e.budget != nil && !e.budget.Check(true) {
				e.appLog().Warn("file_analysis_budget_exhausted",
					"path", fc.Path,
					"tool_use_id", in.ToolUseID,
				)
				break
			}
			fileContent = fc.Content
			filePath = fc.Path
			h := sha256.Sum256([]byte(fc.Content))
			fileContentHash = hex.EncodeToString(h[:])
			break // first file only
		}
	}
	in.FileContent = fileContent
	in.RunnerFilePath = filePath

	// Tier 3: cache lookup (only when there's an LLM to back it — caching
	// deterministic verdicts adds latency for no gain since they're already
	// sub-millisecond).
	//
	// We try the global cache key first, then the project-scoped key. A
	// global hit means "this command is safe in any cwd" and bypasses
	// the LLM regardless of where you are. A project hit only matches
	// the same cwd + branch.
	keyInputs := cache.KeyInputs{
		Tool:              in.ToolName,
		Command:           in.Command,
		CWD:               in.CWD,
		GitBranch:         gitBranchOf(in.CWD),
		PromptVersion:     e.promptVersion,
		RulesHash:         e.rulesHash,
		ProjectConfigHash: projHash,
		// MakefileHash: populated for `make <target>` shapes so a
		// cached LLM verdict invalidates when the Makefile content
		// changes. Empty for all other commands.
		MakefileHash:    projectctx.MakefileHash(in.CWD, in.Command),
		FileContentHash: fileContentHash,
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
					// Verifier disagreement → forward to user (not auto-deny).
					// Only tier 1 (deterministic rules) should hard-block.
					// LLM/verifier disagreements surface as a prompt so the
					// human decides.
					out.Verdict = Continue
					out.Tier = "cache"
					out.Rule = "verifier:" + entry.VerifierProvider + "/" + entry.VerifierModel
					out.Reason = "verified by " + entry.VerifierProvider + " (disagreement with original): " + entry.VerifierReason
					out.SkipReason = "verifier_disagree_forwarded_to_user"
					out.Latency = time.Since(start)
					e.record(in, out)
					writePendingApproval(in.ToolUseID, in.Command, "", in.CWD, in.SessionID, out.Reason)
					return out
				}
			}
			// Shadow mode or non-actionable verdict.
			out.Latency = time.Since(start)
			e.record(in, out)
			return out
		}

		// Exact miss — try canonical (normalized) lookup. This is where
		// the cache gets amplified: one canonical entry for "dig
		// {DOMAIN} {DNS_TYPE}" covers every concrete dig command whose
		// tokens validate against the slot types.
		program := normalize.FirstProgram(in.Command)
		if program != "" {
			if entry, canonHitKey, hit := e.cache.LookupCanonical(program, in.Command, normalize.CanonicalMatches); hit {
				// Telemetry: bump MatchCount so stats can show how often
				// each canonical pattern is serving concrete commands.
				// Best-effort — a failure doesn't affect the decision.
				if _, err := e.cache.IncrementMatchCount(canonHitKey); err != nil {
					e.appLog().Warn("canonical_match_increment_error",
						"err", err.Error(),
						"tool_use_id", in.ToolUseID,
					)
				}
				eff := entry.EffectiveVerdict()
				suffix := "canonical:" + string(eff)
				if entry.Disagreement {
					suffix = "canonical:verifier-deny:" + string(eff)
				} else if entry.Verified {
					suffix = "canonical:verified:" + string(eff)
				}
				out.Shadow.Tier4LLM = "cache:" + suffix
				if !e.cfg.ShadowMode && eff == cache.VerdictAllow {
					out.Verdict = Allow
					out.Tier = "cache"
					out.Rule = "canonical/" + entry.CanonicalForm
					out.Reason = entry.Reason
					out.Latency = time.Since(start)
					e.record(in, out)
					return out
				}
				if !e.cfg.ShadowMode && eff == cache.VerdictDeny {
					// Verifier disagreement → forward to user, not auto-deny.
					out.Verdict = Continue
					out.Tier = "cache"
					out.Rule = "canonical/" + entry.CanonicalForm
					out.Reason = "verified by " + entry.VerifierProvider + " (disagreement): " + entry.VerifierReason
					out.SkipReason = "verifier_disagree_forwarded_to_user"
					out.Latency = time.Since(start)
					e.record(in, out)
					writePendingApproval(in.ToolUseID, in.Command, entry.CanonicalForm, in.CWD, in.SessionID, out.Reason)
					return out
				}
				// Shadow mode: log and fall through.
				out.Latency = time.Since(start)
				e.record(in, out)
				return out
			}
		}
	}

	// Tier 4: LLM classifier (approve-only).
	llmBudgetOK := e.budget == nil || e.budget.Check(false)
	if e.llm != nil && llmBudgetOK {
		llmVerdict := e.runLLMTier(in, keyInputs, globalKey, projectKey)
		out.Shadow.Tier4LLM = llmVerdict.shadow
		// Record budget usage after LLM call (sync path).
		if e.budget != nil {
			e.budget.Record(fileContent != "")
		}
		// Cache safe verdicts so the next identical command is instant.
		// persistLLMAllow handles scope selection, canonical-form
		// caching, and verifier spawn. Shared with the async timeout
		// path in runLLMTier — a timeout that eventually returns
		// "safe" calls persistLLMAllow from its background goroutine.
		if e.cache != nil && llmVerdict.allow {
			e.persistLLMAllow(in, llmVerdict, keyInputs, globalKey, projectKey)
			if llmVerdict.scope == llm.ScopeGlobal {
				out.Shadow.Tier4LLM = "safe:global"
			} else {
				out.Shadow.Tier4LLM = "safe:project"
			}
		}
		// Populate Reason and Rule from the LLM result so the
		// decision log has the WHY. Skip for the async timeout path —
		// no verdict has arrived yet; setting out.Rule to
		// provider/model would misleadingly imply the LLM approved.
		if llmVerdict.shadow != "timeout-async-pending" {
			if llmVerdict.reason != "" {
				out.Reason = llmVerdict.reason
			}
			if e.llm != nil {
				out.Rule = e.llm.Provider() + "/" + e.llm.Model()
			}
		}
		if !e.cfg.ShadowMode && llmVerdict.allow {
			out.Verdict = Allow
			out.Tier = "llm"
			out.Latency = time.Since(start)
			e.record(in, out)
			return out
		}
	} else if !llmBudgetOK {
		out.SkipReason = "llm_budget_exhausted"
		e.appLog().Warn("llm_budget_exhausted", "tool_use_id", in.ToolUseID, "command", in.Command)
	}

	// Tier 5: legacy allow list (migrated from settings.json).
	// Last-resort allow before falling through to the user prompt.
	if e.legacy != nil {
		if match := e.legacy.Match(in.Command); match != nil {
			// out.Shadow.Tier1Rule left unchanged from earlier tiers.
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
	writePendingApproval(in.ToolUseID, in.Command, "", in.CWD, in.SessionID, "no rule matched")
	return out
}

// llmCallResult is the engine-internal summary of a Tier 4 attempt.
type llmCallResult struct {
	allow  bool               // true only when LLM said "safe"
	shadow string             // "safe", "unsafe", "unsure", "skipped:<reason>", or "error"
	reason string             // human-readable reason for the decision
	scope  llm.Scope          // global vs project — used for cache key choice
	slots  []llm.VariableSlot // LLM-identified variable tokens for normalization
}

// toNormalizeSlots converts llm.VariableSlot → normalize.Slot (which
// uses the canonical SlotType). normalize validates the type against
// its closed vocabulary; unknown types are dropped.
func toNormalizeSlots(xs []llm.VariableSlot) []normalize.Slot {
	out := make([]normalize.Slot, 0, len(xs))
	for _, x := range xs {
		out = append(out, normalize.Slot{
			Position: x.Position,
			Type:     normalize.SlotType(x.Type),
		})
	}
	return out
}

// runLLMTier handles redaction, circuit breaker check, and the actual
// LLM call. Always returns; never panics. All errors are logged to the
// app log and the engine falls through.
//
// The classifier call runs under asyncCtx (llmAsyncDeadline, 30s) and
// races against a llmDeadline-length sync timer. On sync-wins, today's
// behavior: map the outcome and return. On timer-wins, hand the
// in-flight goroutine to pendingVerifies: it continues running, and
// on eventual "safe" verdict writes to cache just as the sync path
// would have. keyInputs/globalKey/projectKey are captured into the
// async closure for cache-write scope selection.
func (e *Engine) runLLMTier(
	in Input,
	keyInputs cache.KeyInputs,
	globalKey, projectKey string,
) llmCallResult {
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

	// Start the classifier under a generous async ctx. The sync wait
	// is governed by the separate timer in the select below. If the
	// call finishes within llmDeadline, we use the result now; if
	// not, the goroutine keeps running under asyncCtx and writes to
	// cache on arrival.
	asyncCtx, asyncCancel := context.WithTimeout(context.Background(), llmAsyncDeadline)
	projCtx := projectctx.Context(in.CWD, in.Command)
	// Operator-trusted CLIs (from the legacy allow list) — a list of
	// pre-approved first-word programs the LLM uses to reason about
	// compound shapes (for-loops, pipelines) whose body only invokes
	// these. Capped to avoid prompt bloat; 60 is well above the size of
	// any real settings.json allow list we've observed.
	trusted := e.legacy.TrustedPrograms(60)
	// Trusted domains from project config — tells the LLM that curl/wget
	// to these domains is safe (project's own APIs).
	var trustedDomains []string
	if cached, ok := e.projectConfigCache.Load(in.CWD); ok {
		if pc, ok := cached.(*projectconfig.Config); ok && pc != nil {
			trustedDomains = pc.TrustedDomains
		}
	}
	// Fetch recent session context (last 10 approved canonicals) to help
	// the LLM reason about workflow consistency. Only when session store is live.
	var sessionCtx []string
	if e.store != nil && in.SessionID != "" {
		sessionCtx = e.store.GetSessionContext(in.SessionID, in.AgentID, 10)
	}

	input := llm.ClassifyInput{
		Command:         in.Command,
		Description:     in.Description,
		CWD:             in.CWD,
		ProjectContext:  projCtx,
		FileContent:     in.FileContent,
		FilePath:        in.RunnerFilePath,
		TrustedPrograms: trusted,
		TrustedDomains:  trustedDomains,
		SessionContext:  sessionCtx,
		GitPushContext:  in.GitPushContext,
	}

	type outcome struct {
		dec *llm.Decision
		err error
	}
	resultCh := make(chan outcome, 1)
	go func() {
		dec, err := e.llm.Classify(asyncCtx, input)
		resultCh <- outcome{dec: dec, err: err}
	}()

	select {
	case o := <-resultCh:
		// Sync path — arrived within llmDeadline. Unchanged behavior.
		asyncCancel()
		result := e.mapLLMOutcome(o.dec, o.err, in)
		// On "unsafe" or "unsure", second-guess with the verifier so a
		// fast-classifier false positive gets cached as allow for the
		// next call. No-op when verifier isn't configured.
		if o.err == nil && o.dec != nil &&
			(o.dec.Verdict == llm.VerdictUnsafe || o.dec.Verdict == llm.VerdictUnsure) {
			e.spawnUnsafeReview(in, o.dec.Reason, keyInputs, globalKey, projectKey)
		}
		return result

	case <-time.After(llmDeadline):
		// Sync timer fired. Hand the classifier goroutine off to a
		// background persister.
		//
		// CRITICAL ORDERING: pendingVerifies.Add(1) MUST be called
		// synchronously on the caller goroutine (here), BEFORE the
		// `go func() { … }()` below. Otherwise AwaitVerifications
		// (in cmd/claude-guard/decide.go, called after stdout flush)
		// could begin its Wait with counter=0 and return before the
		// goroutine has registered itself. Matches the ordering in
		// spawnVerification below.
		e.pendingVerifies.Add(1)
		go func() {
			defer e.pendingVerifies.Done()
			defer asyncCancel()
			var o outcome
			select {
			case o = <-resultCh:
			case <-asyncCtx.Done():
				// Absolute deadline hit without a result. Record to
				// the breaker so a cascade of hung LLMs opens the
				// circuit, matching today's sync-timeout semantics.
				if e.breaker != nil {
					_, _ = e.breaker.RecordFailure(&breaker.TimeoutError{
						After: llmAsyncDeadline,
					})
				}
				e.appLog().Info("async_llm_abandoned",
					"reason", "absolute_deadline",
					"command_preview", previewCommand(in.Command),
					"tool_use_id", in.ToolUseID,
				)
				return
			}
			if o.err != nil {
				if e.breaker != nil {
					_, _ = e.breaker.RecordFailure(o.err)
				}
				e.appLog().Warn("async_llm_error",
					"err", o.err.Error(),
					"category", categorizeLLMError(o.err),
					"provider", e.llm.Provider(),
					"model", e.llm.Model(),
					"command_preview", previewCommand(in.Command),
					"tool_use_id", in.ToolUseID,
				)
				return
			}
			if e.breaker != nil {
				_ = e.breaker.RecordSuccess()
			}
			if o.dec.Verdict != llm.VerdictSafe {
				// Match the sync path: non-safe verdicts are not
				// cached (LLM is approve-only). Still spawn the
				// unsafe-review verifier so a late false-positive
				// can still populate an allow cache entry for the
				// next call.
				e.appLog().Info("async_llm_completed",
					"verdict", string(o.dec.Verdict),
					"reason", o.dec.Reason,
					"command_preview", previewCommand(in.Command),
					"tool_use_id", in.ToolUseID,
				)
				e.spawnUnsafeReview(in, o.dec.Reason, keyInputs, globalKey, projectKey)
				return
			}
			scope := o.dec.Scope
			if scope != llm.ScopeGlobal && scope != llm.ScopeProject {
				scope = llm.ScopeProject
			}
			v := llmCallResult{
				allow:  true,
				shadow: "async:safe",
				reason: o.dec.Reason,
				scope:  scope,
				slots:  o.dec.VariableSlots,
			}
			e.persistLLMAllow(in, v, keyInputs, globalKey, projectKey)
			// Record budget usage (async path).
			if e.budget != nil {
				e.budget.Record(in.FileContent != "")
			}
			e.appLog().Info("async_llm_completed",
				"verdict", "safe",
				"scope", string(scope),
				"command_preview", previewCommand(in.Command),
				"tool_use_id", in.ToolUseID,
			)
		}()
		return llmCallResult{shadow: "timeout-async-pending"}
	}
}

// mapLLMOutcome translates a (*Decision, error) pair into an
// llmCallResult with side-effects: breaker update, app-log events.
// Extracted from runLLMTier so the sync path can call it. The async
// goroutine handles its own logging inline because its event names
// (async_llm_error/completed/abandoned) differ from the sync path.
func (e *Engine) mapLLMOutcome(dec *llm.Decision, err error, in Input) llmCallResult {
	if err != nil {
		var newState any
		if e.breaker != nil {
			s, _ := e.breaker.RecordFailure(err)
			if s != nil {
				newState = s
			}
		}
		category := categorizeLLMError(err)
		logArgs := []any{
			"err", err.Error(),
			"category", category,
			"provider", e.llm.Provider(),
			"model", e.llm.Model(),
			"breaker_state", newState,
			"command_preview", previewCommand(in.Command),
			"tool_use_id", in.ToolUseID,
		}
		var pe *llm.ParseError
		if errors.As(err, &pe) {
			logArgs = append(logArgs,
				"raw_len", pe.RawLength,
				"looks_truncated", pe.LooksTruncated,
				"raw_response", pe.RawResponse,
			)
		}
		e.appLog().Warn("llm_error", logArgs...)
		return llmCallResult{shadow: "error:" + category}
	}

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
			slots:  dec.VariableSlots,
		}
	case llm.VerdictUnsafe:
		// LLM is approve-only — fall through. Log the would-have-been block.
		e.appLog().Info("llm_unsafe_fallthrough",
			"reason", dec.Reason,
			"category", dec.Category,
			"tool_use_id", in.ToolUseID,
		)
		return llmCallResult{shadow: shadowWithReason("unsafe", dec.Reason), reason: dec.Reason}
	default:
		return llmCallResult{shadow: shadowWithReason("unsure", dec.Reason), reason: dec.Reason}
	}
}

// shadowWithReason formats a shadow-trace value that includes a
// brief reason snippet, so `claude-guard monitor` surfaces WHY a
// decision was unsafe/unsure without forcing the operator to dig
// into app.jsonl. Format: `<tag>: <first-80-chars-of-reason>`.
// When reason is empty, returns just the tag unchanged.
func shadowWithReason(tag, reason string) string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return tag
	}
	const maxReasonLen = 80
	if len(reason) > maxReasonLen {
		reason = reason[:maxReasonLen-1] + "…"
	}
	return tag + ": " + reason
}

// spawnUnsafeReview fires a goroutine that asks the verifier to
// second-guess a fast-classifier "unsafe" verdict. When the verifier
// says "safe", we write an allow cache entry so the next identical
// command bypasses the user prompt. Symmetric to spawnVerification
// (which handles the "fast said safe, verifier disagreed" case) —
// same cross-provider cadence, same background lifecycle via
// pendingVerifies.
//
// Risk model:
//   - Fast classifier false-positive (common for Gemini Flash on
//     unusual but safe shapes) → verifier flips to Safe → we cache
//     the allow. Speeds up the next identical call. No additional
//     user risk on THIS invocation — the user has already been
//     prompted.
//   - Fast classifier true-positive, verifier agrees Unsafe → do not
//     cache. Same behavior as today's plain fall-through.
//   - Verifier Unsure → abstain; do not cache. Cross-provider signal
//     isn't strong enough to override the fast classifier's caution.
//
// Residual: if the user denied the Claude Code permission prompt on
// this call, verifier-says-safe will still cache an allow, so the
// next identical cmd auto-approves, contradicting the user's deny.
// Documented "acceptable residual" — same as the existing
// safe→verifier flow.
//
// No-op when verifier or cache is not configured. Caller should call
// AwaitVerifications before exiting the process.
func (e *Engine) spawnUnsafeReview(
	in Input,
	fastReason string,
	keyInputs cache.KeyInputs,
	globalKey, projectKey string,
) {
	if e.verifier == nil || e.cache == nil {
		return
	}
	e.pendingVerifies.Add(1)
	go func() {
		defer e.pendingVerifies.Done()
		cmd := in.Command
		if e.redactor != nil {
			res := e.redactor.Scan(cmd)
			if res.Decision == redact.Skip {
				// Same redaction skip as the fast path — don't ship
				// secret-bearing commands to the verifier either.
				return
			}
			cmd = res.Redacted
		}
		if e.breaker != nil {
			permitted, _, _ := e.breaker.Check()
			if !permitted {
				return
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		dec, err := e.verifier.Classify(ctx, llm.ClassifyInput{
			Command:     cmd,
			Description: in.Description,
			CWD:         in.CWD,
			FileContent: in.FileContent,
			FilePath:    in.RunnerFilePath,
		})
		if err != nil {
			e.appLog().Warn("unsafe_review_error",
				"err", err.Error(),
				"verifier_provider", e.verifier.Provider(),
				"verifier_model", e.verifier.Model(),
				"command_preview", previewCommand(in.Command),
				"tool_use_id", in.ToolUseID,
			)
			return
		}
		switch dec.Verdict {
		case llm.VerdictSafe:
			// Verifier disagrees: fast said unsafe, verifier says safe.
			// Write the allow cache entry so next call auto-approves.
			scope := dec.Scope
			if scope != llm.ScopeGlobal && scope != llm.ScopeProject {
				scope = llm.ScopeProject
			}
			v := llmCallResult{
				allow:  true,
				shadow: "unsafe-review:safe",
				reason: dec.Reason,
				scope:  scope,
				slots:  dec.VariableSlots,
			}
			// Cache the allow. Skip the normal async verifier spawn:
			// this verdict ALREADY came from the verifier, so firing
			// spawnVerification would pointlessly re-classify the same
			// command with the same verifier and double the cost.
			e.persistLLMAllowNoVerify(in, v, keyInputs, globalKey, projectKey)
			e.appLog().Warn("unsafe_review_disagree_ALLOW_NEXT_CALL",
				"fast_reason", fastReason,
				"verifier_reason", dec.Reason,
				"verifier_provider", e.verifier.Provider(),
				"verifier_model", e.verifier.Model(),
				"scope", string(scope),
				"command_preview", previewCommand(in.Command),
				"tool_use_id", in.ToolUseID,
			)
		case llm.VerdictUnsafe:
			// Verifier agrees. No action — just log for visibility.
			e.appLog().Info("unsafe_review_agree",
				"fast_reason", fastReason,
				"verifier_reason", dec.Reason,
				"verifier_provider", e.verifier.Provider(),
				"verifier_model", e.verifier.Model(),
				"command_preview", previewCommand(in.Command),
				"tool_use_id", in.ToolUseID,
			)
		default:
			// Unsure → abstain; don't cache.
			e.appLog().Info("unsafe_review_unsure",
				"fast_reason", fastReason,
				"verifier_reason", dec.Reason,
				"verifier_provider", e.verifier.Provider(),
				"verifier_model", e.verifier.Model(),
				"command_preview", previewCommand(in.Command),
				"tool_use_id", in.ToolUseID,
			)
		}
	}()
}

// persistLLMAllow writes a safe verdict to cache (plus the optional
// canonical-form sibling entry), then spawns the async verifier.
// Callable from both the sync path in Decide and the async timeout
// goroutine in runLLMTier. No-op when e.cache is nil or v.allow is
// false.
//
// Shared responsibility: scope selection, canonical-form
// normalization + telemetry, verifier spawn. Keeping one definition
// means both paths behave identically — a late async verdict
// populates cache the same way an on-time sync verdict would have.
func (e *Engine) persistLLMAllow(
	in Input,
	v llmCallResult,
	keyInputs cache.KeyInputs,
	globalKey, projectKey string,
) {
	e.persistLLMAllowImpl(in, v, keyInputs, globalKey, projectKey, true)
}

// persistLLMAllowNoVerify is a variant that skips spawnVerification.
// Used by spawnUnsafeReview: the allow verdict already came from the
// verifier, so re-verifying would double-spend the cross-provider
// budget on the same command.
func (e *Engine) persistLLMAllowNoVerify(
	in Input,
	v llmCallResult,
	keyInputs cache.KeyInputs,
	globalKey, projectKey string,
) {
	e.persistLLMAllowImpl(in, v, keyInputs, globalKey, projectKey, false)
}

func (e *Engine) persistLLMAllowImpl(
	in Input,
	v llmCallResult,
	keyInputs cache.KeyInputs,
	globalKey, projectKey string,
	spawnVerifier bool,
) {
	if e.cache == nil || !v.allow {
		return
	}
	// Tier 2.5 write: also store in session_approvals so subsequent calls
	// within this session skip the LLM entirely (~1ms SQLite hit).
	if e.store != nil && in.SessionID != "" {
		canonical := normalizeCommand(in.Command)
		sessKey := cache.SessionKey(canonical)
		_ = e.store.WriteSessionApproval(in.SessionID, in.AgentID, sessKey, canonical, in.Command, "llm")
		// Advance any matching workflow sequence to the next step.
		e.advanceWorkflowSequence(in, canonical)
	}

	storeKey := projectKey
	if v.scope == llm.ScopeGlobal {
		storeKey = globalKey
	}
	_ = e.cache.Put(storeKey, cache.Entry{
		Verdict:  cache.VerdictAllow,
		Reason:   v.reason,
		Tier:     "llm",
		Provider: e.llm.Provider(),
		Model:    e.llm.Model(),
		Command:  in.Command,
		CWD:      in.CWD,
	}, 90*24*time.Hour)

	// Canonicalization: if the LLM returned variable slots, try to
	// produce a normalized form and cache it as a second entry.
	// Future commands matching the canonical hit the cache without
	// an LLM call. Done BEFORE spawning the verifier so
	// spawnVerification can invalidate BOTH entries on disagreement.
	canonKey := ""
	if len(v.slots) > 0 {
		canonicalForm, dropped, nerr := normalize.Normalize(in.Command, toNormalizeSlots(v.slots))
		if len(dropped) > 0 {
			// Bundle per-decision (M4) — one log line carrying every
			// dropped slot rather than N lines.
			positions := make([]string, 0, len(dropped))
			types := make([]string, 0, len(dropped))
			reasons := make([]string, 0, len(dropped))
			for _, d := range dropped {
				positions = append(positions, d.Slot.Position)
				types = append(types, string(d.Slot.Type))
				reasons = append(reasons, d.Reason)
			}
			e.appLog().Info("normalize_slots_dropped",
				"count", len(dropped),
				"positions", strings.Join(positions, ","),
				"types", strings.Join(types, ","),
				"reasons", strings.Join(reasons, ","),
				"tool_use_id", in.ToolUseID,
			)
		}
		if nerr != nil {
			e.appLog().Warn("normalize_error", "err", nerr.Error(),
				"tool_use_id", in.ToolUseID)
		}
		if canonicalForm != "" {
			program := normalize.FirstProgram(in.Command)
			canonKeyInputs := keyInputs
			canonKeyInputs.Command = canonicalForm
			if v.scope == llm.ScopeGlobal {
				canonKey = cache.GlobalKey(canonKeyInputs)
			} else {
				canonKey = cache.Key(canonKeyInputs)
			}
			_ = e.cache.Put(canonKey, cache.Entry{
				Verdict:       cache.VerdictAllow,
				Reason:        v.reason,
				Tier:          "llm",
				Provider:      e.llm.Provider(),
				Model:         e.llm.Model(),
				Command:       in.Command, // the first concrete command we saw
				CWD:           in.CWD,
				CanonicalForm: canonicalForm,
				Program:       program,
				MatchCount:    1,
			}, 90*24*time.Hour)
		}
	}
	// Spawn the async verifier (cross-provider second opinion).
	// Passing canonKey lets the verifier invalidate the canonical
	// sibling entry too when it disagrees with the fast path.
	// Skipped when called via persistLLMAllowNoVerify — see
	// spawnUnsafeReview for the rationale.
	if spawnVerifier {
		e.spawnVerification(storeKey, canonKey, in)
	}
}

// loadProjectConfig resolves the per-project .claude-guard.yml for
// this command's cwd, returning the tier-2 allow rule extensions and
// the config's hash (for cache-key invalidation). Returns (nil, "")
// when no loader is configured or no file is found. Process-lifetime
// memoization by config-file path keeps the cost flat across multiple
// Decide() calls in one hook invocation.
//
// Warnings from Load (rejected rules, malformed YAML, unknown fields)
// are logged to app.jsonl once per path. The engine still operates
// with whatever rules DID validate — it does not fail closed on
// project-config errors because then a corrupt project file could
// prevent the user from working.
func (e *Engine) loadProjectConfig(cwd string) ([]rules.Rule, string) {
	if e.projectConfigLoader == nil {
		return nil, ""
	}
	if cwd == "" {
		return nil, ""
	}

	// Process-local memoization. Key is cwd — different commands in
	// different cwds may resolve to the same or different config files.
	if cached, ok := e.projectConfigCache.Load(cwd); ok {
		if c, ok := cached.(*projectconfig.Config); ok && c != nil {
			return c.Rules, c.Hash
		}
		return nil, ""
	}

	cfg, err := e.projectConfigLoader(cwd)
	if err != nil {
		e.appLog().Warn("project_config_error", "err", err.Error(), "cwd", cwd)
		e.projectConfigCache.Store(cwd, (*projectconfig.Config)(nil))
		return nil, ""
	}
	e.projectConfigCache.Store(cwd, cfg)
	if cfg == nil {
		return nil, ""
	}

	if cfg.Warning != nil {
		e.appLog().Warn("project_config_warning",
			"path", cfg.Path,
			"warning", cfg.Warning.Error(),
			"accepted_rules", len(cfg.Rules),
		)
	} else {
		e.appLog().Info("project_config_loaded",
			"path", cfg.Path,
			"project_name", cfg.ProjectName,
			"rule_count", len(cfg.Rules),
			"hash", shortHash(cfg.Hash),
		)
	}
	return cfg.Rules, cfg.Hash
}

// shortHash returns the first 12 hex chars of a sha256 string — plenty
// for identifying a config version in logs.
func shortHash(h string) string {
	if len(h) < 12 {
		return h
	}
	return h[:12]
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
// canonicalKey, when non-empty, is a sibling cache entry (the
// normalized form of the same command). Both entries are updated in
// lockstep: if the verifier disagrees, BOTH exact and canonical get
// flipped to Disagreement — otherwise a flagged canonical would keep
// allowing future concrete commands under its pattern.
//
// No-op when the verifier is not configured. Caller should call
// AwaitVerifications before exiting the process.
func (e *Engine) spawnVerification(cacheKey, canonicalKey string, in Input) {
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
			FileContent: in.FileContent,
			FilePath:    in.RunnerFilePath,
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

		result := cache.VerifierResult{
			Provider: e.verifier.Provider(),
			Model:    e.verifier.Model(),
			Verdict:  verifierVerdict,
			Reason:   dec.Reason,
		}
		updated, err := e.cache.Verify(cacheKey, result)
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

		// Apply the same verdict to the canonical sibling if one was
		// written. This prevents a disagreement-on-exact from leaving
		// the canonical (and all future concrete commands under its
		// pattern) silently marked safe (CTO review C1).
		if canonicalKey != "" && canonicalKey != cacheKey {
			canonUpdated, errCanon := e.cache.Verify(canonicalKey, result)
			if errCanon != nil {
				e.appLog().Warn("verifier_canonical_update_error",
					"err", errCanon.Error(),
					"tool_use_id", in.ToolUseID,
				)
			} else if !canonUpdated {
				e.appLog().Info("verifier_canonical_entry_vanished",
					"tool_use_id", in.ToolUseID,
				)
			}
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
			"canonical_sibling_updated", canonicalKey != "",
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
		SkipReason:   out.SkipReason,
		LatencyUS:    out.Latency.Microseconds(),
	}
	if out.Shadow.Tier1Rule != "" || out.Shadow.Tier2Rule != "" || out.Shadow.Tier4LLM != "" {
		rec.Shadow = &clog.ShadowFields{
			Tier1Block: out.Shadow.Tier1Rule,
			Tier2Allow: out.Shadow.Tier2Rule,
			Tier4LLM:   out.Shadow.Tier4LLM,
		}
	}
	rec.SessionTokens = tokensnapshot.Count(in.TranscriptPath)
	e.log.Decision(rec)
}

// ---------------------------------------------------------------------------
// Session-tier helpers
// ---------------------------------------------------------------------------

// normalizeCommand is an alias for cache.SessionCanonical used within the engine.
// Both the engine and the learn hook (cmd layer) use cache.SessionCanonical so
// their session keys are always consistent — critical for the PostToolUse
// session-promotion path to be visible to the Tier 2.5 lookup.
func normalizeCommand(cmd string) string {
	return cache.SessionCanonical(cmd)
}

// firstProgram returns the first space-separated token of cmd (the program name).
func firstProgram(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if i := strings.IndexByte(cmd, ' '); i > 0 {
		return cmd[:i]
	}
	return cmd
}

// sequenceInactivityTimeout is how long after the last approved step a
// sequence remains active. After this window the sequence resets.
const sequenceInactivityTimeout = 10 * time.Minute

// sequenceDangerFlags are command-line flags that significantly change the
// blast radius of a command and must not be auto-approved by sequence detection,
// even when the program+subcommand match a known sequence step. The user must
// explicitly approve any command containing these flags.
var sequenceDangerFlags = []string{
	"-destroy", "--destroy",   // terraform apply -destroy
	"-force", "--force",       // various force operations
	"--replace",               // terraform apply --replace=
	"--recreate",              // docker-compose recreate, etc.
	"--hard",                  // git reset --hard
	"--purge",                 // apt/dpkg --purge
	"--delete", "-D",          // git branch -D, etc.
}

// commandHasDangerFlag reports whether cmd contains any sequenceDangerFlag.
// Used by Tier 2.5 (session cache) and Tier 2.6 (workflow sequence) to reject
// commands whose blast radius changed since the original approval.
func commandHasDangerFlag(cmd string) bool {
	for _, flag := range sequenceDangerFlags {
		if strings.Contains(cmd, flag) {
			return true
		}
	}
	return false
}

// checkWorkflowSequence checks whether cmd is the next step in any
// in-progress workflow sequence for this session/agent. Returns (true, name)
// on a match. Sequences are started by the first step being approved through
// any tier; subsequent steps match here. All checks happen after Tier 1.
func (e *Engine) checkWorkflowSequence(in Input, canonical string) (bool, string) {
	if e.store == nil || in.SessionID == "" || len(e.cfg.WorkflowSequences) == 0 {
		return false, ""
	}
	// Reject any command with a danger flag regardless of sequence position.
	// Protects against `terraform apply -destroy` matching "terraform apply" step.
	if commandHasDangerFlag(in.Command) {
		return false, ""
	}
	for idx, seq := range e.cfg.WorkflowSequences {
		stepIdx, lastUpdated, found := e.store.ReadSequenceProgress(in.SessionID, in.AgentID, idx)
		if !found {
			continue
		}
		// Check inactivity timeout.
		if time.Since(lastUpdated) > sequenceInactivityTimeout {
			_ = e.store.DeleteSequenceProgress(in.SessionID, in.AgentID, idx)
			continue
		}
		// The next step is stepIdx+1.
		nextStep := stepIdx + 1
		if nextStep >= len(seq.Steps) {
			continue // sequence complete
		}
		if strings.HasPrefix(canonical, seq.Steps[nextStep]) {
			// Match: advance sequence.
			_ = e.store.WriteSequenceProgress(in.SessionID, in.AgentID, idx, nextStep)
			return true, seq.Name
		}
	}
	return false, ""
}

// advanceWorkflowSequence records an approved command against all matching
// workflow sequences. Called from persistLLMAllowImpl when the LLM approves.
// If the command matches step 0 of a sequence, it starts that sequence.
// If it matches a later step, it advances it (in case sequence was not started
// through Tier 2.5 but through a different tier).
func (e *Engine) advanceWorkflowSequence(in Input, canonical string) {
	if e.store == nil || in.SessionID == "" || len(e.cfg.WorkflowSequences) == 0 {
		return
	}
	for idx, seq := range e.cfg.WorkflowSequences {
		for stepIdx, step := range seq.Steps {
			if strings.HasPrefix(canonical, step) {
				// Record progress (upsert — handles both start and mid-sequence).
				_ = e.store.WriteSequenceProgress(in.SessionID, in.AgentID, idx, stepIdx)
				break
			}
		}
	}
}
