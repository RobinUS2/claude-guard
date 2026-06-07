# Plan: Dynamic/LLM-Based Stop Hook

**Created:** 2026-06-07
**Status:** Planning
**Context:** The stop hook currently runs deterministic pattern-matching rules against the
transcript. It can catch "uncommitted changes" and "open todos" but cannot understand
the semantic meaning of a session. It misses cases like "you described a plan but only
completed step 2 of 5" or "you mentioned adding tests but the file wasn't updated."
Making it LLM-backed turns it from a git-state checker into a genuine task-completion
reviewer.

---

## Current State

**How it works today:**
1. `PostStop` hook fires after every Claude turn
2. `stop.go` reads transcript JSONL, runs `stop.Evaluate()`
3. Deterministic rules check: uncommitted changes, proposed-test-not-run, open todos,
   committed-not-pushed, worktree-left-open, feature-branch-left
4. If a rule fires: injects a `userMessage` continue string
5. Session-scoped cap: max 3 continues per session; rule-scoped caps

**What it misses:**
- "You said you'd update the README but didn't"
- "You implemented the function but haven't called it from main.go"
- "Step 3 of your plan (write tests) is still pending — the code was written but tests weren't"
- Semantic completion vs mechanical completion (all commits done, but the TASK isn't)
- False positives: current rules fire even when the user deliberately stopped mid-task

---

## Design: LLM as a Tier 2 Stop Reviewer

**Position:** LLM fires ONLY when all deterministic rules return false (nothing obvious is
wrong). It's a semantic completeness check, not a replacement for the mechanical checks.

```
Deterministic rules → all pass? → LLM semantic review → inject? → continue message
                    → any fires? → inject deterministic message (skip LLM, save cost)
```

**LLM prompt input (compact, ~500 tokens):**
- Last user message (what was requested)
- Last assistant message summary (what Claude said it did)
- Last 10 Bash calls (what actually ran)
- Open todo items (from TodoWrite)
- Turn count

**LLM output (structured JSON):**
```json
{
  "complete": true | false,
  "confidence": "high" | "medium" | "low",
  "reason": "The tests were mentioned but go test was never called",
  "inject": "You described adding tests but I don't see go test in the session. Run the tests to verify.",
  "skip_reason": "Task appears complete — code written, tests run, committed"
}
```

**Inject rules:**
- `complete=false` AND `confidence=high` → inject `inject` message
- `complete=false` AND `confidence=medium` → inject if no prior LLM continues this session
- `complete=true` OR `confidence=low` → skip injection
- LLM error → fall back to deterministic-only (no injection)

---

## Cost Control

**Critical:** the stop hook runs after EVERY Claude turn. LLM calls must be rate-limited.

- Max **1 LLM stop call per session** (tracked in session state file)
- Max **2 LLM stop calls per hour** across all sessions (token-bucket rate limiter)
- Use **Haiku/Flash only** (cheapest models, ~$0.001 per call)
- Prompt hard-capped at 500 tokens (last assistant text trimmed to 200 chars, bash calls to 100 chars each)
- Timeout: **2 seconds** (stop hook must not block Claude meaningfully)
- Async write: LLM call runs after hook returns continue="" (async, fires on next turn)

**Alternative: use the existing circuit breaker** from the main engine (already shared).

---

## Prompt Design

```
You are a task-completion checker. Determine if the AI assistant's last response
represents a genuinely COMPLETE handoff to the user.

USER REQUEST (what was asked):
{first_user_text[:300]}

ASSISTANT RESPONSE (what Claude said it did):
{last_assistant_text[:300]}

ACTIONS TAKEN (bash commands run this session):
{bash_calls_summary}

OPEN TODO ITEMS:
{todo_items_summary}

Answer in JSON only:
{
  "complete": true/false,
  "confidence": "high"/"medium"/"low",
  "inject": "one sentence to inject if not complete (empty if complete)",
  "skip_reason": "why skipping injection (if complete)"
}

Only inject if you are HIGH confidence the task is incomplete AND the assistant
missed something concrete (not just 'could improve'). When in doubt: complete=true.
```

---

## Implementation

### New: `internal/stop/llm_rule.go`
```go
type LLMStopRule struct {
    classifier llm.Classifier     // Haiku or Flash
    rateLimit  *stopRateLimiter   // 1 per session, 2 per hour
}

func (r *LLMStopRule) Name() string         { return "llm-semantic-review" }
func (r *LLMStopRule) HighConfidence() bool { return true }  // only fires post-deterministic
func (r *LLMStopRule) MaxContinues() int    { return 1 }     // one LLM inject per session
func (r *LLMStopRule) TextPreFilter() string { return "" }   // always runs (after det. rules)
func (r *LLMStopRule) Eval(t Transcript, sh ShellContext) (bool, string)
```

### Modified: `cmd/claude-guard/stop.go`
- Add LLM classifier construction (same env-var lookup as main engine)
- Add LLMStopRule to the rules slice, LAST (runs only after all deterministic rules)
- Wire rate limiter (session-file + in-memory token bucket)

### New: `internal/stop/rate_limiter.go`
```go
type stopRateLimiter struct {
    sessionPath string        // tracks per-session LLM calls
    globalBucket *tokenBucket // 2 calls/hour across all sessions
}

func (r *stopRateLimiter) Allow(sessionID string) bool
```

### New: `internal/stop/llm_review_decision.go`
```go
type LLMReviewDecision struct {
    Complete   bool   `json:"complete"`
    Confidence string `json:"confidence"`
    Inject     string `json:"inject"`
    SkipReason string `json:"skip_reason"`
}

func parseDecision(raw string) (*LLMReviewDecision, error)
```

---

## Implementation Phases

- [ ] `internal/stop/llm_review_decision.go` — JSON schema + parser
- [ ] `internal/stop/rate_limiter.go` — session + global rate limiting
- [ ] `internal/stop/llm_rule.go` — LLMStopRule implementing StopRule interface
- [ ] `cmd/claude-guard/stop.go` — wire LLM classifier + rate limiter + new rule
- [ ] Tests: rate limiter, decision parser, mock-LLM rule eval
- [ ] `go test ./internal/stop/...`
- [ ] Manual verify: `echo '{}' | claude-guard stop` (no-op), then a session with open todos

---

## Files to Touch

| File | Change |
|---|---|
| `internal/stop/llm_review_decision.go` | New — JSON decision schema + parser |
| `internal/stop/rate_limiter.go` | New — per-session + global rate limiter |
| `internal/stop/llm_rule.go` | New — LLMStopRule |
| `cmd/claude-guard/stop.go` | Wire new components |

---

## Success Criteria

- LLM stop rule fires at most 1× per session, 2×/hour globally
- When deterministic rules fire, LLM is skipped (no extra cost)
- A session where Claude said "I'll add tests" but didn't → LLM injects
- A session where all todos are complete → no injection
- LLM error/timeout → graceful fallback (no injection), no hook failure

---

## Failure Routing

| Step | On failure → |
|---|---|
| LLM error | Swallow, return `(false, "")` — deterministic rules still run |
| Rate limit exceeded | Skip LLM, return `(false, "")` |
| Parse error | Treat as `complete=true`, no injection |
| Timeout (>2s) | Cancel, return `(false, "")` immediately |
