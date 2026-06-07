# Plan: Session-Aware Approval — Reduce User Interruptions

**Created:** 2026-06-07
**Status:** Planning
**Context:** The guard has `session_id` on every hook call but never uses it in approval logic. Within a single Claude Code session the user sees repetitive prompts for commands they've already approved or that are logical follow-ups to approved work. This plan designs a session-scoped trust layer to eliminate that friction.

---

## Problem

**Current pipeline:** Tier 1 (block) → Tier 2 (allow, static) → Cache (global/project) → LLM → Legacy → Tier 6 (Continue → user prompt)

Session ID is logged and stored in `pending_approvals` but plays no role in any approval decision. That means:

- `git add README.md` approved at 10:00 → `git add src/main.go` at 10:05 still prompts
- LLM classified `go test ./...` as safe → `go test ./internal/...` still goes to LLM
- User clicks "Allow" → only the PostToolUse learn hook fires; next session still starts cold
- Subagents (Explore, plan executor) all prompt independently, even when the parent approved the same commands moments ago

**Goal:** Within a session, once something is established as safe (by LLM or user), similar/follow-up commands should auto-approve without prompting.

---

## What Already Exists (Don't Re-Invent)

| Component | Location | Current role |
|---|---|---|
| `session_id` in every hook | `internal/hook/hook.go:19` | Logged only |
| `pending_approvals` SQLite table | `internal/store/store.go:163` | Tracks Continue verdicts; has `session_id` |
| PostToolUse `learn.go` | `cmd/claude-guard/learn.go` | Writes cache entry on user approval; no session scope |
| Canonical form normalization | `internal/normalize/` | `git commit -m "foo"` → `git commit -m {MESSAGE}` |
| Session state file | `internal/stop/session.go` | Tracks `continues` count, fired rules — NOT approval state |
| Verdict cache (SQLite) | `internal/store/store.go` | Global / project-scoped; 90-day TTL LLM verdicts |
| LLM `ClassifyInput` | `internal/llm/` | Has `Command`, `Description`, `CWD` — no session history |
| `approval_count` column in `verdicts` | `internal/store/store.go:149` | Reserved but unused |

---

## Five Mechanisms (ordered by impact × implementation cost)

### Mechanism 1: Session-Scoped Cache Tier (Tier 2.5)
**"Approved once this session → instant-allow for the rest of the session"**

**How it works:**
1. New SQLite table: `session_approvals (session_id, canonical_key, approved_at, source)`
2. Written when: (a) Tier 3/4 approves something, or (b) user manually approves (learn hook)
3. New Tier 2.5 lookup in engine, after static Tier 2 but before the global cache:
   - Key = `hash(session_id + canonical_form_of_command)`
   - Hit → instant Allow; no LLM call, no latency
4. Session TTL: 8 hours (covers a full workday); auto-expiry via `approved_at`

**Engine change:** One new `for attempt` block in `Decide()` using `in.SessionID`. Minimal diff — mirrors the existing global/project cache attempt loop.

**Why first:** Biggest single reduction in repeat prompts. Zero LLM cost for repeated commands. Session boundary is safe — next session starts clean.

**Risk:** If a command was conditionally approved (LLM said "safe in this context"), session-cache would re-approve it in a different context later that session. Mitigation: only session-cache entries that were globally scoped by the LLM, or that have `source=user`.

---

### Mechanism 2: PostToolUse → Session Promotion (extend learn.go)
**"User clicks Allow → rest of session never asks again for that pattern"**

**Current learn.go:** writes to project/global cache (keyed on canonical form, no session). After 3 approvals, promotes to global. Session has no accelerated path.

**Change:**
1. In `cmdLearn()`, after writing to project cache, also write to `session_approvals`
2. Session entry is immediate (no 3-approval threshold) — it's session-scoped so the blast radius is one session
3. Use the canonical form already computed in `learn.go` (line 92-93)

**Why second:** Builds on existing learn hook with minimal new code. User approval is the strongest possible trust signal — should take effect immediately within the session.

---

### Mechanism 3: LLM Session Context Injection
**"The LLM knows what Claude has already been approved to do this session"**

**How it works:**
1. In `engine.go::runLLMTier()`, before the LLM call, query `session_approvals` for the last N (max 10) approved canonical forms for this session
2. Inject into `ClassifyInput` as a new `SessionContext []string` field
3. In the LLM system prompt: "This session has already approved: `go build ./...`, `go test ./...`. If the current command is consistent with this workflow, lean toward safe."

**Why this reduces prompts:** The LLM currently has no session context. It sees `go vet ./...` cold and may hesitate. With context it reasons: "user is clearly doing a Go dev cycle, vet is consistent, safe."

**Cost:** One extra SQLite query per LLM call (~1ms). Prompt grows by ~200 chars. Worth it for ambiguous commands.

**Risk:** LLM may over-rely on session context and approve something genuinely new. Mitigate: session context is framed as "context for reasoning", not "permission granted".

---

### Mechanism 4: Logical Follow-Up Workflow Sequences
**"Approved step N → auto-allow steps N+1 through N+k of known sequences"**

**Known sequences to hard-code (Tier 2.5.5):**

```go
var workflowSequences = [][]string{
    {"go build ./...", "go test ./...", "go vet ./...", "go install ./..."},
    {"make build", "make test", "make install", "make lint"},
    {"git add {PATH}", "git commit -m {MESSAGE}", "git push"},
    {"npm install", "npm run build", "npm test", "npm run lint"},
    {"cargo build", "cargo test", "cargo clippy"},
    {"terraform plan", "terraform apply"},
    {"docker build {FLAGS}", "docker run {FLAGS}"},
}
```

**How it works:**
1. Maintain `session_sequence_progress (session_id, sequence_idx, step_idx, last_updated)` in SQLite
2. When a command is approved, check if it matches any sequence step; if yes, record position
3. When next command arrives, check if it's the next step of an in-progress sequence → instant Allow
4. Sequence expires if next step doesn't arrive within 10 minutes (workflow abandoned)

**Why fourth:** More complex than the cache tiers but covers cases where commands aren't identical but are semantically linked. Eliminates the most common "you JUST did X, why ask about Y" pattern.

---

### Mechanism 5: Agent-Type Trust Profile
**"Explore agents and known safe agent types get a broader session allow list"**

**How it works:**
1. Claude Code sends `agent_type` (e.g., `"Explore"`, `"claude-code-guide"`) in the hook input
2. Define per-agent-type trust profiles in config:
   ```go
   AgentTrustProfiles = map[string][]string{
       "Explore": {"find", "grep", "cat", "ls", "git log", "git diff", "git show"},
   }
   ```
3. In Tier 2, after the static allow list, check agent-type profile
4. Only applies when `agent_id != ""` (i.e., actually a subagent, not the main session)

**Why last:** Useful but narrower. Explore agents have a known read-only profile. This is essentially a smarter version of the static Tier 2 allow list that activates based on who's asking.

---

## Implementation Phases

### Phase 1: Session Cache Foundation (1-2 days)
- [ ] Add `session_approvals` table to `store.go` (schema migration, CRUD)
- [ ] Add `SessionKey(sessionID, canonicalCommand)` function to `cache/`
- [ ] Add Tier 2.5 lookup in `engine.go::Decide()` — check session table before global cache
- [ ] Write to session table in `persistLLMAllow()` (after LLM approves)
- [ ] Tests: session hit/miss, TTL expiry, session isolation between sessions
- [ ] Add `session` tier label to decision log records

### Phase 2: PostToolUse Session Promotion (0.5 days)
- [ ] In `learn.go::cmdLearnWithIO()`, after writing project cache, also write to `session_approvals`
- [ ] User-approved entries skip the canonical normalization step (exact command gets session-cached)
- [ ] Test: approve command → verify session table entry → next call hits session tier

### Phase 3: LLM Session Context (1 day)
- [ ] Add `SessionContext []string` to `llm.ClassifyInput`
- [ ] Query `session_approvals` for last 10 canonical forms in `runLLMTier()`
- [ ] Add session context block to LLM system prompt (capped at 500 chars)
- [ ] Test: verify prompt includes session context, verify LLM is less likely to hesitate on follow-ups

### Phase 4: Workflow Sequence Detection (1-2 days)
- [ ] Define `workflowSequences` in `internal/config/defaults.go`
- [ ] Add `session_sequence_progress` table to `store.go`
- [ ] Add sequence-progression logic in engine — updates on Allow, checks on new command
- [ ] Sequence expiry: 10-minute inactivity timeout
- [ ] Test: go build → go test → auto-approved; 11-minute gap resets

### Phase 5: Agent-Type Trust Profiles (0.5 days)
- [ ] Define `AgentTrustProfiles` in config
- [ ] Add agent-type check in Tier 2 (after project config allow rules)
- [ ] Test: Explore agent gets find/grep/ls without LLM; non-Explore doesn't

---

## Schema Changes (store.go, schemaVersion bump to 2)

```sql
CREATE TABLE IF NOT EXISTS session_approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    canonical_key TEXT NOT NULL,     -- hash used for lookup
    canonical_form TEXT,             -- human-readable, for debugging
    command TEXT,                    -- first concrete command that produced this entry
    source TEXT NOT NULL,            -- "llm", "user", "workflow"
    approved_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,        -- approved_at + 8h
    UNIQUE(session_id, canonical_key)
);
CREATE INDEX IF NOT EXISTS idx_session_approvals_lookup
    ON session_approvals(session_id, canonical_key);
CREATE INDEX IF NOT EXISTS idx_session_approvals_expiry
    ON session_approvals(expires_at);

CREATE TABLE IF NOT EXISTS session_sequence_progress (
    session_id TEXT NOT NULL,
    sequence_idx INTEGER NOT NULL,   -- index into workflowSequences
    step_idx INTEGER NOT NULL,       -- last approved step in this sequence
    last_updated TEXT NOT NULL,
    PRIMARY KEY (session_id, sequence_idx)
);
```

---

## Success Metrics

| Metric | Current | Target |
|---|---|---|
| `continue` verdicts per session | ~40% of tool calls | <15% |
| LLM calls per session | N | N × 0.4 (60% cache/session hit) |
| User "Allow" clicks per session | Measure baseline first | -50% within session |
| Session cache hit rate | 0% | >30% by Phase 2 |
| `learned` verdict auto-allows | Slow (3-approval global) | Fast (1-approval session) |

**Measurement:** `claude-guard stats --session <id>` should break down by tier including new `session` tier. Dashboard (`claude-guard dashboard`) adds session interrupt rate trend.

---

## Failure Routing

| Phase | On failure → |
|---|---|
| Phase 1 schema migration fails | Abort; guard falls back to current behavior (no session table) |
| Phase 1 session lookup error | Swallow, fall through to global cache — same as today |
| Phase 3 LLM context query fails | Skip context injection, send prompt without it |
| Phase 4 sequence step mismatch | Fall through; no harm, no auto-allow |

---

## Open Questions

1. **Session TTL**: 8 hours covers a workday but what about long-running sessions (overnight, `--continue`)? Should TTL be session-lifetime or clock-based?
2. **Cross-agent scope**: Should a subagent's approved commands count for the main session's session cache? Current proposal: yes (they share `session_id`), which is what the user probably wants.
3. **Revocation**: If user explicitly denies a command mid-session, should that block the session cache for that pattern? Current proposal: yes — explicit deny writes a `deny` entry to `session_approvals` that overrides any previous allow.
4. **Schema version bump**: Existing deployments need a smooth migration path. Adding tables to existing DB works in SQLite without a breaking change.

---

## Files to Touch

| File | Change |
|---|---|
| `internal/store/store.go` | Add tables, CRUD for `session_approvals` + `session_sequence_progress`; bump schemaVersion to 2 |
| `internal/cache/cache.go` | Add `SessionKey(sessionID, canonicalCmd) string` |
| `internal/engine/engine.go` | Add Tier 2.5 session-cache lookup; inject session context before LLM; write to session table on approve |
| `internal/llm/llm.go` (or types) | Add `SessionContext []string` to `ClassifyInput` |
| `cmd/claude-guard/learn.go` | Write to `session_approvals` on PostToolUse user approval |
| `internal/config/defaults.go` | Add `workflowSequences`, `AgentTrustProfiles` |
| `testdata/bash_allow.txt` | Session-tier test cases |
| `internal/store/store_test.go` | Session table tests |
| `internal/engine/engine_test.go` | Session tier integration tests |

---

## References

- Engine pipeline: `internal/engine/engine.go:363` (Decide function)
- Session state (stop hook): `internal/stop/session.go`
- Learn hook: `cmd/claude-guard/learn.go`
- Store schema: `internal/store/store.go:108`
- Cache key inputs: `internal/cache/cache.go:143`
