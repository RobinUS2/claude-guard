# Stop Hook Design

**Status:** Design (not implemented)
**Context:** claude-guard already gates tool calls via a PreToolUse hook. This doc designs
a complementary Stop hook that fires when Claude is about to end its turn and asks:
"did it actually finish?" If a rule fires, the hook injects a `userMessage` that
causes Claude to keep going.

---

## 1. Where it lives

### Hook registration

The existing PreToolUse hook lives in `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "*", "hooks": [{ "type": "command", "command": "/Users/robin/.claude/bin/claude-guard decide" }] }
    ],
    "Stop": [
      { "matcher": "", "hooks": [{ "type": "command", "command": "/Users/robin/.claude/bin/claude-guard stop" }] }
    ]
  }
}
```

`matcher` is empty string for Stop hooks (there's nothing to match against at the
hook-registration level — selection happens inside the command itself).

### New subcommand: `cmd/claude-guard/stop.go`

`cmdStop` mirrors `cmdDecide`: reads JSON from stdin, writes JSON to stdout, exits 0.

```
cmd/claude-guard/
  decide.go         (PreToolUse — existing)
  stop.go           (Stop — new)
  main.go           (add "stop" to dispatch)

internal/stop/
  stop.go           (StopRule interface, evaluator)
  rules.go          (default rule set)
  session.go        (per-session state: continue counter, fired rules)
  shell.go          (ShellContext: cached subprocess runner with timeout)
```

`main.go` dispatch already has the pattern — add one case:

```go
case "stop":
    os.Exit(cmdStop(args[1:]))
```

---

## 2. Decision model

### Inputs

Claude Code sends this JSON on stdin when the Stop hook fires:

```json
{
  "session_id": "abc123",
  "stop_hook_active": false,
  "transcript": [
    { "role": "user",      "content": "push, merge, install" },
    { "role": "assistant", "content": [{ "type": "text", "text": "Done, all pushed." }] },
    { "role": "tool",      "tool_use_id": "...", "content": "..." }
  ]
}
```

`stop_hook_active` is the loop-prevention signal from Claude Code itself: `true` means
this turn was *already triggered by a previous stop hook continue*.

**Session ID fallback:** If `session_id` is empty or absent, derive a stable key from
the SHA-256 of the first user message content (first 32 bytes of hex). This lets the
per-session counter work even without a platform-provided ID.

### What we can extract

| Source | How |
|--------|-----|
| Claude's last assistant message (text) | Walk transcript in reverse, find last `role=assistant`, join text blocks |
| All Bash calls in session | Filter transcript for tool-use blocks with tool name `Bash` |
| First user message | First `role=user` item — used for `require_in_first_message` scoping |
| Shell state | Subprocesses via `ShellContext` (cached, timeout-gated) |
| Guard's own log | `decisions.jsonl` filtered by session_id (optional enrichment) |

### What we cannot see

- **Tool output content easily**: It's in the transcript but each tool has its own JSON
  shape; parsing it generically is fragile. Prefer re-running shell checks directly.
- **Subagent boundaries**: The transcript doesn't distinguish an outer agent from a
  subagent dispatch. Use `require_in_first_message` to scope rules to sessions where
  the user explicitly requested the action.
- **Real-time file changes**: The hook sees what Claude *said*, not what changed on
  disk. Always verify with shell checks.

### Rule interface

```go
// StopRule evaluates whether Claude's turn is truly complete.
// Return (true, reason) to inject a continue message; (false, "") to let it stop.
type StopRule interface {
    Name() string
    // HighConfidence marks rules that may fire even when stop_hook_active is true.
    // Only shell-verified rules (not text-only matches) should return true.
    HighConfidence() bool
    // TextPreFilter returns a regex that the last assistant message must match
    // before any shell check runs. Returning "" skips text pre-filtering.
    // This is the primary performance gate: shell checks never run unless
    // the text pre-filter already matched.
    TextPreFilter() string
    // Eval is only called when TextPreFilter matched (or returned "").
    // sh is a cached, timeout-gated shell runner — call sh.Run("git status --short")
    // without worrying about duplicate subprocess invocations.
    Eval(t Transcript, sh ShellContext) (shouldContinue bool, reason string)
}
```

**Critical performance invariant:** `Eval` (and any shell check within it) is only
called after `TextPreFilter` matches. This ensures the hook exits in < 1ms for the
vast majority of turns where no text pattern triggers.

### ShellContext

```go
type ShellContext interface {
    // Run executes cmd via sh -c with the configured timeout (default 500ms).
    // Results are cached within a single Stop evaluation — two rules calling
    // "git status --short" only spawn one subprocess.
    Run(cmd string) (stdout string, err error)
}
```

Timeout is configurable via `.claude-guard.yml`:
```yaml
stop_hook:
  shell_timeout_ms: 500   # default
```

### Response

```go
type StopResponse struct {
    UserMessage string `json:"userMessage,omitempty"`
}
```

Empty `UserMessage` + exit 0 = let Claude stop.
Non-empty `UserMessage` = inject into Claude's conversation and continue.

### Log event

Every Stop hook evaluation appends one event to `decisions.jsonl`:

```json
{
  "time": "2026-04-19T10:00:00Z",
  "msg": "stop_hook",
  "session_id": "abc123",
  "stop_hook_active": false,
  "fired_rule": "uncommitted-changes",
  "injected": true,
  "continue_count": 1,
  "latency_us": 42000
}
```

`fired_rule` is `""` and `injected` is `false` when the hook lets Claude stop cleanly.
This lets `claude-guard stats` report: `stop hooks: 47 evaluations, 5 continues injected`.

---

## 3. Concrete rules (starter set)

### Rule 1: `uncommitted-changes`

**What it catches:** Claude says "done" / "all set" / "complete" but `git status`
shows staged or unstaged changes.

**Grounded in logs:** In the BQ budget session, the push succeeded but the merge was
blocked by the guard. Claude stopped at "pushed" without completing the merge —
`git status` would have shown 3 locally modified files.

```
TextPreFilter: \b(done|complete|finished|all set|pushed|merged|shipped)\b
ShellCheck:    git status --short
Fire when:     shell output is non-empty
HighConfidence: true (shell-verified)
```

Message:
```
There are uncommitted or staged changes in this repo:
{shell_output}
Please commit, stash, or explain why these should stay as-is before finishing.
```

### Rule 2: `proposed-test-not-run`

**What it catches:** Claude's message mentions a test command in prose or code, but
no Bash tool call in the session executed it.

**Grounded in logs:** A common pattern — Claude proposes verification in text but the
session ends without running it. Seen after the BQ budget changes: test plan described
in PR description, no final `go test ./...` confirmation in tool calls.

```
TextPreFilter: \b(go test|npm test|make test|pytest|cargo test)\b
TranscriptCheck: no Bash call matching \b(go test|npm test|make test|pytest|cargo test)\b
HighConfidence: false (text-only — suppress when stop_hook_active)
```

Note: the text pre-filter is intentionally broad (prose + code mentions). The
transcript check confirms none ran — no shell check needed.

### Rule 3: `install-not-run`

**What it catches:** The user's original message mentioned "install" / "make install"
but no such Bash call appears in this session.

**Grounded in logs:** The BQ budget task explicitly asked "commit, push, install" —
the session ended after push without reaching `make install`.

```
TextPreFilter: \b(install|make install)\b        (on last assistant message)
require_in_first_message: \b(install|make install)\b  (user must have asked for it)
TranscriptCheck: no Bash call matching make install
HighConfidence: false
```

The `require_in_first_message` check gates the rule to sessions where the user
explicitly asked for install — prevents misfires from subagent turns.

### Rule 4: `open-todo-items`

**What it catches:** A `TodoWrite` call appears in the session transcript with items
still in `pending` or `in_progress` state at session end.

```
TextPreFilter: ""  (always runs transcript check — fast, no shell)
TranscriptCheck: last TodoWrite call has incomplete items
HighConfidence: true (transcript-verified)
```

### Rule 5: `pr-created-not-verified`

**What it catches:** `gh pr create` ran in session but no subsequent CI check
(`gh pr checks`, `gh pr view`) occurred.

```
TextPreFilter: ""  (transcript check only)
TranscriptCheck: Bash call with "gh pr create" exists AND no later Bash call
                 matching (gh pr checks|gh pr view|gh pr status)
HighConfidence: false
```

---

## 4. Failure modes and loop prevention

### The loop

Hook fires → injects message → Claude does something → stops → hook fires again →
... → infinite session.

### Three-layer defence

**Layer 1: Platform signal** (`stop_hook_active`)
When `stop_hook_active: true`, only rules with `HighConfidence() == true` may fire,
and only if the session continue count < 2 (not 3). Text-only rules are suppressed.

**Layer 2: Per-session counter** (`internal/stop/session.go`)
State file at `/tmp/claude-guard-stop-<session_key>.json`:
```json
{ "continues": 2, "fired": ["uncommitted-changes", "install-not-run"] }
```
Hard cap: **3 continues per session**, then always return empty (let Claude stop).
Counter increments every time the hook injects a message. When the cap is hit, log:
```json
{ "msg": "stop_hook", "injected": false, "suppressed": "max_continues_reached" }
```

**Layer 3: Rule cool-down**
Once a rule fires in a session, mark it fired. Don't re-fire unless the shell-check
output hash has changed (e.g. `git status` now returns different output = changes
were committed). This prevents looping on a rule the user is deliberately ignoring.

### Fast disable

1. **Env var**: `CLAUDE_GUARD_STOP_DISABLED=1` — hook exits immediately with no output.
2. **Per-rule config**:
   ```yaml
   stop_hook:
     rules:
       uncommitted-changes:
         enabled: false
   ```
3. **Nuclear**: Remove the `"Stop"` entry from `~/.claude/settings.json`. `claude-guard doctor` will warn; the PreToolUse gate is unaffected.

---

## 5. Config surface

### Per-project (`.claude-guard.yml`)

```yaml
stop_hook:
  shell_timeout_ms: 500   # default

  rules:
    install-not-run:
      enabled: false    # this project deploys via CI, not local make install

    custom:
      - name: migration-not-applied
        text_pre_filter: '\b(migration|migrate)\b'
        shell_check: "cat .migration-pending 2>/dev/null"
        shell_nonempty: true
        high_confidence: true
        message: "A migration was mentioned. Run `make db-migrate` before finishing."
```

### Global (`~/.config/claude-guard/stop-rules.yaml`)

Same format. Merged before per-project config; per-project wins on conflicts.

---

## 6. Relationship to the existing allow/deny layer

The two hook types are **orthogonal**:

| Hook | Fires | Verdict | Acts on |
|------|-------|---------|---------|
| `PreToolUse` | Before each tool call | Allow / Deny / Continue | Individual tool use |
| `Stop` | When Claude ends its turn | Continue / (stop) | The entire turn |

The Stop hook does **not** use the engine's tier pipeline (instant_allow, LLM, etc.).
It has its own `StopRule` interface and a simpler two-outcome model: inject a message
or don't.

Shared infrastructure:
- Config loading (`internal/config`) — reads the same `.claude-guard.yml`
- Logging (`internal/log`) — appends stop_hook events to `decisions.jsonl`
- Version / doctor checks

Not shared:
- The `Engine` (PreToolUse only)
- The cache / LLM tier (Stop rules are deterministic — text + shell checks)
- The budget tracker (not applicable here)

`claude-guard stats` output gains a new section:
```
stop hooks (last 24h):
  evaluations: 47
  continues injected: 5  (10.6%)
  max-continue cap hit: 0
  top rules: uncommitted-changes=3  open-todo-items=2
```

---

## 7. API limits and open questions

| Limit | Impact | Mitigation |
|-------|--------|------------|
| `stop_hook_active` is platform's only loop-break | Can still loop within the 3-continue budget | Per-session cool-down (layer 3) |
| Transcript tool-output shape varies per tool | Parsing Bash output to verify "tests passed" is fragile | Re-run shell checks rather than parsing transcript output |
| No session_id in PreToolUse payload | Can't correlate guard's allow/deny history with a stop session | Would require guard to write a side-channel file during PreToolUse |
| Stop hook fires on subagent turns | `install-not-run` could fire mid-plan when a subagent stops | `require_in_first_message` scopes rule to sessions where user asked for it |
| Hook total latency budget unknown | If all 5 shell checks run at 500ms, worst case = 2.5s | Text pre-filter ensures shell checks only run on matching turns; typical exit < 1ms |
| `stop_hook_active` may not be set reliably in all CC versions | Layer 1 loop prevention may be absent | Rely on layers 2+3 as primary; layer 1 is a bonus |

---

## 8. Implementation order

1. `internal/stop/shell.go` — `ShellContext` with timeout + result cache
2. `internal/stop/session.go` — per-session state file (counter + fired-rules)
3. `internal/stop/stop.go` — `StopRule` interface + evaluator (fast-path: text pre-filter before shell)
4. `internal/stop/rules.go` — Rules 1 and 4 (`uncommitted-changes`, `open-todo-items`)
5. `cmd/claude-guard/stop.go` — stdin parse → evaluate → stdout response
6. `claude-guard stats` update — stop_hook section in aggregation
7. Hook registration in `~/.claude/settings.json`
8. `claude-guard doctor` update — verify Stop hook is registered
9. Rules 2, 3, 5 + custom-rules config support
10. `internal/log` — stop_hook event format (feeds item 6)

Note: logging (item 6/10) and stats are wired *before* hook registration (item 7)
so the first real firings are immediately observable in `claude-guard stats`.
