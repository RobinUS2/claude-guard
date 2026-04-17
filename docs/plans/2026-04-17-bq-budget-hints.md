# BQ Budget Gating + Auto-Allow Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `go build`/`go test`/`go run` to instant-allow, gate real BigQuery queries behind a pre-flight dry-run with byte-budget tracking, and inject contextual hints back into Claude's conversation when queries are intercepted.

**Architecture:** Three new/extended packages (`internal/budget/bq.go`, `internal/engine/bq.go`, extended `internal/hook/`) plus small additions to existing rules and config. The BQ path runs as a special pre-flight tier between tier 2 (instant-allow) and tier 3 (cache): it spawns `bq query --dry_run` as a subprocess, parses the estimated bytes, checks a daily rolling ledger, and either allows (with a byte-count hint injected via `userMessage`) or falls through to the user prompt with a rewrite suggestion. The `userMessage` field is wired into the Claude Code hook protocol's top-level JSON, which injects text directly into Claude's conversation — this is how we hint Claude to rewrite queries or report costs without blocking the user interface.

**Tech Stack:** Go, `os/exec` for dry-run subprocess, JSON file-based budget ledger, Claude Code `userMessage` hook protocol field.

**Out of scope (separate plans):** `PipedReadonly` rule type, `PostToolUse` hook for actual bytes-billed tracking.

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `internal/engine/engine.go` | Modify | Add MCP allow-list check; add `UserMessage` to `Output` |
| `internal/engine/engine_test.go` | Modify | MCP allow tests + BQ pre-flight integration tests |
| `internal/rules/rules.go` | Modify | Add `RequireFlags []string` to `AnchoredCommand` |
| `internal/rules/rules_test.go` | Modify | Test `RequireFlags` matching |
| `internal/hook/hook.go` | Modify | Add `UserMessage string` to `Response` |
| `internal/hook/hook_test.go` | Modify | Test `userMessage` serialization |
| `internal/budget/bq.go` | **Create** | Rolling daily BQ bytes budget (JSONL ledger) |
| `internal/budget/bq_test.go` | **Create** | Budget check/record/status tests |
| `internal/engine/bq.go` | **Create** | BQ pre-flight: detection, dry-run subprocess, bytes parser |
| `internal/engine/bq_test.go` | **Create** | BQ engine unit tests (stubbed subprocess) |
| `cmd/claude-guard/decide.go` | Modify | Pass `out.UserMessage` to `hook.Response` |
| `cmd/claude-guard/stats.go` | Modify | Add hit-rate + time-saved display |
| `internal/config/defaults.go` | Modify | go-readonly fix; bq-dry-run rules; remove `query` from bq-readonly |

## Failure Routing

| Phase | On Failure → |
|---|---|
| Task 0 (MCP allow-list) | ABORT — high volume, should ship first |
| Task 1-2 (rules/hook) | ABORT — foundation, nothing builds without them |
| Task 3 (budget) | Skip budget check, still run dry-run hint |
| Task 4 (engine BQ) | Fall through to LLM tier (no regression, same as today) |
| Task 5 (config) | Revert defaults change, keep existing bq-readonly as-is |
| Task 8 (stats) | Ship without, add in follow-up |

---

## Task 0: MCP tool call allow-list

**Files:**
- Modify: `internal/engine/engine.go` — add MCP allow-list check in `decideGeneric`
- Modify: `internal/engine/engine_test.go` — MCP allow tests

Every MCP tool call currently hits `decideGeneric()` which sends it to the LLM. The LLM returns "unsure" because the prompt is written for Bash commands. This generates a user prompt for every single MCP call. Given that gdrive, google-calendar, computer-use, and Claude Preview are active in every session, this is the highest-volume prompt gap in the system.

Fix: check the tool name against a hardcoded allow-list of known read-only MCP tools **before** calling the LLM. No new rule type needed — just a slice of allowed tool name prefixes inside `decideGeneric`.

- [ ] **Step 1: Write failing tests**

Add to `internal/engine/engine_test.go`:

```go
func TestMCPReadonlyAllowList(t *testing.T) {
    eng := engine.New(config.Default(), nil)
    allowed := []string{
        "mcp__gdrive__gdrive_list_files",
        "mcp__gdrive__gdrive_read_file",
        "mcp__gdrive__gdrive_get_file",
        "mcp__gdrive__gdrive_get_document_info",
        "mcp__gdrive__gdrive_get_spreadsheet_info",
        "mcp__gdrive__gdrive_search",
        "mcp__google-calendar__list-events",
        "mcp__google-calendar__get-event",
        "mcp__google-calendar__list-calendars",
        "mcp__google-calendar__get-freebusy",
        "mcp__google-calendar__get-current-time",
        "mcp__Claude_Preview__preview_screenshot",
        "mcp__Claude_Preview__preview_list",
        "mcp__Claude_Preview__preview_logs",
        "mcp__Claude_Preview__preview_console_logs",
        "mcp__Claude_Preview__preview_network",
        "mcp__Claude_Preview__preview_snapshot",
        "mcp__computer-use__screenshot",
        "mcp__computer-use__cursor_position",
        "mcp__computer-use__list_granted_applications",
    }
    for _, toolName := range allowed {
        out := eng.Decide(engine.Input{ToolName: toolName, Command: "MCP tool call (not bash) " + toolName + ": {}"})
        if out.Verdict != engine.Allow {
            t.Errorf("tool=%s: got %v (tier=%s), want Allow", toolName, out.Verdict, out.Tier)
        }
        if out.Tier != "instant_allow" {
            t.Errorf("tool=%s: tier=%s, want instant_allow", toolName, out.Tier)
        }
    }
    // Write/mutating tools must NOT be in the allow list
    blocked := []string{
        "mcp__gdrive__gdrive_create_doc",
        "mcp__gdrive__gdrive_update_sheet",
        "mcp__gdrive__gdrive_delete_rows_columns",
        "mcp__computer-use__left_click",
        "mcp__computer-use__type",
    }
    for _, toolName := range blocked {
        out := eng.Decide(engine.Input{ToolName: toolName, Command: "MCP tool call (not bash) " + toolName + ": {}"})
        if out.Verdict == engine.Allow && out.Tier == "instant_allow" {
            t.Errorf("tool=%s: should NOT be instant_allow (mutating tool)", toolName)
        }
    }
}
```

- [ ] **Step 2: Run test — expect FAIL**

```bash
go test ./internal/engine/... -run TestMCPReadonlyAllowList -v
```

Expected: all allowed tools return `Continue` (fall through), not `Allow`.

- [ ] **Step 3: Add MCP allow-list to `decideGeneric`**

In `internal/engine/engine.go`, find `decideGeneric` (or add it if it only exists as a stub). Before the LLM call, add:

```go
// mcpReadonlyTools is the allow-list of MCP tool names that are
// unconditionally safe to auto-approve. These are read-only operations
// on known services (GDrive, Calendar, Preview, computer screenshot).
// Naming convention: mcp__<server>__<tool>. Only exact matches allowed —
// no prefix wildcards to avoid accidentally approving write variants.
var mcpReadonlyTools = map[string]struct{}{
    // Google Drive — read only
    "mcp__gdrive__gdrive_list_files":           {},
    "mcp__gdrive__gdrive_read_file":            {},
    "mcp__gdrive__gdrive_get_file":             {},
    "mcp__gdrive__gdrive_get_document_info":    {},
    "mcp__gdrive__gdrive_get_spreadsheet_info": {},
    "mcp__gdrive__gdrive_search":               {},
    // Google Calendar — read only
    "mcp__google-calendar__list-events":      {},
    "mcp__google-calendar__get-event":        {},
    "mcp__google-calendar__list-calendars":   {},
    "mcp__google-calendar__get-freebusy":     {},
    "mcp__google-calendar__get-current-time": {},
    // Claude Preview — observation only (no click/type)
    "mcp__Claude_Preview__preview_screenshot":    {},
    "mcp__Claude_Preview__preview_list":          {},
    "mcp__Claude_Preview__preview_logs":          {},
    "mcp__Claude_Preview__preview_console_logs":  {},
    "mcp__Claude_Preview__preview_network":       {},
    "mcp__Claude_Preview__preview_snapshot":      {},
    // Computer use — observation only (no click/type/key)
    "mcp__computer-use__screenshot":               {},
    "mcp__computer-use__cursor_position":          {},
    "mcp__computer-use__list_granted_applications":{},
}
```

In `decideGeneric` (wherever it is in `engine.go`), add the check at the top of the function:

```go
func (e *Engine) decideGeneric(in Input, start time.Time) Output {
    // Fast path: known read-only MCP tools bypass the LLM entirely.
    if _, ok := mcpReadonlyTools[in.ToolName]; ok {
        out := Output{
            Verdict: Allow,
            Tier:    "instant_allow",
            Rule:    "mcp-readonly",
            Reason:  "known read-only MCP tool",
            Latency: time.Since(start),
        }
        e.record(in, out)
        return out
    }
    // ... rest of existing decideGeneric logic ...
}
```

- [ ] **Step 4: Run test — expect PASS**

```bash
go test ./internal/engine/... -run TestMCPReadonlyAllowList -v
```

- [ ] **Step 5: Run full suite**

```bash
go test ./... 2>&1 | tail -20
```

- [ ] **Step 6: Commit**

```bash
git add internal/engine/engine.go internal/engine/engine_test.go
git commit -m "engine: add MCP read-only allow-list (gdrive, calendar, preview, computer-use screenshot)"
```

---

## Task 1: `go-readonly` quick fix

**Files:**
- Modify: `internal/config/defaults.go` (lines ~470-475)
- Test: `internal/engine/engine_test.go` (or golden test file)

This is the smallest change in the plan and should ship first — it has zero dependencies.

- [ ] **Step 1: Write failing test**

Add to `internal/engine/engine_test.go` (find the existing instant-allow test block and add alongside it):

```go
func TestGoBuiltinCommands(t *testing.T) {
    tests := []struct {
        cmd  string
        want engine.Verdict
    }{
        {"go build ./...", engine.Allow},
        {"go test ./...", engine.Allow},
        {"go run main.go", engine.Allow},
        {"go test -exec=/tmp/evil ./...", engine.Continue}, // -exec must be blocked
        {"go install .", engine.Continue},                  // install not in list
    }
    eng := engine.New(config.Default(), nil)
    for _, tt := range tests {
        out := eng.Decide(engine.Input{ToolName: "Bash", Command: tt.cmd})
        if out.Verdict != tt.want {
            t.Errorf("cmd=%q: got %v, want %v (tier=%s rule=%s)",
                tt.cmd, out.Verdict, tt.want, out.Tier, out.Rule)
        }
    }
}
```

- [ ] **Step 2: Run test — expect FAIL**

```bash
cd /Users/robin/Documents/code/claude-guard
go test ./internal/engine/... -run TestGoBuiltinCommands -v
```

Expected: `go build ./...` and `go test ./...` return `Continue`, not `Allow`.

- [ ] **Step 3: Update `defaults.go`**

Find `goReadonly` (around line 471) and change:

```go
// BEFORE
goReadonly := &rules.AnchoredCommand{
    RuleName:         "go-readonly",
    Programs:         []string{"go"},
    RequireSubcmdAny: []string{"version", "env", "list", "vet", "fmt", "doc", "help"},
}

// AFTER
goReadonly := &rules.AnchoredCommand{
    RuleName:         "go-readonly",
    Programs:         []string{"go"},
    RequireSubcmdAny: []string{"version", "env", "list", "vet", "fmt", "doc", "help",
        "build", "test", "run"},
    ForbidFlags: []string{"-exec"}, // go test -exec=<binary> overrides test runner
}
```

- [ ] **Step 4: Run test — expect PASS**

```bash
go test ./internal/engine/... -run TestGoBuiltinCommands -v
```

Expected: all cases pass.

- [ ] **Step 5: Run full test suite**

```bash
go test ./... 2>&1 | tail -20
```

Expected: no regressions.

- [ ] **Step 6: Commit**

```bash
git add internal/config/defaults.go internal/engine/engine_test.go
git commit -m "config: add go build/test/run to go-readonly, forbid -exec"
```

---

## Task 2: Add `RequireFlags` to `AnchoredCommand`

**Files:**
- Modify: `internal/rules/rules.go` (AnchoredCommand struct + Eval)
- Modify: `internal/rules/rules_test.go`

`RequireFlags` makes a tier-2 rule match only when all listed flags are present. Used to create a separate `bq-dry-run` rule that only fires on `bq query --dry_run`.

- [ ] **Step 1: Write failing test**

Add to `internal/rules/rules_test.go`:

```go
func TestAnchoredCommandRequireFlags(t *testing.T) {
    ruleUnderscore := &AnchoredCommand{
        RuleName:         "bq-dry-run",
        Programs:         []string{"bq"},
        RequireSubcmdAny: []string{"query"},
        RequireFlags:     []string{"--dry_run"},
    }
    ruleHyphen := &AnchoredCommand{
        RuleName:         "bq-dry-run-hyphen",
        Programs:         []string{"bq"},
        RequireSubcmdAny: []string{"query"},
        RequireFlags:     []string{"--dry-run"},
    }
    tests := []struct {
        rule *AnchoredCommand
        cmd  string
        want Verdict
    }{
        {ruleUnderscore, "bq query --dry_run --nouse_legacy_sql 'SELECT 1'", Match},
        {ruleUnderscore, "bq query --nouse_legacy_sql 'SELECT 1'", NoMatch}, // missing --dry_run
        {ruleUnderscore, "bq query", NoMatch},                               // missing --dry_run
        {ruleUnderscore, "bq ls", NoMatch},                                  // wrong subcommand
        {ruleHyphen, "bq query --dry-run --nouse_legacy_sql 'SELECT 1'", Match},
        {ruleHyphen, "bq query --dry_run 'SELECT 1'", NoMatch}, // underscore != hyphen rule
    }
    for _, tt := range tests {
        p, err := shellparse.Parse(tt.cmd)
        if err != nil {
            t.Fatalf("parse %q: %v", tt.cmd, err)
        }
        got, _ := tt.rule.Eval(p)
        if got != tt.want {
            t.Errorf("rule=%s cmd=%q: got %v, want %v", tt.rule.RuleName, tt.cmd, got, tt.want)
        }
    }
}
```

- [ ] **Step 2: Run test — expect FAIL**

```bash
go test ./internal/rules/... -run TestAnchoredCommandRequireFlags -v
```

Expected: compile error — `RequireFlags` field does not exist yet.

- [ ] **Step 3: Add `RequireFlags` field to `AnchoredCommand`**

In `internal/rules/rules.go`, add the field (line ~77):

```go
// AnchoredCommand matches read-only commands with no shell trickery.
type AnchoredCommand struct {
    RuleName         string
    Programs         []string
    RequireSubcmdAny []string // if non-empty, first positional arg must be in this list
    ForbidFlags      []string // reject if any of these flags appear
    RequireFlags     []string // if non-empty, ALL of these flags must be present
}
```

- [ ] **Step 4: Add `RequireFlags` check to `Eval`**

In `AnchoredCommand.Eval`, after the `ForbidFlags` loop (line ~106), add:

```go
for _, required := range r.RequireFlags {
    if !anchoredFlagPresent(c.Flags, required) {
        return NoMatch, ""
    }
}
```

Add the helper below `anchoredFlagForbidden` (around line 176):

```go
// anchoredFlagPresent returns true when a RequireFlags entry matches
// one of the call's flag tokens. Uses the same matching rules as
// anchoredFlagForbidden (exact, key=value, combined short flags) but
// returns true on match instead of false.
func anchoredFlagPresent(callFlags []string, required string) bool {
    if strings.HasPrefix(required, "--") {
        for _, f := range callFlags {
            if f == required || strings.HasPrefix(f, required+"=") {
                return true
            }
        }
        return false
    }
    if strings.HasPrefix(required, "-") && len(required) == 2 {
        want := rune(required[1])
        for _, f := range callFlags {
            if f == required || strings.HasPrefix(f, required+"=") {
                return true
            }
            if strings.HasPrefix(f, "-") && !strings.HasPrefix(f, "--") && len(f) > 2 {
                for _, ch := range f[1:] {
                    if ch == want {
                        return true
                    }
                }
            }
        }
        return false
    }
    for _, f := range callFlags {
        if f == required || strings.HasPrefix(f, required+"=") {
            return true
        }
    }
    return false
}
```

- [ ] **Step 5: Run test — expect PASS**

```bash
go test ./internal/rules/... -run TestAnchoredCommandRequireFlags -v
```

- [ ] **Step 6: Run full suite**

```bash
go test ./... 2>&1 | tail -20
```

- [ ] **Step 7: Commit**

```bash
git add internal/rules/rules.go internal/rules/rules_test.go
git commit -m "rules: add RequireFlags to AnchoredCommand for positive flag assertion"
```

---

## Task 3: Add `UserMessage` to hook response

**Files:**
- Modify: `internal/hook/hook.go`
- Modify: `internal/hook/hook_test.go`

`userMessage` is a top-level field in the Claude Code hook protocol that injects text directly into Claude's conversation. When set alongside `allow` or `continue`, Claude reads it as a note from the hook before proceeding. We use it to show byte-cost estimates and rewrite suggestions.

- [ ] **Step 1: Write failing test**

Add to `internal/hook/hook_test.go`:

```go
func TestResponseWithUserMessage(t *testing.T) {
    r := AllowWithMessage("tier=bq-prelight rule=bq-budget", "Query will process ~512 MB (under daily limit).")
    data, err := json.Marshal(r)
    if err != nil {
        t.Fatal(err)
    }
    var m map[string]any
    if err := json.Unmarshal(data, &m); err != nil {
        t.Fatal(err)
    }
    if m["userMessage"] != "Query will process ~512 MB (under daily limit)." {
        t.Errorf("userMessage missing or wrong: %v", m["userMessage"])
    }
    hso, ok := m["hookSpecificOutput"].(map[string]any)
    if !ok {
        t.Fatal("hookSpecificOutput missing")
    }
    if hso["permissionDecision"] != "allow" {
        t.Errorf("permissionDecision wrong: %v", hso["permissionDecision"])
    }
}

func TestContinueWithUserMessage(t *testing.T) {
    r := ContinueWithMessage("Daily BQ budget exhausted (103 GB / 100 GB). Use --dry_run or approve manually.")
    data, _ := json.Marshal(r)
    var m map[string]any
    _ = json.Unmarshal(data, &m)
    if m["userMessage"] == nil {
        t.Error("userMessage should be set on continue-with-message")
    }
    if m["hookSpecificOutput"] != nil {
        t.Error("hookSpecificOutput should be absent for continue")
    }
}
```

- [ ] **Step 2: Run test — expect FAIL**

```bash
go test ./internal/hook/... -run "TestResponseWithUserMessage|TestContinueWithUserMessage" -v
```

Expected: compile error — `AllowWithMessage` / `ContinueWithMessage` undefined.

- [ ] **Step 3: Add `UserMessage` field and new constructors**

In `internal/hook/hook.go`, extend `Response`:

```go
// Response is the JSON shape Claude Code expects on stdout.
type Response struct {
    HookSpecificOutput *hookSpecificOutput `json:"hookSpecificOutput,omitempty"`
    // UserMessage, when non-empty, injects text into Claude's conversation
    // as a hook-side note. Claude Code surfaces this before the next tool
    // result — useful for cost hints, rewrite suggestions, and budget warnings.
    UserMessage string `json:"userMessage,omitempty"`
}
```

Add two new constructors after the existing `Deny`:

```go
// AllowWithMessage auto-approves and injects msg into Claude's conversation.
func AllowWithMessage(reason, msg string) Response {
    r := Allow(reason)
    r.UserMessage = msg
    return r
}

// ContinueWithMessage falls through to Claude Code's normal permission
// flow AND injects msg into Claude's conversation. Use this when you want
// to inform Claude (e.g. "budget exhausted") without outright blocking.
func ContinueWithMessage(msg string) Response {
    return Response{UserMessage: msg}
}
```

- [ ] **Step 4: Run test — expect PASS**

```bash
go test ./internal/hook/... -run "TestResponseWithUserMessage|TestContinueWithUserMessage" -v
```

- [ ] **Step 5: Run full suite**

```bash
go test ./... 2>&1 | tail -20
```

- [ ] **Step 6: Commit**

```bash
git add internal/hook/hook.go internal/hook/hook_test.go
git commit -m "hook: add UserMessage field + AllowWithMessage/ContinueWithMessage constructors"
```

---

## Task 4: BQ bytes budget package

**Files:**
- Create: `internal/budget/bq.go`
- Create: `internal/budget/bq_test.go`

Rolling daily budget stored as a single JSON file. Tracks estimated bytes (from dry-run output) per calendar day. Thread-safe within a process; uses atomic rename for cross-process safety (matching the cache package pattern).

- [ ] **Step 1: Write failing tests**

Create `internal/budget/bq_test.go`:

```go
package budget

import (
    "path/filepath"
    "testing"
    "time"
)

func TestBQBudget_UnderLimit(t *testing.T) {
    dir := t.TempDir()
    b := NewBQ(dir, 100*1<<30) // 100 GB daily limit

    if !b.Check(5 * 1 << 30) { // 5 GB query
        t.Fatal("fresh budget should allow")
    }
}

func TestBQBudget_OverLimit(t *testing.T) {
    dir := t.TempDir()
    b := NewBQ(dir, 10*1<<30) // 10 GB daily limit

    b.Record(8 * 1 << 30) // record 8 GB used
    if b.Check(5 * 1 << 30) { // ask for 5 more (total 13 GB)
        t.Fatal("should be over budget")
    }
    if !b.Check(1 * 1 << 30) { // ask for 1 more (total 9 GB) — still ok
        t.Fatal("should still have headroom for smaller query")
    }
}

func TestBQBudget_ResetsDaily(t *testing.T) {
    dir := t.TempDir()
    b := NewBQ(dir, 10*1<<30)

    // Simulate yesterday's data by writing directly to the ledger file.
    yesterday := time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02")
    ledger := bqLedger{Date: yesterday, BytesUsed: 50 * 1 << 30}
    writeLedger(filepath.Join(dir, bqLedgerFile), ledger)

    // Today's budget should be fresh (yesterday's data ignored).
    if !b.Check(10 * 1 << 30) {
        t.Fatal("new day should reset budget")
    }
}

func TestBQBudget_Status(t *testing.T) {
    dir := t.TempDir()
    b := NewBQ(dir, 100*1<<30)
    b.Record(30 * 1 << 30)
    s := b.Status()
    if s.BytesUsed != 30*1<<30 {
        t.Errorf("BytesUsed = %d, want %d", s.BytesUsed, 30*1<<30)
    }
    if s.BytesLimit != 100*1<<30 {
        t.Errorf("BytesLimit = %d, want %d", s.BytesLimit, 100*1<<30)
    }
}
```

- [ ] **Step 2: Run tests — expect FAIL**

```bash
go test ./internal/budget/... -v
```

Expected: package does not exist yet.

- [ ] **Step 3: Create `internal/budget/bq.go`**

```go
// Package budget tracks rolling daily BigQuery byte usage for the
// BQ pre-flight budget gate. Thread-safe within a process; uses
// atomic file rename for cross-process consistency.
package budget

import (
    "encoding/json"
    "os"
    "path/filepath"
    "sync"
    "time"
)

const bqLedgerFile = "bq-daily.json"

// bqLedger is the on-disk shape. One file, overwritten each day.
type bqLedger struct {
    Date      string `json:"date"`       // "2006-01-02" UTC
    BytesUsed int64  `json:"bytes_used"`
    Queries   int    `json:"queries"`
}

// BQBudget tracks estimated byte usage for BigQuery queries.
type BQBudget struct {
    dir   string
    limit int64
    mu    sync.Mutex
}

// BQStatus is a snapshot of the current budget state.
type BQStatus struct {
    BytesUsed  int64
    BytesLimit int64
    Queries    int
}

// NewBQ creates a BQBudget with the given daily byte limit.
// dir should be the same cache dir used by the rest of claude-guard
// (~/.cache/claude-guard/).
func NewBQ(dir string, dailyByteLimit int64) *BQBudget {
    return &BQBudget{dir: dir, limit: dailyByteLimit}
}

// Check reports whether a query estimated at estimatedBytes can run
// without exhausting today's budget. estimatedBytes is added to the
// current total; if the result exceeds the limit, returns false.
func (b *BQBudget) Check(estimatedBytes int64) bool {
    b.mu.Lock()
    defer b.mu.Unlock()
    l := b.readToday()
    return l.BytesUsed+estimatedBytes <= b.limit
}

// Record adds estimatedBytes to today's rolling total.
func (b *BQBudget) Record(estimatedBytes int64) {
    b.mu.Lock()
    defer b.mu.Unlock()
    l := b.readToday()
    l.BytesUsed += estimatedBytes
    l.Queries++
    _ = writeLedger(b.ledgerPath(), l)
}

// Status returns a snapshot of today's usage.
func (b *BQBudget) Status() BQStatus {
    b.mu.Lock()
    defer b.mu.Unlock()
    l := b.readToday()
    return BQStatus{BytesUsed: l.BytesUsed, BytesLimit: b.limit, Queries: l.Queries}
}

func (b *BQBudget) ledgerPath() string {
    return filepath.Join(b.dir, bqLedgerFile)
}

// readToday loads today's ledger, or returns a fresh one if the file
// is missing, unreadable, or from a previous day.
func (b *BQBudget) readToday() bqLedger {
    today := time.Now().UTC().Format("2006-01-02")
    data, err := os.ReadFile(b.ledgerPath())
    if err != nil {
        return bqLedger{Date: today}
    }
    var l bqLedger
    if err := json.Unmarshal(data, &l); err != nil || l.Date != today {
        return bqLedger{Date: today}
    }
    return l
}

// writeLedger atomically writes the ledger using tmp+rename.
func writeLedger(path string, l bqLedger) error {
    if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
        return err
    }
    data, err := json.Marshal(l)
    if err != nil {
        return err
    }
    tmp := path + ".tmp"
    if err := os.WriteFile(tmp, data, 0o640); err != nil {
        return err
    }
    return os.Rename(tmp, path)
}
```

- [ ] **Step 4: Run tests — expect PASS**

```bash
go test ./internal/budget/... -v
```

- [ ] **Step 5: Run full suite**

```bash
go test ./... 2>&1 | tail -20
```

- [ ] **Step 6: Commit**

```bash
git add internal/budget/
git commit -m "budget: add BQBudget for daily byte-usage rolling ledger"
```

---

## Task 5: BQ pre-flight engine logic

**Files:**
- Create: `internal/engine/bq.go`
- Create: `internal/engine/bq_test.go`

Handles detection of `bq query` without `--dry_run`, runs a dry-run subprocess, parses the byte estimate, checks the budget, and returns an annotated engine output (verdict + user message).

- [ ] **Step 1: Write failing tests**

Create `internal/engine/bq_test.go`:

```go
package engine

import (
    "testing"
)

func TestParseBQDryRunBytes(t *testing.T) {
    tests := []struct {
        output string
        want   int64
        ok     bool
    }{
        {
            "Query successfully validated. Assuming the tables are not modified, running this query will process 1073741824 bytes of data.",
            1073741824, true,
        },
        {
            "Query successfully validated. Running this query will process 536870912 bytes of data.",
            536870912, true,
        },
        {
            "Error: table not found", 0, false,
        },
        {"", 0, false},
    }
    for _, tt := range tests {
        got, ok := parseBQDryRunBytes(tt.output)
        if ok != tt.ok || got != tt.want {
            t.Errorf("input=%q: got (%d,%v), want (%d,%v)", tt.output, got, ok, tt.want, tt.ok)
        }
    }
}

func TestIsBQQueryWithoutDryRun(t *testing.T) {
    tests := []struct {
        cmd  string
        want bool
    }{
        {"bq query --nouse_legacy_sql 'SELECT 1'", true},
        {"bq query --dry_run --nouse_legacy_sql 'SELECT 1'", false}, // has dry_run
        {"bq ls", false},         // not query
        {"gcloud bq query", false}, // not bq program
    }
    for _, tt := range tests {
        got := isBQQueryWithoutDryRun(tt.cmd)
        if got != tt.want {
            t.Errorf("cmd=%q: got %v, want %v", tt.cmd, got, tt.want)
        }
    }
}

func TestBuildDryRunCommand(t *testing.T) {
    tests := []struct {
        cmd  string
        want string
    }{
        {
            "bq query --nouse_legacy_sql 'SELECT * FROM dataset.table'",
            "bq query --dry_run --nouse_legacy_sql 'SELECT * FROM dataset.table'",
        },
        {
            // SQL with embedded spaces in quoted string — must not be mangled
            `bq query --nouse_legacy_sql 'SELECT id FROM users WHERE name = "Alice Smith"'`,
            `bq query --dry_run --nouse_legacy_sql 'SELECT id FROM users WHERE name = "Alice Smith"'`,
        },
    }
    for _, tt := range tests {
        got := buildDryRunCommand(tt.cmd)
        if got != tt.want {
            t.Errorf("buildDryRunCommand(%q) = %q, want %q", tt.cmd, got, tt.want)
        }
        if !strings.Contains(got, "--dry_run") {
            t.Errorf("dry-run command missing --dry_run flag: %s", got)
        }
    }
}
```

- [ ] **Step 2: Run tests — expect FAIL**

```bash
go test ./internal/engine/... -run "TestParseBQ|TestIsBQ|TestBuildDry" -v
```

- [ ] **Step 3: Create `internal/engine/bq.go`**

```go
package engine

import (
    "context"
    "fmt"
    "os/exec"
    "regexp"
    "strconv"
    "strings"
    "time"
)

// bqDryRunTimeout caps how long we wait for a dry-run subprocess.
// Real bq dry-runs typically complete in 1-3 s. 10 s gives plenty of
// headroom without blocking the user for too long.
const bqDryRunTimeout = 10 * time.Second

// bqBytesPattern extracts the byte estimate from bq --dry_run output.
// Both output shapes observed in the wild:
//   "will process 1073741824 bytes of data."
//   "running this query will process 536870912 bytes of data."
var bqBytesPattern = regexp.MustCompile(`will process (\d+) bytes`)

// isBQQueryWithoutDryRun returns true when cmd is a plain `bq query`
// that is missing the --dry_run flag. Operates on the raw command
// string — fast path before we commit to spawning a subprocess.
func isBQQueryWithoutDryRun(cmd string) bool {
    // First token must be exactly "bq" (no path prefix for now).
    fields := strings.Fields(cmd)
    if len(fields) < 2 {
        return false
    }
    prog := fields[0]
    if prog != "bq" && !strings.HasSuffix(prog, "/bq") {
        return false
    }
    // Second token must be "query".
    if fields[1] != "query" {
        return false
    }
    // --dry_run must NOT be present.
    for _, f := range fields[2:] {
        if f == "--dry_run" || f == "--dry-run" {
            return false
        }
    }
    return true
}

// buildDryRunCommand inserts --dry_run after "bq query" in cmd.
// Uses string replacement rather than field split so shell quoting in
// the query text is preserved intact (e.g. 'SELECT name FROM t WHERE
// city = "Amsterdam"' must not be broken across fields).
// Returns "" if cmd does not have the expected shape.
func buildDryRunCommand(cmd string) string {
    trimmed := strings.TrimSpace(cmd)
    const marker = "bq query "
    if !strings.HasPrefix(trimmed, marker) && trimmed != "bq query" {
        return ""
    }
    return strings.Replace(trimmed, "bq query", "bq query --dry_run", 1)
}

// parseBQDryRunBytes extracts the byte estimate from bq --dry_run output.
// Returns (bytes, true) on success, (0, false) when the pattern is absent.
func parseBQDryRunBytes(output string) (int64, bool) {
    m := bqBytesPattern.FindStringSubmatch(output)
    if len(m) < 2 {
        return 0, false
    }
    n, err := strconv.ParseInt(m[1], 10, 64)
    if err != nil {
        return 0, false
    }
    return n, true
}

// runBQDryRun executes bq --dry_run and returns stdout+stderr combined.
// runDryRun is a variable so tests can stub it without spawning a real process.
var runBQDryRun = func(dryRunCmd string) (string, error) {
    ctx, cancel := context.WithTimeout(context.Background(), bqDryRunTimeout)
    defer cancel()
    // Split on spaces — sufficient for bq commands (no embedded spaces
    // in flags; query text is a single-quoted argument handled by shell
    // when passed to exec.Command via shell=false, so we use sh -c).
    cmd := exec.CommandContext(ctx, "sh", "-c", dryRunCmd)
    out, err := cmd.CombinedOutput()
    return string(out), err
}

// formatBytes returns a human-readable string for a byte count.
func formatBytes(n int64) string {
    const (
        KB = 1 << 10
        MB = 1 << 20
        GB = 1 << 30
        TB = 1 << 40
    )
    switch {
    case n >= TB:
        return fmt.Sprintf("%.2f TB", float64(n)/TB)
    case n >= GB:
        return fmt.Sprintf("%.2f GB", float64(n)/GB)
    case n >= MB:
        return fmt.Sprintf("%.2f MB", float64(n)/MB)
    case n >= KB:
        return fmt.Sprintf("%.2f KB", float64(n)/KB)
    default:
        return fmt.Sprintf("%d B", n)
    }
}
```

- [ ] **Step 4: Run tests — expect PASS**

```bash
go test ./internal/engine/... -run "TestParseBQ|TestIsBQ|TestBuildDry" -v
```

- [ ] **Step 5: Run full suite**

```bash
go test ./... 2>&1 | tail -20
```

- [ ] **Step 6: Commit**

```bash
git add internal/engine/bq.go internal/engine/bq_test.go
git commit -m "engine: add BQ detection, dry-run subprocess, bytes parser"
```

---

## Task 6: Wire BQ pre-flight into the engine + expose `UserMessage`

**Files:**
- Modify: `internal/engine/engine.go`
- Modify: `cmd/claude-guard/decide.go`

Adds the BQ pre-flight tier between tier 2 and tier 3. When `isBQQueryWithoutDryRun` fires, the engine runs the dry-run subprocess, checks the budget, and returns either `Allow` (with byte estimate in `UserMessage`) or `Continue` (with a rewrite suggestion in `UserMessage`). The `Output` struct grows a `UserMessage` field; `decide.go` passes it to `hook.Response`.

- [ ] **Step 1: Write integration test for BQ pre-flight (stubbed subprocess)**

Add to `internal/engine/engine_test.go`:

```go
func TestBQPreflightHint(t *testing.T) {
    // Stub the dry-run subprocess to return a known byte count.
    origRun := runBQDryRun
    defer func() { runBQDryRun = origRun }()
    runBQDryRun = func(_ string) (string, error) {
        return "Query successfully validated. Running this query will process 536870912 bytes of data.", nil
    }

    cacheDir := t.TempDir()
    bqBudget := budget.NewBQ(cacheDir, 100*1<<30) // 100 GB limit
    eng := engine.NewWithOptions(engine.Options{
        Config: config.Default(),
        BQBudget: bqBudget,
    })

    out := eng.Decide(engine.Input{
        ToolName: "Bash",
        Command:  "bq query --nouse_legacy_sql 'SELECT * FROM dataset.table'",
    })

    if out.Verdict != engine.Allow {
        t.Errorf("verdict = %v, want Allow (under budget)", out.Verdict)
    }
    if out.UserMessage == "" {
        t.Error("UserMessage should contain byte estimate")
    }
    if !strings.Contains(out.UserMessage, "512.00 MB") {
        t.Errorf("UserMessage should mention bytes: %s", out.UserMessage)
    }
}

func TestBQPreflightBudgetExhausted(t *testing.T) {
    origRun := runBQDryRun
    defer func() { runBQDryRun = origRun }()
    runBQDryRun = func(_ string) (string, error) {
        return "Running this query will process 10737418240 bytes of data.", nil // 10 GB
    }

    cacheDir := t.TempDir()
    bqBudget := budget.NewBQ(cacheDir, 5*1<<30) // 5 GB limit — already exceeded by this query
    eng := engine.NewWithOptions(engine.Options{
        Config: config.Default(),
        BQBudget: bqBudget,
    })

    out := eng.Decide(engine.Input{
        ToolName: "Bash",
        Command:  "bq query --nouse_legacy_sql 'SELECT * FROM big_table'",
    })

    if out.Verdict != engine.Continue {
        t.Errorf("verdict = %v, want Continue (over budget)", out.Verdict)
    }
    if out.UserMessage == "" {
        t.Error("UserMessage should contain budget-exhausted hint")
    }
}
```

- [ ] **Step 2: Run test — expect FAIL**

```bash
go test ./internal/engine/... -run "TestBQPreflight" -v
```

Expected: compile errors — `UserMessage` on `Output`, `BQBudget` in `Options` not defined.

- [ ] **Step 3: Add `UserMessage` to `engine.Output`**

In `internal/engine/engine.go`, extend `Output` (around line 93):

```go
type Output struct {
    Verdict     Verdict
    Tier        string
    Rule        string
    Reason      string
    Latency     time.Duration
    UserMessage string // hint injected into Claude's conversation; "" = no injection
    Shadow      ShadowTrace
}
```

- [ ] **Step 4: Add `BQBudget` to `engine.Options`**

In `internal/engine/engine.go`, extend `Options` (around line 153):

```go
type Options struct {
    Config              *config.Config
    DecisionLog         *clog.DecisionLogger
    AppLog              *slog.Logger
    Redactor            *redact.Redactor
    LLM                 llm.Classifier
    Verifier            llm.Classifier
    Breaker             *breaker.Breaker
    Cache               *cache.Cache
    Legacy              *legacy.AllowList
    ProjectConfigLoader func(cwd string) (*projectconfig.Config, error)
    BQBudget            *budget.BQBudget // nil = BQ pre-flight disabled
}
```

Add the field to `Engine` struct (around line 114):

```go
type Engine struct {
    // ... existing fields ...
    bqBudget *budget.BQBudget
}
```

Wire it in `NewWithOptions`:

```go
e := &Engine{
    // ... existing fields ...
    bqBudget: opts.BQBudget,
}
```

- [ ] **Step 5: Insert BQ pre-flight tier in `Decide`**

In `internal/engine/engine.go`, inside `Decide`, after the tier-2 allow loop and before the tier-3 cache lookup (around line 410):

```go
// BQ pre-flight tier: intercept `bq query` without --dry_run.
// Runs a dry-run subprocess to get the byte estimate, checks the
// rolling budget, and injects a userMessage into the response.
// Skipped when BQBudget is not configured (e.g. tests that don't set it).
if e.bqBudget != nil && isBQQueryWithoutDryRun(in.Command) {
    return e.runBQPreFlight(in, start)
}
```

Add the method below `Decide`:

```go
// runBQPreFlight runs bq --dry_run, checks the budget, and returns
// either Allow (under budget) or Continue (over budget / subprocess error).
// In both cases a UserMessage is set so Claude sees the cost information.
func (e *Engine) runBQPreFlight(in Input, start time.Time) Output {
    dryCmd := buildDryRunCommand(in.Command)
    if dryCmd == "" {
        // Command didn't parse cleanly — fall through.
        return Output{Verdict: Continue, Tier: "default", Latency: time.Since(start)}
    }

    rawOut, err := runBQDryRun(dryCmd)
    if err != nil {
        // Dry-run failed (no BQ credentials, network error, syntax error).
        // Fall through to LLM / user prompt; attach a soft hint.
        msg := fmt.Sprintf(
            "BQ dry-run failed (%v). Query not pre-approved — please review manually.", err)
        out := Output{
            Verdict:     Continue,
            Tier:        "default",
            UserMessage: msg,
            Latency:     time.Since(start),
        }
        e.record(in, out)
        return out
    }

    bytes, ok := parseBQDryRunBytes(rawOut)
    if !ok {
        // Couldn't parse bytes — dry-run ran but output was unexpected.
        out := Output{
            Verdict:     Continue,
            Tier:        "default",
            UserMessage: "BQ dry-run output was unexpected — please review manually.",
            Latency:     time.Since(start),
        }
        e.record(in, out)
        return out
    }

    status := e.bqBudget.Status()
    humanBytes := formatBytes(bytes)
    humanUsed := formatBytes(status.BytesUsed)
    humanLimit := formatBytes(status.BytesLimit)

    if !e.bqBudget.Check(bytes) {
        // Over budget — fall through to user prompt.
        msg := fmt.Sprintf(
            "BQ budget exhausted: this query would process %s, but daily limit is %s (used: %s). "+
                "Use `--dry_run` to inspect or approve manually.",
            humanBytes, humanLimit, humanUsed)
        out := Output{
            Verdict:     Continue,
            Tier:        "bq_budget",
            Reason:      "daily byte budget exhausted",
            UserMessage: msg,
            Latency:     time.Since(start),
        }
        e.record(in, out)
        return out
    }

    // Under budget — record and allow.
    e.bqBudget.Record(bytes)
    updatedStatus := e.bqBudget.Status()
    msg := fmt.Sprintf(
        "BQ pre-flight: query will process ~%s. Daily usage: %s / %s (%d queries today).",
        humanBytes, formatBytes(updatedStatus.BytesUsed), humanLimit, updatedStatus.Queries)
    out := Output{
        Verdict:     Allow,
        Tier:        "bq_preflight",
        Rule:        "bq-budget",
        Reason:      fmt.Sprintf("under daily budget (%s)", humanLimit),
        UserMessage: msg,
        Latency:     time.Since(start),
    }
    e.record(in, out)
    return out
}
```

- [ ] **Step 6: Pass `UserMessage` from engine to hook in `decide.go`**

In `cmd/claude-guard/decide.go`, update the response translation (around line 191):

```go
var resp hook.Response
switch out.Verdict {
case engine.Allow:
    if out.UserMessage != "" {
        resp = hook.AllowWithMessage(
            fmt.Sprintf("tier=%s rule=%s", out.Tier, out.Rule),
            out.UserMessage,
        )
    } else {
        resp = hook.Allow(fmt.Sprintf("tier=%s rule=%s", out.Tier, out.Rule))
    }
case engine.Deny:
    resp = hook.Deny(fmt.Sprintf("%s (tier=%s rule=%s)", out.Reason, out.Tier, out.Rule))
default:
    if out.UserMessage != "" {
        resp = hook.ContinueWithMessage(out.UserMessage)
    } else {
        resp = hook.Continue()
    }
}
```

- [ ] **Step 7: Run tests — expect PASS**

```bash
go test ./internal/engine/... -run "TestBQPreflight" -v
```

- [ ] **Step 8: Run full suite**

```bash
go test ./... 2>&1 | tail -20
```

- [ ] **Step 9: Commit**

```bash
git add internal/engine/engine.go cmd/claude-guard/decide.go
git commit -m "engine: BQ pre-flight tier with byte-budget gating and userMessage hints"
```

---

## Task 7: Config — wire `BQBudget` in production + update BQ tier-2 rules

**Files:**
- Modify: `internal/config/defaults.go` — add bq-dry-run allow rule, remove `query` from bq-readonly
- Modify: `cmd/claude-guard/decide.go` — construct `BQBudget` and pass to engine options

This task makes the BQ pre-flight live in production. `bq query --dry_run` gets instant-allowed at tier 2 (free, no budget concern). All other `bq query` calls fall to the new BQ pre-flight tier.

- [ ] **Step 1: Write golden test for bq tier-2 split**

Add to `internal/engine/golden_test.go` (or engine_test.go):

```go
func TestBQTier2Split(t *testing.T) {
    eng := engine.New(config.Default(), nil)
    tests := []struct {
        cmd      string
        wantTier string
    }{
        {"bq query --dry_run --nouse_legacy_sql 'SELECT 1'", "instant_allow"},
        {"bq ls", "instant_allow"},
        {"bq show dataset.table", "instant_allow"},
        // Real queries fall through (no BQBudget configured in this test)
        {"bq query --nouse_legacy_sql 'SELECT * FROM t'", "default"},
    }
    for _, tt := range tests {
        out := eng.Decide(engine.Input{ToolName: "Bash", Command: tt.cmd})
        if out.Tier != tt.wantTier {
            t.Errorf("cmd=%q: tier=%s, want %s", tt.cmd, out.Tier, tt.wantTier)
        }
    }
}
```

- [ ] **Step 2: Run test — expect FAIL**

```bash
go test ./internal/engine/... -run TestBQTier2Split -v
```

Expected: `bq query --dry_run` returns `default` (not `instant_allow`), and `bq query` (non-dry-run) also returns `default`.

- [ ] **Step 3: Update `defaults.go`**

In `internal/config/defaults.go`, replace:

```go
// BEFORE
bqReadonly := &rules.AnchoredCommand{
    RuleName:         "bq-readonly",
    Programs:         []string{"bq"},
    RequireSubcmdAny: []string{"show", "ls", "query", "head"},
}
```

With:

```go
// AFTER: split query into a separate dry-run-only rule.
// Real bq query falls through to the BQ pre-flight tier (budget + hint).
bqReadonly := &rules.AnchoredCommand{
    RuleName:         "bq-readonly",
    Programs:         []string{"bq"},
    RequireSubcmdAny: []string{"show", "ls", "head"},
}

// bq query --dry_run / --dry-run is always free — validate and estimate, never bill.
// Two rules: one per flag spelling (bq CLI accepts both underscore and hyphen).
bqDryRunUnderscore := &rules.AnchoredCommand{
    RuleName:         "bq-dry-run",
    Programs:         []string{"bq"},
    RequireSubcmdAny: []string{"query"},
    RequireFlags:     []string{"--dry_run"},
}
bqDryRunHyphen := &rules.AnchoredCommand{
    RuleName:         "bq-dry-run-hyphen",
    Programs:         []string{"bq"},
    RequireSubcmdAny: []string{"query"},
    RequireFlags:     []string{"--dry-run"},
}
```

Add both dry-run variants to the return slice and to `CdPrefixed.InnerRules` (after `bqReadonly` in both places):

```go
return []rules.Rule{
    posixReadonly,
    findReadonly,
    gitReadonly,
    bqReadonly,
    bqDryRunUnderscore, // ADD: --dry_run
    bqDryRunHyphen,     // ADD: --dry-run
    terraformReadonly,
    // ...
}
```

```go
&rules.CdPrefixed{
    RuleName: "cd-prefixed-readonly",
    InnerRules: []rules.Rule{
        posixReadonly,
        findReadonly,
        gitReadonly,
        bqReadonly,
        bqDryRunUnderscore, // ADD
        bqDryRunHyphen,     // ADD
        // ...
    },
}
```

- [ ] **Step 4: Construct `BQBudget` in `decide.go` and pass to engine**

In `cmd/claude-guard/decide.go`, after the `cacheRoot` line (around line 75):

```go
// BQ byte budget: 100 GB per day by default.
// Configurable via cfg.BQ.DailyByteLimitGB when that config key is wired.
const defaultBQDailyLimitGB = 100
bqBudget := budget.NewBQ(cacheRoot, defaultBQDailyLimitGB*1<<30)
```

Add `BQBudget: bqBudget` to `engine.Options` in `NewWithOptions` call.

Import `"github.com/RobinUS2/claude-guard/internal/budget"` at the top of `decide.go`.

- [ ] **Step 5: Run tests — expect PASS**

```bash
go test ./internal/engine/... -run TestBQTier2Split -v
go test ./... 2>&1 | tail -20
```

- [ ] **Step 6: Manual smoke test** (requires BQ credentials)

```bash
# Should instant-allow (tier 2, bq-dry-run)
echo '{"tool_name":"Bash","tool_input":{"command":"bq query --dry_run --nouse_legacy_sql '\''SELECT 1'\''"},"session_id":"test","cwd":"/tmp","hook_event_name":"PreToolUse","tool_use_id":"x"}' \
  | ./claude-guard decide

# Should run pre-flight and allow (or continue if over budget)
echo '{"tool_name":"Bash","tool_input":{"command":"bq query --nouse_legacy_sql '\''SELECT 1'\''"},"session_id":"test","cwd":"/tmp","hook_event_name":"PreToolUse","tool_use_id":"y"}' \
  | ./claude-guard decide
```

Expected for dry-run: `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow",...}}`

Expected for real query: response includes `"userMessage"` with byte estimate.

- [ ] **Step 7: Commit**

```bash
git add internal/config/defaults.go cmd/claude-guard/decide.go
git commit -m "config: split bq-readonly → bq-dry-run (instant-allow) + bq-budget pre-flight for real queries"
```

---

### Task 8: Hit-rate and time-saved measurement in `stats.go`

Show how many user prompts claude-guard avoided and estimate wall-clock time saved.

**Files:**
- Modify: `cmd/claude-guard/stats.go`
- Test: `cmd/claude-guard/stats_test.go`

The existing decision log (`decisions.jsonl`) already records `verdict` and `tier` per entry. We need to:

1. Count entries where the engine resolved without asking the user: `verdict=allow` at tier `instant_allow`, `cache`, or `llm`.
2. Count entries where the user was prompted: `verdict=continue` (tier `default`).
3. Derive `interrupts_avoided` and `time_saved_estimate`.

**Heuristic:** 3 minutes per avoided user-prompt (conservative; typical pause is longer when the user is mid-thought).

- [ ] **Step 1: Write failing test**

In `cmd/claude-guard/stats_test.go`, add:

```go
func TestComputeTimeSaved(t *testing.T) {
    entries := []logEntry{
        {Verdict: "allow",    Tier: "instant_allow"},
        {Verdict: "allow",    Tier: "cache"},
        {Verdict: "allow",    Tier: "llm"},
        {Verdict: "continue", Tier: "default"},   // user prompted
        {Verdict: "continue", Tier: "default"},   // user prompted
    }
    avoided, saved := computeTimeSaved(entries)
    if avoided != 3 {
        t.Errorf("avoided=%d, want 3", avoided)
    }
    wantMin := 3 * 3 // 3 avoided × 3 min
    if saved != wantMin {
        t.Errorf("saved=%d min, want %d", saved, wantMin)
    }
}
```

- [ ] **Step 2: Run test — expect FAIL**

```bash
go test ./cmd/claude-guard/... -run TestComputeTimeSaved -v
```

Expected: `undefined: computeTimeSaved`

- [ ] **Step 3: Implement `computeTimeSaved` in `stats.go`**

Add to `cmd/claude-guard/stats.go`:

```go
const minutesPerInterruptAvoided = 3

// computeTimeSaved returns (interruptsAvoided, minutesSaved).
// An interrupt is "avoided" when the engine resolved without prompting the user
// (instant_allow, cache, or llm tier — all automated paths).
func computeTimeSaved(entries []logEntry) (int, int) {
    avoided := 0
    for _, e := range entries {
        switch e.Tier {
        case "instant_allow", "cache", "llm":
            if e.Verdict == "allow" {
                avoided++
            }
        }
    }
    return avoided, avoided * minutesPerInterruptAvoided
}
```

- [ ] **Step 4: Surface in `cmdStats` output**

In the `cmdStats` function (or equivalent stats renderer), after the existing rule-hit counts, add:

```go
avoided, savedMin := computeTimeSaved(entries)
fmt.Printf("\nInterrupts avoided:  %d\n", avoided)
fmt.Printf("Time saved (est.):   ~%d min (~%.1f h)\n",
    savedMin, float64(savedMin)/60.0)
fmt.Printf("  (heuristic: %d min per avoided user-prompt)\n", minutesPerInterruptAvoided)
```

- [ ] **Step 5: Run test — expect PASS**

```bash
go test ./cmd/claude-guard/... -run TestComputeTimeSaved -v
go test ./... 2>&1 | tail -20
```

- [ ] **Step 6: Commit**

```bash
git add cmd/claude-guard/stats.go cmd/claude-guard/stats_test.go
git commit -m "stats: add interrupts-avoided and time-saved-estimate to output"
```

---

## Notes

### Threshold tuning
The 100 GB / day default is conservative for ad-hoc dev use (~$0.50/day at $5/TB). For heavy analytics repos, tune via config. `claude-guard doctor` should show BQ budget status once it's wired.

### `userMessage` field
This is the Claude Code hook protocol's top-level `userMessage` key. It injects text into Claude's conversation as a hook-side note before the next tool response. Verified against the `hookSpecificOutput` schema from `docs/plans/2026-04-15-claude-guard.md`. Not currently documented in the public Claude Code hook docs — verify on upgrade.

### Subprocess latency
`bq query --dry_run` typically takes 1–3 s. This is the cost of the pre-flight. If latency becomes a problem, add a `bq_preflight_timeout` config key (default 10s already set in `bq.go`).

### Dry-run subprocess failures
If the dry-run fails (no credentials, network, invalid SQL), the engine falls through to the user prompt with a soft message — never silently blocks. Claude can still approve manually.

### What this does NOT do
- Track actual `totalBytesBilled` (requires PostToolUse hook — separate plan)
- Detect BQ queries mentioned in conversation text (requires UserPromptSubmit hook)
- The `PipedReadonly` rule type for piped-command allow (separate plan)
