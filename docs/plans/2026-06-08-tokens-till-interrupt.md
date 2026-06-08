# Tokens-Till-Interrupt Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Track approximate session token count per decision in `decisions.jsonl` and compute a `tokens between interrupts` flow metric in `claude-guard stats`.

**Architecture:** A new `tokensnapshot` package reads the `transcript_path` file (already in the `hook.Request` struct but currently unused) by summing raw JSON-line byte lengths and dividing by 5. That estimate is stored as `session_tokens` in every decision log entry. The `stats` command uses per-session sequences of interrupt-point token snapshots to emit delta-based `tokens between interrupts` percentiles alongside the existing time and calls metrics.

**Tech Stack:** Go standard library only — `bufio`, `os`, `encoding/json`, `slog`. No new dependencies.

---

## File Map

| Action | Path |
|--------|------|
| Create | `internal/tokensnapshot/tokensnapshot.go` |
| Create | `internal/tokensnapshot/tokensnapshot_test.go` |
| Modify | `internal/log/log.go` |
| Modify | `internal/engine/engine.go` |
| Modify | `cmd/claude-guard/decide.go` |
| Modify | `cmd/claude-guard/stats.go` |
| Modify | `cmd/claude-guard/hints.go` |

---

### Task 1: `tokensnapshot` package

**Files:**
- Create: `internal/tokensnapshot/tokensnapshot.go`
- Create: `internal/tokensnapshot/tokensnapshot_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/tokensnapshot/tokensnapshot_test.go
package tokensnapshot_test

import (
	"os"
	"testing"

	"github.com/RobinUS2/claude-guard/internal/tokensnapshot"
)

func TestCount_EmptyFile(t *testing.T) {
	f := t.TempDir() + "/transcript.jsonl"
	if err := os.WriteFile(f, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	if n := tokensnapshot.Count(f); n != 0 {
		t.Fatalf("empty file: want 0, got %d", n)
	}
}

func TestCount_NonZero(t *testing.T) {
	f := t.TempDir() + "/transcript.jsonl"
	// 100 bytes → expect roughly 20 tokens (100/5)
	content := `{"role":"user","content":"hello world this is a test message for counting"}` + "\n" +
		`{"role":"assistant","content":"acknowledged"}` + "\n"
	if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	n := tokensnapshot.Count(f)
	if n < 10 || n > 50 {
		t.Fatalf("want roughly 20 tokens, got %d (file: %d bytes)", n, len(content))
	}
}

func TestCount_MissingFile(t *testing.T) {
	if n := tokensnapshot.Count("/nonexistent/path/transcript.jsonl"); n != 0 {
		t.Fatalf("missing file: want 0, got %d", n)
	}
}

func TestCount_EmptyPath(t *testing.T) {
	if n := tokensnapshot.Count(""); n != 0 {
		t.Fatalf("empty path: want 0, got %d", n)
	}
}
```

- [ ] **Step 2: Run test — expect compile error**

```bash
cd ~/Documents/code/claude-guard
go test ./internal/tokensnapshot/... -v
```

Expected: `cannot find package "github.com/RobinUS2/claude-guard/internal/tokensnapshot"`

- [ ] **Step 3: Write implementation**

```go
// internal/tokensnapshot/tokensnapshot.go
package tokensnapshot

import (
	"bufio"
	"os"
)

// Count returns an approximate token count for the Claude Code transcript at
// path. It sums raw JSON-line byte lengths and divides by 5 (rough
// chars-per-token for JSON-wrapped content). Returns 0 when path is empty,
// the file does not exist, or any read error occurs — callers treat 0 as
// "unknown" and omit the metric rather than logging a zero.
func Count(path string) int64 {
	if path == "" {
		return 0
	}
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()

	var total int64
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 512*1024), 512*1024)
	for sc.Scan() {
		total += int64(len(sc.Bytes()))
	}
	if total == 0 {
		return 0
	}
	return total / 5
}
```

- [ ] **Step 4: Run test — expect PASS**

```bash
go test ./internal/tokensnapshot/... -v
```

Expected: all 4 tests PASS

- [ ] **Step 5: Commit**

```bash
cd ~/Documents/code/claude-guard
git add internal/tokensnapshot/
git commit -m "feat(tokensnapshot): fast transcript byte counter for token estimates"
```

---

### Task 2: Add `SessionTokens` to log schema

**Files:**
- Modify: `internal/log/log.go`

- [ ] **Step 1: Write failing test**

Add to the existing `internal/log/log_test.go` file (which is `package log`, not `package log_test` — match it):

```go
func TestDecisionLogger_SessionTokens_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	paths := DefaultPaths(dir)
	dl, err := OpenDecisionLogger(paths, 10, 3)
	if err != nil {
		t.Fatal(err)
	}
	dl.Decision(DecisionRecord{
		GuardVersion:  "test",
		ToolName:      "Bash",
		Tier:          "instant_allow",
		Verdict:       "allow",
		LatencyUS:     100,
		SessionTokens: 1234,
	})
	dl.Decision(DecisionRecord{
		GuardVersion: "test",
		ToolName:     "Bash",
		Tier:         "instant_allow",
		Verdict:      "allow",
		LatencyUS:    100,
		// SessionTokens = 0 intentionally
	})
	dl.Close()

	data, err := os.ReadFile(paths.Decisions)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitN(strings.TrimRight(string(data), "\n"), "\n", 2)
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d:\n%s", len(lines), data)
	}

	// First line must have session_tokens = 1234.
	var r1 ReadRecord
	if err := json.Unmarshal([]byte(lines[0]), &r1); err != nil {
		t.Fatalf("line 1 decode: %v", err)
	}
	if r1.SessionTokens != 1234 {
		t.Errorf("line 1 SessionTokens: want 1234, got %d", r1.SessionTokens)
	}

	// Second line must NOT contain the key at all (omitempty when zero).
	if strings.Contains(lines[1], "session_tokens") {
		t.Errorf("session_tokens key must be absent when zero, got: %s", lines[1])
	}
}
```

- [ ] **Step 2: Run test — expect compile error**

```bash
go test ./internal/log/... -v -run TestDecisionLogger_SessionTokens
```

Expected: compile error — `SessionTokens` not defined in `DecisionRecord` or `ReadRecord`

- [ ] **Step 3: Add `SessionTokens` to `DecisionRecord` (write side)**

In `internal/log/log.go`, in the `DecisionRecord` struct after the `Shadow` field, add:

```go
// SessionTokens is an approximate count of tokens in the Claude Code
// transcript at decision time, derived from transcript file byte length / 5.
// Zero means the transcript path was unavailable or the file was empty.
// Omitted from the log entry when zero.
SessionTokens int64
```

- [ ] **Step 4: Add `session_tokens` to `decisionAttrs`**

In `internal/log/log.go`, in `decisionAttrs()` just before the `if rec.Shadow != nil` block, add:

```go
if rec.SessionTokens > 0 {
    attrs = append(attrs, slog.Int64("session_tokens", rec.SessionTokens))
}
```

- [ ] **Step 5: Add `SessionTokens` to `ReadRecord` (read side)**

In `internal/log/log.go`, in the `ReadRecord` struct after `LatencyUS`, add:

```go
SessionTokens int64 `json:"session_tokens,omitempty"`
```

- [ ] **Step 6: Run tests — expect PASS**

```bash
go test ./internal/log/... -v -run TestDecisionLogger_SessionTokens
```

Expected: both sub-cases PASS

- [ ] **Step 7: Run full log package tests**

```bash
go test ./internal/log/... -v
```

Expected: all PASS

- [ ] **Step 8: Commit**

```bash
git add internal/log/log.go internal/log/log_test.go
git commit -m "feat(log): add session_tokens field to decision log schema"
```

---

### Task 3: Wire `tokensnapshot` into engine and decide

**Files:**
- Modify: `internal/engine/engine.go`
- Modify: `cmd/claude-guard/decide.go`

- [ ] **Step 1: Add `TranscriptPath` to engine `Input`**

In `internal/engine/engine.go`, in the `Input` struct after `IsWrite`, add:

```go
// TranscriptPath is the path to the Claude Code session transcript file.
// Populated from the PreToolUse hook payload. Used to snapshot approximate
// session token count at decision time. Empty when hook does not provide it.
TranscriptPath string
```

- [ ] **Step 2: Import `tokensnapshot` in engine.go**

In `internal/engine/engine.go`, add to the import block:

```go
"github.com/RobinUS2/claude-guard/internal/tokensnapshot"
```

- [ ] **Step 3: Set `SessionTokens` in `record()`**

In `internal/engine/engine.go`, in the `record()` function, just before `e.log.Decision(rec)` (line ~1683), add:

```go
rec.SessionTokens = tokensnapshot.Count(in.TranscriptPath)
```

- [ ] **Step 4: Pass `TranscriptPath` from decide.go**

In `cmd/claude-guard/decide.go`, in the `engine.Input{...}` literal (lines ~111-118), add:

```go
TranscriptPath: req.TranscriptPath,
```

- [ ] **Step 5: Build — expect clean**

```bash
cd ~/Documents/code/claude-guard
go build ./...
```

Expected: exits 0, no errors

- [ ] **Step 6: Smoke test via `claude-guard test`**

```bash
~/.claude/bin/claude-guard test "ls -la" 2>&1
```

Wait — we haven't installed the new binary yet. Build it locally and test:

```bash
go run ./cmd/claude-guard test "ls -la"
```

Expected: `verdict: allow` (or similar), no panic

- [ ] **Step 7: Run all tests**

```bash
go test ./... -race
```

Expected: all PASS, no races

- [ ] **Step 8: Commit**

```bash
git add internal/engine/engine.go cmd/claude-guard/decide.go
git commit -m "feat(engine): snapshot transcript token count into session_tokens log field"
```

---

### Task 4: `tokens between interrupts` in stats

**Files:**
- Modify: `cmd/claude-guard/stats.go`

The strategy: as `aggregation.add()` processes each record, track `sessionLastInterruptToken map[string]int64` (token count at the most recent Continue verdict per session). On each Continue record with `SessionTokens > 0`, compute the delta and append to `tokenStretches []int64`.

- [ ] **Step 1: Write failing test**

Create `cmd/claude-guard/stats_tokens_test.go`:

```go
// cmd/claude-guard/stats_tokens_test.go
package main

import (
	"testing"
	"time"

	clog "github.com/RobinUS2/claude-guard/internal/log"
)

func TestTokenStretches_BasicDeltas(t *testing.T) {
	agg := newAggregation()

	base := time.Now()
	records := []clog.ReadRecord{
		{Msg: "decision", Time: base.Add(0).Format(time.RFC3339Nano),           SessionID: "s1", Verdict: "allow",    SessionTokens: 800},
		{Msg: "decision", Time: base.Add(10 * time.Second).Format(time.RFC3339Nano), SessionID: "s1", Verdict: "allow",    SessionTokens: 1600},
		{Msg: "decision", Time: base.Add(20 * time.Second).Format(time.RFC3339Nano), SessionID: "s1", Verdict: "continue", SessionTokens: 3000}, // +3000 from 0
		{Msg: "decision", Time: base.Add(30 * time.Second).Format(time.RFC3339Nano), SessionID: "s1", Verdict: "allow",    SessionTokens: 4000},
		{Msg: "decision", Time: base.Add(40 * time.Second).Format(time.RFC3339Nano), SessionID: "s1", Verdict: "continue", SessionTokens: 5500}, // +2500 from 3000
	}
	for i := range records {
		agg.add(&records[i])
	}

	stretches := agg.tokenStretches
	if len(stretches) != 2 {
		t.Fatalf("want 2 stretches, got %d: %v", len(stretches), stretches)
	}
	if stretches[0] != 3000 {
		t.Fatalf("first stretch: want 3000, got %d", stretches[0])
	}
	if stretches[1] != 2500 {
		t.Fatalf("second stretch: want 2500, got %d", stretches[1])
	}
}

func TestTokenStretches_ZeroTokensSkipped(t *testing.T) {
	agg := newAggregation()

	base := time.Now()
	records := []clog.ReadRecord{
		// Old-format records with no session_tokens — must not produce a stretch.
		{Msg: "decision", Time: base.Format(time.RFC3339Nano), SessionID: "s1", Verdict: "continue", SessionTokens: 0},
		{Msg: "decision", Time: base.Add(10 * time.Second).Format(time.RFC3339Nano), SessionID: "s1", Verdict: "continue", SessionTokens: 0},
	}
	for i := range records {
		agg.add(&records[i])
	}

	if len(agg.tokenStretches) != 0 {
		t.Fatalf("want 0 token stretches for zero-token records, got %d", len(agg.tokenStretches))
	}
}

func TestTokenStretches_MultiSession(t *testing.T) {
	agg := newAggregation()

	base := time.Now()
	records := []clog.ReadRecord{
		{Msg: "decision", Time: base.Format(time.RFC3339Nano),                      SessionID: "s1", Verdict: "continue", SessionTokens: 1000},
		{Msg: "decision", Time: base.Add(5 * time.Second).Format(time.RFC3339Nano), SessionID: "s2", Verdict: "continue", SessionTokens: 2000},
		{Msg: "decision", Time: base.Add(10 * time.Second).Format(time.RFC3339Nano), SessionID: "s1", Verdict: "continue", SessionTokens: 4000},
	}
	for i := range records {
		agg.add(&records[i])
	}

	// s1: 1000 (first), then 4000-1000=3000
	// s2: 2000 (first)
	if len(agg.tokenStretches) != 3 {
		t.Fatalf("want 3 stretches, got %d: %v", len(agg.tokenStretches), agg.tokenStretches)
	}
}
```

- [ ] **Step 2: Run test — expect compile error**

```bash
go test ./cmd/claude-guard/... -v -run TestTokenStretches
```

Expected: compile error — `tokenStretches` not in `aggregation`

- [ ] **Step 3: Add fields to `aggregation` struct**

In `cmd/claude-guard/stats.go`, in the `aggregation` struct, add after `sessionLast`:

```go
// token-based interrupt tracking
sessionLastInterruptToken map[string]int64 // last interrupt's token snapshot per session
tokenStretches            []int64          // delta tokens between consecutive interrupts
```

- [ ] **Step 4: Initialise in `newAggregation()`**

In `newAggregation()`, add:

```go
sessionLastInterruptToken: map[string]int64{},
```

- [ ] **Step 5: Populate in `aggregation.add()`**

In `aggregation.add()`, after the existing `if strings.EqualFold(rec.Verdict, "continue") { ... }` block, add the token tracking. Note: `sid` is guaranteed non-empty at this point — the function already returns early if `sid == ""` a few lines above.

```go
// Token-based stretch tracking (sid is always non-empty here).
if rec.SessionTokens > 0 && strings.EqualFold(rec.Verdict, "continue") {
    if last, ok := a.sessionLastInterruptToken[sid]; ok {
        if rec.SessionTokens > last {
            a.tokenStretches = append(a.tokenStretches, rec.SessionTokens-last)
        }
    } else {
        // First interrupt in this session — delta from transcript start.
        a.tokenStretches = append(a.tokenStretches, rec.SessionTokens)
    }
    a.sessionLastInterruptToken[sid] = rec.SessionTokens
}
```

- [ ] **Step 6: Add helpers**

Add after `percentileInt` in `stats.go`:

```go
// percentileInt64 returns the p-th percentile from a sorted int64 slice.
func percentileInt64(values []int64, p float64) int64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]int64(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := int(float64(len(sorted)-1) * p)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// fmtTokens formats an approximate token count as "1.2k" or "850".
func fmtTokens(n int64) string {
	if n >= 1000 {
		return fmt.Sprintf("%.1fk", float64(n)/1000)
	}
	return fmt.Sprintf("%d", n)
}
```

- [ ] **Step 7: Output the metric in `cmdStats`**

In `cmdStats()`, in the `if len(stretches) > 0 || agg.interruptCount > 0` block, after the `flowQuality` print block (after the `max:` line), add:

```go
if len(agg.tokenStretches) >= 3 {
    fmt.Println("  tokens between interrupts (approx):")
    fmt.Printf("    median:  %s\n", fmtTokens(percentileInt64(agg.tokenStretches, 0.50)))
    fmt.Printf("    p95:     %s\n", fmtTokens(percentileInt64(agg.tokenStretches, 0.95)))
}
```

- [ ] **Step 8: Run tests — expect PASS**

```bash
go test ./cmd/claude-guard/... -v -run TestTokenStretches
```

Expected: all 3 tests PASS

- [ ] **Step 9: Build and smoke test**

```bash
go build ./... && go run ./cmd/claude-guard stats --since 168h 2>&1 | grep -A3 "tokens between" || echo "(metric absent — need new log entries)"
```

Expected: either the metric appears or the echo fires (old log has no `session_tokens` entries — both outcomes are correct)

- [ ] **Step 10: Run full test suite**

```bash
go test ./... -race
```

Expected: all PASS, no races

- [ ] **Step 11: Commit**

```bash
git add cmd/claude-guard/stats.go cmd/claude-guard/stats_tokens_test.go
git commit -m "feat(stats): add tokens-between-interrupts flow metric"
```

---

### Task 5: Hints update

**Files:**
- Modify: `cmd/claude-guard/hints.go`

- [ ] **Step 1: Add token guidance to `writePlanningGuidance`**

In `cmd/claude-guard/hints.go`, in `writePlanningGuidance()`, locate the block that prints `### Why this matters:` and add after it (before the final `### Quick reference:` block):

```go
fmt.Fprintln(w, "")
fmt.Fprintln(w, "### Token Budget")
fmt.Fprintln(w, "")
fmt.Fprintln(w, "Each uninterrupted stretch consumes a token budget before the next user-approval.")
fmt.Fprintln(w, "Run `claude-guard stats` to see your median tokens-between-interrupts.")
fmt.Fprintln(w, "High token stretches = efficient flow. Low = frequent approvals burning budget.")
fmt.Fprintln(w, "Batch approval-gated steps to end to maximise tokens spent on productive work.")
```

- [ ] **Step 2: Build and verify**

```bash
go build ./... && go run ./cmd/claude-guard hints 2>&1 | grep -A5 "Token Budget"
```

Expected: section appears in output

- [ ] **Step 3: Commit**

```bash
git add cmd/claude-guard/hints.go
git commit -m "feat(hints): add token budget guidance to planning layer"
```

---

### Task 6: Full build, install, verify

- [ ] **Step 1: Run complete test suite with race detector**

```bash
cd ~/Documents/code/claude-guard
go test ./... -race -count=1
```

Expected: all PASS, no data races

- [ ] **Step 2: Install**

```bash
make install
```

Expected: `~/.claude/bin/claude-guard` updated

- [ ] **Step 3: Doctor check**

```bash
~/.claude/bin/claude-guard doctor
```

Expected: all checks pass, mode shown, no errors

- [ ] **Step 4: Live stats check**

```bash
~/.claude/bin/claude-guard stats --since 1h
```

Expected: stats output loads without error; `tokens between interrupts` absent (log entries pre-date this change — expected) OR present if you run a few tool calls first

- [ ] **Step 5: Verify new log entries capture tokens**

Run any bash command through the guard (e.g. via Claude Code), then:

```bash
tail -3 ~/.claude/logs/claude-guard/decisions.jsonl | python3 /tmp/show_log_schema.py
```

Expected: at least one entry with `"session_tokens": <N>` present

- [ ] **Step 6: Run stats again after live entries**

```bash
~/.claude/bin/claude-guard stats --since 1h
```

Expected: `tokens between interrupts` metric now appears once enough Continue events accumulate

---

## Failure Routing

| Phase | On Failure → |
|-------|-------------|
| Task 1 tests fail | Fix `tokensnapshot.Count` — check bufio scanner buffer size, file open error handling |
| Task 2 compile error | Check `DecisionAttrsForTest` export is in the right package, import path correct |
| Task 3 build fails | Verify `tokensnapshot` import path matches `go.mod` module name |
| Task 4 tests fail | Check `aggregation.add()` — confirm `sid != ""` guard and `sessionLastInterruptToken` initialisation |
| Race detected | Look for concurrent map writes in `aggregation` — it's used single-threaded in stats, so races indicate a test setup problem |
| `session_tokens` absent in live log | Confirm `req.TranscriptPath` is non-empty — Claude Code may not populate it in some hook versions; add debug log in `record()` |

## Notes

- `session_tokens = 0` is the backward-compat sentinel: old log entries omit the field, `ReadRecord.SessionTokens` defaults to 0, token metric is silently skipped for those entries.
- The `/5` divisor is intentionally conservative (JSON transcript has structural overhead). Actual token efficiency depends on content density.
- The `DecisionAttrsForTest` export is the minimal surface needed for test access — keep it test-only, don't call it from production code.
- GitHub issue: [RobinUS2/claude-guard#11](https://github.com/RobinUS2/claude-guard/issues/11)
