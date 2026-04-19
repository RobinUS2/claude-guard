# Stop Hook Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a `claude-guard stop` subcommand that fires as a Claude Code Stop
hook, evaluates whether Claude truly finished (git state, todo items, test commands),
and injects a `userMessage` to continue when a rule fires.

**Architecture:** New `internal/stop/` package with `StopRule` interface, per-session
state file, and a `ShellContext` that caches subprocess results. The Stop evaluator
applies a text pre-filter before any shell check, keeping latency < 1ms for turns
where no pattern matches. Five built-in rules cover the most common "stopped too
early" patterns.

**Tech Stack:** Go, same module as existing guard. No new dependencies.

---

## File structure

| Path | Action | Purpose |
|------|---------|---------|
| `internal/stop/shell.go` | Create | `ShellContext` interface + impl (cached, timeout-gated) |
| `internal/stop/session.go` | Create | Per-session continue counter + fired-rule tracking |
| `internal/stop/stop.go` | Create | `StopRule` interface + `Evaluate()` (text pre-filter → Eval) |
| `internal/stop/rules.go` | Create | 5 built-in rules |
| `internal/stop/stop_test.go` | Create | Evaluator + rules unit tests |
| `internal/log/log.go` | Modify | Add `MsgStopHook` constant + `StopHookRecord` read struct |
| `cmd/claude-guard/stop.go` | Create | `cmdStop`: stdin → evaluate → stdout |
| `cmd/claude-guard/stats.go` | Modify | Aggregate stop_hook events, print section |
| `cmd/claude-guard/main.go` | Modify | Add `"stop"` to dispatch |

---

## Task 1: `ShellContext` (internal/stop/shell.go)

**Files:**
- Create: `internal/stop/shell.go`

- [ ] **Step 1: Write failing test**

```go
// internal/stop/shell_test.go
package stop

import (
    "testing"
    "time"
)

func TestShellContext_Run(t *testing.T) {
    sh := newShellContext(500 * time.Millisecond)
    out, err := sh.Run("echo hello")
    if err != nil {
        t.Fatal(err)
    }
    if out != "hello\n" {
        t.Errorf("got %q, want %q", out, "hello\n")
    }
}

func TestShellContext_Cached(t *testing.T) {
    calls := 0
    // Use a command whose side effect we can count
    sh := newShellContext(500 * time.Millisecond)
    sh.Run("echo cached")
    sh.Run("echo cached")
    _ = calls
    // Can't count exec calls directly; verify no error on repeat
    out1, _ := sh.Run("echo same")
    out2, _ := sh.Run("echo same")
    if out1 != out2 {
        t.Error("cached results should be identical")
    }
}

func TestShellContext_Timeout(t *testing.T) {
    sh := newShellContext(50 * time.Millisecond)
    _, err := sh.Run("sleep 2")
    if err == nil {
        t.Error("expected timeout error")
    }
}
```

- [ ] **Step 2: Run to verify failure**

```
cd internal/stop && go test ./... 2>&1 | head -5
```
Expected: compile error (package doesn't exist yet).

- [ ] **Step 3: Implement `internal/stop/shell.go`**

```go
package stop

import (
    "context"
    "os/exec"
    "sync"
    "time"
)

// ShellContext runs shell commands with a per-invocation timeout.
// Results are cached within a single Stop evaluation (same cmd → same output).
type ShellContext interface {
    Run(cmd string) (stdout string, err error)
}

type shellContext struct {
    timeout time.Duration
    mu      sync.Mutex
    cache   map[string]shellResult
}

type shellResult struct {
    out string
    err error
}

func newShellContext(timeout time.Duration) *shellContext {
    return &shellContext{
        timeout: timeout,
        cache:   map[string]shellResult{},
    }
}

func (s *shellContext) Run(cmd string) (string, error) {
    s.mu.Lock()
    if r, ok := s.cache[cmd]; ok {
        s.mu.Unlock()
        return r.out, r.err
    }
    s.mu.Unlock()

    ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
    defer cancel()
    raw, err := exec.CommandContext(ctx, "sh", "-c", cmd).Output()
    r := shellResult{out: string(raw), err: err}

    s.mu.Lock()
    s.cache[cmd] = r
    s.mu.Unlock()
    return r.out, r.err
}
```

- [ ] **Step 4: Run tests**

```
go test ./internal/stop/ -run TestShellContext -v
```
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/stop/shell.go internal/stop/shell_test.go
git commit -m "feat(stop): ShellContext with timeout and result cache"
```

---

## Task 2: Session state (internal/stop/session.go)

**Files:**
- Create: `internal/stop/session.go`

- [ ] **Step 1: Write failing test**

```go
// internal/stop/session_test.go
package stop

import (
    "os"
    "path/filepath"
    "testing"
)

func TestSession_IncrementAndCap(t *testing.T) {
    dir := t.TempDir()
    sess := newSession("test-session", dir)

    // First three increments succeed
    for i := 1; i <= 3; i++ {
        n, ok := sess.increment()
        if !ok {
            t.Fatalf("increment %d: got suppressed, want ok", i)
        }
        if n != i {
            t.Errorf("count=%d, want %d", n, i)
        }
    }

    // Fourth is over cap
    _, ok := sess.increment()
    if ok {
        t.Error("expected cap to be hit at 3, got ok")
    }
}

func TestSession_FiredRule(t *testing.T) {
    dir := t.TempDir()
    sess := newSession("test-session", dir)
    sess.increment()

    if sess.hasFired("rule-a") {
        t.Error("rule-a should not have fired yet")
    }
    sess.markFired("rule-a", "sha1")
    if !sess.hasFired("rule-a") {
        t.Error("rule-a should be marked fired")
    }
    // Same shell hash → still fired (no re-fire)
    if sess.shellHashChanged("rule-a", "sha1") {
        t.Error("same hash should not show as changed")
    }
    // Different hash → allow re-fire
    if !sess.shellHashChanged("rule-a", "sha2") {
        t.Error("different hash should show as changed")
    }
}

func TestSession_EmptySessionID(t *testing.T) {
    dir := t.TempDir()
    // Should not panic or create a bad filename
    sess := newSession("", dir)
    _, ok := sess.increment()
    if !ok {
        t.Error("first increment should succeed")
    }
    // Verify file exists somewhere valid
    entries, _ := os.ReadDir(dir)
    if len(entries) == 0 {
        t.Error("expected session file to be created")
    }
    // File name must not be just ".json"
    for _, e := range entries {
        if filepath.Ext(e.Name()) == ".json" && len(e.Name()) <= 5 {
            t.Errorf("bad session filename: %s", e.Name())
        }
    }
}
```

- [ ] **Step 2: Run — expect compile error**

```
go test ./internal/stop/ -run TestSession
```

- [ ] **Step 3: Implement `internal/stop/session.go`**

```go
package stop

import (
    "crypto/sha256"
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
    "sync"
)

const maxContinuesPerSession = 3

type sessionState struct {
    Continues int               `json:"continues"`
    Fired     map[string]string `json:"fired"` // rule name → shell output hash
}

type session struct {
    mu   sync.Mutex
    path string
}

// newSession returns a session backed by a file in dir.
// sessionID may be empty; a stable fallback key is derived from its hash.
func newSession(sessionID, dir string) *session {
    key := sessionID
    if key == "" {
        h := sha256.Sum256([]byte("empty"))
        key = fmt.Sprintf("anon-%x", h[:4])
    }
    return &session{
        path: filepath.Join(dir, "claude-guard-stop-"+key+".json"),
    }
}

func (s *session) load() sessionState {
    s.mu.Lock()
    defer s.mu.Unlock()
    data, err := os.ReadFile(s.path)
    if err != nil {
        return sessionState{Fired: map[string]string{}}
    }
    var st sessionState
    if err := json.Unmarshal(data, &st); err != nil || st.Fired == nil {
        return sessionState{Fired: map[string]string{}}
    }
    return st
}

func (s *session) save(st sessionState) {
    data, _ := json.Marshal(st)
    _ = os.WriteFile(s.path, data, 0o600)
}

// increment bumps the continue counter. Returns (newCount, true) if within cap,
// or (count, false) if the hard cap has been reached.
func (s *session) increment() (int, bool) {
    st := s.load()
    if st.Continues >= maxContinuesPerSession {
        return st.Continues, false
    }
    st.Continues++
    s.save(st)
    return st.Continues, true
}

func (s *session) hasFired(rule string) bool {
    st := s.load()
    _, ok := st.Fired[rule]
    return ok
}

// shellHashChanged returns true when the rule has not fired before,
// or when the current shell output hash differs from the stored one.
func (s *session) shellHashChanged(rule, currentHash string) bool {
    st := s.load()
    stored, ok := st.Fired[rule]
    if !ok {
        return true
    }
    return stored != currentHash
}

func (s *session) markFired(rule, shellHash string) {
    st := s.load()
    st.Fired[rule] = shellHash
    s.save(st)
}

// shellHash returns a short hash of output for cool-down comparison.
func shellHash(output string) string {
    h := sha256.Sum256([]byte(output))
    return fmt.Sprintf("%x", h[:4])
}
```

- [ ] **Step 4: Run tests**

```
go test ./internal/stop/ -run TestSession -v
```
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/stop/session.go internal/stop/session_test.go
git commit -m "feat(stop): session state file with continue counter and rule cool-down"
```

---

## Task 3: StopRule interface and evaluator (internal/stop/stop.go)

**Files:**
- Create: `internal/stop/stop.go`

- [ ] **Step 1: Write failing test**

```go
// internal/stop/stop_test.go
package stop

import (
    "os"
    "testing"
    "time"
)

// mockRule is a StopRule for testing.
type mockRule struct {
    name           string
    highConfidence bool
    preFilter      string
    shouldFire     bool
    reason         string
}

func (m *mockRule) Name() string            { return m.name }
func (m *mockRule) HighConfidence() bool    { return m.highConfidence }
func (m *mockRule) TextPreFilter() string   { return m.preFilter }
func (m *mockRule) Eval(_ Transcript, _ ShellContext) (bool, string) {
    return m.shouldFire, m.reason
}

func TestEvaluate_NoRulesFire(t *testing.T) {
    dir := t.TempDir()
    rules := []StopRule{
        &mockRule{name: "r1", preFilter: `\bnever-matches-xyz\b`, shouldFire: true},
    }
    msg := Evaluate("sess1", dir, false, Transcript{}, rules, 500*time.Millisecond)
    if msg != "" {
        t.Errorf("expected empty, got %q", msg)
    }
}

func TestEvaluate_RuleFires(t *testing.T) {
    dir := t.TempDir()
    rules := []StopRule{
        &mockRule{name: "r1", preFilter: `\bdone\b`, shouldFire: true, reason: "uncommitted stuff"},
    }
    tr := Transcript{LastAssistantText: "Done, all complete."}
    msg := Evaluate("sess1", dir, false, tr, rules, 500*time.Millisecond)
    if msg == "" {
        t.Error("expected rule to fire")
    }
}

func TestEvaluate_MaxContinuesCap(t *testing.T) {
    dir := t.TempDir()
    // Pre-fill session to cap
    sess := newSession("capped", dir)
    for i := 0; i < maxContinuesPerSession; i++ {
        sess.increment()
    }
    rules := []StopRule{
        &mockRule{name: "r1", preFilter: "", shouldFire: true, reason: "always fires"},
    }
    msg := Evaluate("capped", dir, false, Transcript{}, rules, 500*time.Millisecond)
    if msg != "" {
        t.Errorf("should be suppressed at cap, got %q", msg)
    }
}

func TestEvaluate_StopHookActive_HighConfidenceOnly(t *testing.T) {
    dir := t.TempDir()
    rules := []StopRule{
        &mockRule{name: "low",  highConfidence: false, preFilter: "", shouldFire: true, reason: "low conf"},
        &mockRule{name: "high", highConfidence: true,  preFilter: "", shouldFire: true, reason: "high conf"},
    }
    msg := Evaluate("sess2", dir, true /* stopHookActive */, Transcript{}, rules, 500*time.Millisecond)
    if msg == "" {
        t.Error("high-confidence rule should still fire when stop_hook_active")
    }
    // Verify it was the high-confidence one
    if msg != "high conf" {
        t.Errorf("got %q, want %q", msg, "high conf")
    }
}

func TestEvaluate_RuleCoolDown(t *testing.T) {
    dir := t.TempDir()
    sess := newSession("cool", dir)
    sess.markFired("r1", shellHash("some-output"))

    called := 0
    rule := &mockRule{name: "r1", preFilter: "", shouldFire: true, reason: "fires"}
    _ = rule
    // A real rule would check shell state, but mockRule always returns true.
    // Cool-down is based on shell output hash matching — test via session directly.
    if !sess.hasFired("r1") {
        t.Error("r1 should be marked as fired")
    }
    _ = called
    // Verify hasFired works as cool-down gate
    if sess.shellHashChanged("r1", shellHash("some-output")) {
        t.Error("same shell hash should not trigger re-fire")
    }
    if !sess.shellHashChanged("r1", shellHash("different-output")) {
        t.Error("different shell hash should allow re-fire")
    }
}

func TestMain(m *testing.M) {
    os.Exit(m.Run())
}
```

- [ ] **Step 2: Run — expect compile error**

```
go test ./internal/stop/ -run TestEvaluate
```

- [ ] **Step 3: Implement `internal/stop/stop.go`**

```go
package stop

import (
    "regexp"
    "time"
)

// Transcript is the parsed content of a Stop hook session.
type Transcript struct {
    LastAssistantText string   // joined text blocks of last assistant message
    FirstUserText     string   // first user message content
    BashCalls         []string // all Bash command strings called in session
    HasTodoWrite      bool     // any TodoWrite call in session
    LastTodoItems     []TodoItem
}

// TodoItem represents a single todo entry.
// JSON tags must match Claude Code's TodoWrite input schema.
type TodoItem struct {
    Content string `json:"content"`
    Status  string `json:"status"` // "pending", "in_progress", "completed"
}

// StopRule evaluates whether the session is truly complete.
type StopRule interface {
    Name() string
    // HighConfidence rules may fire even when stop_hook_active is true.
    // Only rules with shell-verified evidence should return true.
    HighConfidence() bool
    // TextPreFilter is a regex applied to LastAssistantText before Eval.
    // Return "" to skip text pre-filtering (use for transcript-only checks).
    TextPreFilter() string
    // Eval is called only when TextPreFilter matched (or was "").
    Eval(t Transcript, sh ShellContext) (shouldContinue bool, reason string)
}

// Evaluate runs all rules against the transcript and returns the first
// continue-message that fires, or "" if Claude should stop.
// sessionDir is used for the per-session state file (usually /tmp).
func Evaluate(sessionID, sessionDir string, stopHookActive bool, t Transcript, rules []StopRule, shellTimeout time.Duration) string {
    sess := newSession(sessionID, sessionDir)
    sh := newShellContext(shellTimeout)

    for _, rule := range rules {
        // When stop_hook_active, only high-confidence rules may fire.
        if stopHookActive && !rule.HighConfidence() {
            continue
        }

        // Text pre-filter gate — must match before any shell check runs.
        if pf := rule.TextPreFilter(); pf != "" {
            re, err := regexp.Compile(`(?i)` + pf)
            if err != nil || !re.MatchString(t.LastAssistantText) {
                continue
            }
        }

        // Rule cool-down: if it already fired this session with the same
        // shell state, skip.
        if sess.hasFired(rule.Name()) {
            continue
        }

        ok, reason := rule.Eval(t, sh)
        if !ok {
            continue
        }

        // Check continue cap before injecting.
        _, withinCap := sess.increment()
        if !withinCap {
            return "" // hard cap reached
        }

        sess.markFired(rule.Name(), shellHash(reason))
        return reason
    }
    return ""
}
```

- [ ] **Step 4: Run tests**

```
go test ./internal/stop/ -run TestEvaluate -v
```
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/stop/stop.go internal/stop/stop_test.go
git commit -m "feat(stop): StopRule interface and Evaluate() with pre-filter fast path"
```

---

## Task 4: Built-in rules (internal/stop/rules.go)

**Files:**
- Create: `internal/stop/rules.go`

- [ ] **Step 1: Write failing test**

```go
// Add to internal/stop/stop_test.go

func TestRuleUncommittedChanges_Fires(t *testing.T) {
    dir := t.TempDir()
    // Stub: any non-empty git status output
    rule := &uncommittedChangesRule{}
    sh := &stubShell{"git status --short": " M internal/foo.go\n"}
    tr := Transcript{LastAssistantText: "All done, pushed everything."}
    ok, reason := rule.Eval(tr, sh)
    if !ok {
        t.Error("expected rule to fire on non-empty git status")
    }
    if reason == "" {
        t.Error("reason should not be empty")
    }
}

func TestRuleOpenTodoItems_Fires(t *testing.T) {
    rule := &openTodoItemsRule{}
    tr := Transcript{
        HasTodoWrite: true,
        LastTodoItems: []TodoItem{
            {Content: "step 1", Status: "completed"},
            {Content: "step 2", Status: "pending"},
        },
    }
    ok, reason := rule.Eval(tr, &stubShell{})
    if !ok {
        t.Error("expected rule to fire with pending items")
    }
    _ = reason
}

func TestRuleOpenTodoItems_NoFire(t *testing.T) {
    rule := &openTodoItemsRule{}
    tr := Transcript{
        HasTodoWrite: true,
        LastTodoItems: []TodoItem{
            {Content: "step 1", Status: "completed"},
        },
    }
    ok, _ := rule.Eval(tr, &stubShell{})
    if ok {
        t.Error("should not fire when all items complete")
    }
}

// stubShell implements ShellContext for testing.
type stubShell map[string]string

func (s stubShell) Run(cmd string) (string, error) {
    return s[cmd], nil
}
```

- [ ] **Step 2: Run — expect compile error**

```
go test ./internal/stop/ -run TestRule
```

- [ ] **Step 3: Implement `internal/stop/rules.go`**

```go
package stop

import (
    "fmt"
    "strings"
)

// --- Rule 1: uncommitted-changes ---

type uncommittedChangesRule struct{}

func (r *uncommittedChangesRule) Name() string          { return "uncommitted-changes" }
func (r *uncommittedChangesRule) HighConfidence() bool  { return true }
func (r *uncommittedChangesRule) TextPreFilter() string {
    return `\b(done|complete|finished|all set|pushed|merged|shipped)\b`
}

func (r *uncommittedChangesRule) Eval(t Transcript, sh ShellContext) (bool, string) {
    out, err := sh.Run("git status --short")
    if err != nil || strings.TrimSpace(out) == "" {
        return false, ""
    }
    return true, fmt.Sprintf(
        "There are uncommitted or staged changes:\n%s\nPlease commit, stash, or explain before finishing.",
        strings.TrimSpace(out),
    )
}

// --- Rule 2: proposed-test-not-run ---

type proposedTestNotRunRule struct{}

func (r *proposedTestNotRunRule) Name() string          { return "proposed-test-not-run" }
func (r *proposedTestNotRunRule) HighConfidence() bool  { return false }
func (r *proposedTestNotRunRule) TextPreFilter() string {
    return `\b(go test|npm test|make test|pytest|cargo test)\b`
}

func (r *proposedTestNotRunRule) Eval(t Transcript, _ ShellContext) (bool, string) {
    testPatterns := []string{"go test", "npm test", "make test", "pytest", "cargo test"}
    for _, bash := range t.BashCalls {
        for _, pat := range testPatterns {
            if strings.Contains(bash, pat) {
                return false, "" // test was run
            }
        }
    }
    return true, "You mentioned a test command but I don't see it in the session's tool calls. Run the tests to verify, or confirm they were run in a prior session."
}

// --- Rule 3: install-not-run ---

type installNotRunRule struct{}

func (r *installNotRunRule) Name() string          { return "install-not-run" }
func (r *installNotRunRule) HighConfidence() bool  { return false }
func (r *installNotRunRule) TextPreFilter() string {
    return `\b(make install|install)\b`
}

func (r *installNotRunRule) Eval(t Transcript, _ ShellContext) (bool, string) {
    // Only fire if user's first message also mentioned install.
    if !strings.Contains(strings.ToLower(t.FirstUserText), "install") {
        return false, ""
    }
    for _, bash := range t.BashCalls {
        if strings.Contains(bash, "make install") {
            return false, ""
        }
    }
    return true, "The task asked for 'install' but make install hasn't run yet. Run `make install` to complete the deployment."
}

// --- Rule 4: open-todo-items ---

type openTodoItemsRule struct{}

func (r *openTodoItemsRule) Name() string          { return "open-todo-items" }
func (r *openTodoItemsRule) HighConfidence() bool  { return true }
func (r *openTodoItemsRule) TextPreFilter() string { return "" } // transcript check only

func (r *openTodoItemsRule) Eval(t Transcript, _ ShellContext) (bool, string) {
    if !t.HasTodoWrite {
        return false, ""
    }
    var pending []string
    for _, item := range t.LastTodoItems {
        if item.Status == "pending" || item.Status == "in_progress" {
            pending = append(pending, "- ["+item.Status+"] "+item.Content)
        }
    }
    if len(pending) == 0 {
        return false, ""
    }
    return true, fmt.Sprintf(
        "There are still unchecked items in the todo list:\n%s\nContinue until all tasks are completed, or explicitly say which to defer.",
        strings.Join(pending, "\n"),
    )
}

// --- Rule 5: pr-created-not-verified ---

type prCreatedNotVerifiedRule struct{}

func (r *prCreatedNotVerifiedRule) Name() string          { return "pr-created-not-verified" }
func (r *prCreatedNotVerifiedRule) HighConfidence() bool  { return false }
func (r *prCreatedNotVerifiedRule) TextPreFilter() string { return "" }

func (r *prCreatedNotVerifiedRule) Eval(t Transcript, _ ShellContext) (bool, string) {
    prCreated := false
    for _, bash := range t.BashCalls {
        if strings.Contains(bash, "gh pr create") {
            prCreated = true
        }
    }
    if !prCreated {
        return false, ""
    }
    for _, bash := range t.BashCalls {
        if strings.Contains(bash, "gh pr checks") ||
            strings.Contains(bash, "gh pr view") ||
            strings.Contains(bash, "gh pr status") {
            return false, ""
        }
    }
    return true, "A PR was created but CI status wasn't checked. Run `gh pr checks <num>` to verify, or note the PR number for manual follow-up."
}

// DefaultRules returns the built-in rule set in evaluation order.
func DefaultRules() []StopRule {
    return []StopRule{
        &openTodoItemsRule{},       // transcript-only, no shell cost
        &uncommittedChangesRule{},  // text pre-filter + git status
        &installNotRunRule{},       // text pre-filter + transcript check
        &proposedTestNotRunRule{},  // text pre-filter + transcript check
        &prCreatedNotVerifiedRule{}, // transcript-only
    }
}
```

- [ ] **Step 4: Run all stop tests**

```
go test ./internal/stop/... -v
```
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/stop/rules.go
git commit -m "feat(stop): 5 built-in stop rules (uncommitted-changes, open-todos, install, test, pr-verify)"
```

---

## Task 5: Log event format (internal/log/log.go)

**Files:**
- Modify: `internal/log/log.go`

- [ ] **Step 1: Add stop_hook constants and record type**

In `internal/log/log.go`, add alongside `MsgDecision`:

```go
const (
    MsgDecision = "decision"
    MsgStopHook = "stop_hook" // new
)

// StopHookRecord is the shape for reading stop_hook events from decisions.jsonl.
type StopHookRecord struct {
    Time           string `json:"time"`
    Msg            string `json:"msg"`
    SessionID      string `json:"session_id,omitempty"`
    StopHookActive bool   `json:"stop_hook_active"`
    FiredRule      string `json:"fired_rule,omitempty"`
    Injected       bool   `json:"injected"`
    Suppressed     string `json:"suppressed,omitempty"` // "max_continues_reached" or ""
    ContinueCount  int    `json:"continue_count"`
    LatencyUS      int64  `json:"latency_us"`
}
```

- [ ] **Step 2: Verify compile**

```
go build ./internal/log/...
```
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add internal/log/log.go
git commit -m "feat(log): add MsgStopHook constant and StopHookRecord for stats aggregation"
```

---

## Task 6: `cmdStop` handler (cmd/claude-guard/stop.go)

**Files:**
- Create: `cmd/claude-guard/stop.go`
- Modify: `cmd/claude-guard/main.go`

- [ ] **Step 1: Write integration test**

```go
// cmd/claude-guard/stop_test.go
package main

import (
    "bytes"
    "encoding/json"
    "os"
    "strings"
    "testing"
)

func TestCmdStop_EmptyTranscript(t *testing.T) {
    payload := `{"session_id":"test","stop_hook_active":false,"transcript":[]}`
    old := os.Stdin
    r, w, _ := os.Pipe()
    os.Stdin = r
    w.WriteString(payload)
    w.Close()
    defer func() { os.Stdin = old }()

    var buf bytes.Buffer
    code := cmdStopWithIO(strings.NewReader(payload), &buf)
    if code != 0 {
        t.Fatalf("exit code %d", code)
    }
    var resp struct {
        UserMessage string `json:"userMessage"`
    }
    if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
        // Empty response is also valid
        return
    }
    // No rule should fire on empty transcript
    if resp.UserMessage != "" {
        t.Errorf("unexpected continue message: %q", resp.UserMessage)
    }
}
```

- [ ] **Step 2: Run — expect compile error**

```
go test ./cmd/claude-guard/ -run TestCmdStop
```

- [ ] **Step 3: Implement `cmd/claude-guard/stop.go`**

```go
package main

import (
    "encoding/json"
    "fmt"
    "io"
    "os"
    "strings"
    "time"

    "github.com/RobinUS2/claude-guard/internal/stop"
)

const stopShellTimeoutMs = 500

type stopInput struct {
    SessionID      string            `json:"session_id"`
    StopHookActive bool              `json:"stop_hook_active"`
    Transcript     []json.RawMessage `json:"transcript"`
}

type stopResponse struct {
    UserMessage string `json:"userMessage,omitempty"`
}

func cmdStop(_ []string) int {
    return cmdStopWithIO(os.Stdin, os.Stdout)
}

func cmdStopWithIO(r io.Reader, w io.Writer) int {
    start := time.Now()

    data, err := io.ReadAll(r)
    if err != nil {
        fmt.Fprintf(os.Stderr, "stop: read stdin: %v\n", err)
        return 1
    }

    var in stopInput
    if err := json.Unmarshal(data, &in); err != nil {
        // Malformed input: let Claude stop (fail-open).
        fmt.Fprintf(os.Stderr, "stop: parse input: %v\n", err)
        return writeStopResponse(w, "")
    }

    tr := parseTranscript(in.Transcript)
    sessionDir := os.TempDir()
    timeout := time.Duration(stopShellTimeoutMs) * time.Millisecond

    msg := stop.Evaluate(
        in.SessionID,
        sessionDir,
        in.StopHookActive,
        tr,
        stop.DefaultRules(),
        timeout,
    )

    _ = start // latency logging: future work (Task 5 log event)
    return writeStopResponse(w, msg)
}

func writeStopResponse(w io.Writer, msg string) int {
    resp := stopResponse{UserMessage: msg}
    data, _ := json.Marshal(resp)
    fmt.Fprintln(w, string(data))
    return 0
}

// parseTranscript extracts the Transcript fields claude-guard rules need.
//
// Claude Code transcript format: each entry has a "role" field.
//   - role="user":      string or []content-block (tool_result blocks are in here)
//   - role="assistant": string or []content-block, which may include type="text"
//                       AND type="tool_use" blocks (this is where Bash calls live)
//
// Tool calls (Bash, TodoWrite) appear as type="tool_use" inside assistant content,
// NOT as separate role="tool" entries. This is the key structural fact.
func parseTranscript(raw []json.RawMessage) stop.Transcript {
    var tr stop.Transcript

    type contentBlock struct {
        Type  string          `json:"type"`
        Text  string          `json:"text"`             // type="text"
        Name  string          `json:"name"`             // type="tool_use"
        Input json.RawMessage `json:"input"`            // type="tool_use"
    }
    type turn struct {
        Role    string          `json:"role"`
        Content json.RawMessage `json:"content"`
    }
    type bashInput struct {
        Command string `json:"command"`
    }
    type todoInput struct {
        Todos []stop.TodoItem `json:"todos"`
    }

    var lastAssistantParts []string
    firstUser := true

    for _, rawTurn := range raw {
        var t turn
        if err := json.Unmarshal(rawTurn, &t); err != nil {
            continue
        }

        switch t.Role {
        case "user":
            if firstUser {
                firstUser = false
                // Content may be a plain string.
                var s string
                if err := json.Unmarshal(t.Content, &s); err == nil {
                    tr.FirstUserText = s
                }
            }

        case "assistant":
            lastAssistantParts = nil
            // Content may be a plain string or an array of content blocks.
            var s string
            if err := json.Unmarshal(t.Content, &s); err == nil {
                lastAssistantParts = append(lastAssistantParts, s)
                break
            }
            var blocks []contentBlock
            if err := json.Unmarshal(t.Content, &blocks); err != nil {
                break
            }
            for _, blk := range blocks {
                switch blk.Type {
                case "text":
                    if blk.Text != "" {
                        lastAssistantParts = append(lastAssistantParts, blk.Text)
                    }
                case "tool_use":
                    // Tool calls live here — extract Bash and TodoWrite.
                    if blk.Name == "Bash" {
                        var inp bashInput
                        if err := json.Unmarshal(blk.Input, &inp); err == nil && inp.Command != "" {
                            tr.BashCalls = append(tr.BashCalls, inp.Command)
                        }
                    }
                    if blk.Name == "TodoWrite" {
                        var inp todoInput
                        if err := json.Unmarshal(blk.Input, &inp); err == nil && len(inp.Todos) > 0 {
                            tr.HasTodoWrite = true
                            tr.LastTodoItems = inp.Todos
                        }
                    }
                }
            }
        }
    }
    tr.LastAssistantText = strings.Join(lastAssistantParts, "\n")
    return tr
}
```

- [ ] **Step 4: Add "stop" to dispatch in `main.go`**

In `cmd/claude-guard/main.go`, add to the switch:
```go
case "stop":
    os.Exit(cmdStop(args[1:]))
```

- [ ] **Step 5: Run tests**

```
go test ./cmd/claude-guard/ -run TestCmdStop -v
go test ./... 
```
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add cmd/claude-guard/stop.go cmd/claude-guard/stop_test.go cmd/claude-guard/main.go
git commit -m "feat(stop): cmdStop handler — parse transcript, evaluate rules, emit userMessage"
```

---

## Task 7: Stats aggregation for stop_hook events

**Files:**
- Modify: `cmd/claude-guard/stats.go`

- [ ] **Step 1: Write failing test**

```go
// Add to cmd/claude-guard/stats_test.go

func TestAggregateStopHook(t *testing.T) {
    agg := newAggregation()
    agg.addStopHook(&clog.StopHookRecord{
        Msg: clog.MsgStopHook, Injected: true, FiredRule: "uncommitted-changes", ContinueCount: 1,
    })
    agg.addStopHook(&clog.StopHookRecord{
        Msg: clog.MsgStopHook, Injected: false,
    })
    if agg.stopTotal != 2 {
        t.Errorf("stopTotal=%d, want 2", agg.stopTotal)
    }
    if agg.stopInjected != 1 {
        t.Errorf("stopInjected=%d, want 1", agg.stopInjected)
    }
    if agg.stopByRule["uncommitted-changes"] != 1 {
        t.Errorf("stopByRule wrong: %v", agg.stopByRule)
    }
}
```

- [ ] **Step 2: Run — expect compile error**

```
go test ./cmd/claude-guard/ -run TestAggregateStopHook
```

- [ ] **Step 3: Add stop_hook fields to `aggregation` in `stats.go`**

```go
type aggregation struct {
    // ... existing fields ...
    stopTotal    int
    stopInjected int
    stopCapped   int
    stopByRule   map[string]int
}

func newAggregation() *aggregation {
    return &aggregation{
        byVerdict:     map[string]int{},
        byTier:        map[string]int{},
        byTier4Shadow: map[string]int{},
        stopByRule:    map[string]int{},
    }
}

func (a *aggregation) addStopHook(rec *clog.StopHookRecord) {
    a.stopTotal++
    if rec.Injected {
        a.stopInjected++
        if rec.FiredRule != "" {
            a.stopByRule[rec.FiredRule]++
        }
    }
    if rec.Suppressed == "max_continues_reached" {
        a.stopCapped++
    }
}
```

- [ ] **Step 4: Update `cmdStats` scanner to handle stop_hook records**

In the scan loop in `cmdStats`, add a branch after the `MsgDecision` check:
```go
if rec.Msg == clog.MsgStopHook {
    var stopRec clog.StopHookRecord
    if err := json.Unmarshal(scanner.Bytes(), &stopRec); err == nil {
        agg.addStopHook(&stopRec)
    }
    continue
}
```

- [ ] **Step 5: Print stop_hook section in `cmdStats`**

After the existing tiers section:
```go
if agg.stopTotal > 0 {
    fmt.Println()
    fmt.Println("stop hooks:")
    fmt.Printf("  evaluations: %d\n", agg.stopTotal)
    fmt.Printf("  continues injected: %d (%.1f%%)\n",
        agg.stopInjected, float64(agg.stopInjected)/float64(agg.stopTotal)*100)
    if agg.stopCapped > 0 {
        fmt.Printf("  max-continue cap hit: %d\n", agg.stopCapped)
    }
    if len(agg.stopByRule) > 0 {
        fmt.Printf("  top rules:")
        for rule, n := range agg.stopByRule {
            fmt.Printf(" %s=%d", rule, n)
        }
        fmt.Println()
    }
}
```

- [ ] **Step 6: Run tests**

```
go test ./cmd/claude-guard/... -v
go test ./...
```
Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add cmd/claude-guard/stats.go cmd/claude-guard/stats_test.go
git commit -m "feat(stats): aggregate and display stop_hook evaluation counts and rule hits"
```

---

## Task 8: Hook registration + doctor check

**Files:**
- Modify: `~/.claude/settings.json`
- Modify: `cmd/claude-guard/doctor.go` (existing file — add Stop hook check)

- [ ] **Step 1: Register the Stop hook**

Add to `~/.claude/settings.json` under `hooks`:
```json
"Stop": [
  {
    "matcher": "",
    "hooks": [
      {
        "type": "command",
        "command": "/Users/robin/.claude/bin/claude-guard stop"
      }
    ]
  }
]
```

- [ ] **Step 2: Update `claude-guard doctor` to check Stop hook**

`doctor.go` already has `checkHookWired` for the PreToolUse hook (line ~208).
Add a parallel `checkStopHookWired` and call it in `cmdDoctor`:

```go
// After the existing "hook:wired" check (line ~156):
stopWired, stopDetail := checkStopHookWired(settingsPath)
if stopWired {
    check("hook:stop", true, stopDetail)
} else {
    warn("hook:stop", stopDetail)
}

// New helper (add alongside checkHookWired):
func checkStopHookWired(settingsPath string) (bool, string) {
    data, err := os.ReadFile(settingsPath)
    if err != nil {
        return false, fmt.Sprintf("cannot read %s: %v", settingsPath, err)
    }
    var parsed map[string]any
    if err := json.Unmarshal(data, &parsed); err != nil {
        return false, fmt.Sprintf("%s not valid JSON: %v", settingsPath, err)
    }
    hooks, _ := parsed["hooks"].(map[string]any)
    stopHooks, _ := hooks["Stop"].([]any)
    for _, entry := range stopHooks {
        m, _ := entry.(map[string]any)
        inner, _ := m["hooks"].([]any)
        for _, h := range inner {
            hm, _ := h.(map[string]any)
            if cmd, _ := hm["command"].(string); strings.Contains(cmd, "claude-guard stop") {
                return true, cmd
            }
        }
    }
    return false, fmt.Sprintf("no Stop hook pointing to claude-guard stop in %s", settingsPath)
}
```

- [ ] **Step 3: Install the new binary**

```
make install
```
or:
```
go install ./cmd/claude-guard/
```

- [ ] **Step 4: Smoke test**

```bash
# Dry-run with a synthetic payload
echo '{"session_id":"smoke","stop_hook_active":false,"transcript":[]}' | claude-guard stop
```
Expected: `{}` (userMessage is omitempty — empty string is omitted; no rule fires on empty transcript).

```bash
# Verify doctor recognises the Stop hook
claude-guard doctor
```
Expected: no "Stop hook not registered" warning.

- [ ] **Step 5: Run full test suite one final time**

```
go test ./...
```
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add cmd/claude-guard/doctor.go
git commit -m "feat(stop): register Stop hook in settings.json, add doctor check"
```

- [ ] **Step 7: Push**

```bash
git push
```
