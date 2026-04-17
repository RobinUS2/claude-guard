# File Content Analysis + Daily Budget Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the tier 4 LLM see file contents for runner commands (`go run`, `python`, etc.), reducing false positives. Add daily LLM call budgets to control cost.

**Architecture:** Three new packages (`internal/budget/`, `internal/filectx/`) plus extensions to existing packages (`internal/llm/`, `internal/cache/`, `internal/config/`, `internal/engine/`, `cmd/claude-guard/`). Budget is checked before file analysis and before every LLM call. File content is included in the existing LLM prompt as a new section.

**Tech Stack:** Go, file I/O, SHA-256 hashing, JSON file-based counters.

**Spec:** `docs/plans/2026-04-17-file-content-analysis-design.md`

---

### Task 1: Daily Budget Package (`internal/budget/`)

**Files:**
- Create: `internal/budget/budget.go`
- Create: `internal/budget/budget_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/budget/budget_test.go`:

```go
package budget

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCheck_UnderBudget(t *testing.T) {
	dir := t.TempDir()
	b := New(dir, 500, 50)
	if !b.Check(false) {
		t.Fatal("fresh budget should allow LLM calls")
	}
	if !b.Check(true) {
		t.Fatal("fresh budget should allow file-analysis calls")
	}
}

func TestRecord_IncrementsCounters(t *testing.T) {
	dir := t.TempDir()
	b := New(dir, 500, 50)

	b.Record(false) // LLM-only
	b.Record(true)  // LLM + file

	s := b.Status()
	if s.LLMUsed != 2 {
		t.Errorf("LLMUsed = %d, want 2", s.LLMUsed)
	}
	if s.FileUsed != 1 {
		t.Errorf("FileUsed = %d, want 1", s.FileUsed)
	}
}

func TestCheck_GlobalBudgetExhausted(t *testing.T) {
	dir := t.TempDir()
	b := New(dir, 3, 50) // 3 LLM calls max

	b.Record(false)
	b.Record(false)
	b.Record(false)

	if b.Check(false) {
		t.Fatal("should reject when global LLM budget exhausted")
	}
	// File analysis also rejected because it consumes a global call too.
	if b.Check(true) {
		t.Fatal("file-analysis should also reject when global budget exhausted")
	}
}

func TestCheck_FileBudgetExhausted_LLMStillAllowed(t *testing.T) {
	dir := t.TempDir()
	b := New(dir, 500, 2) // 2 file-analysis calls max

	b.Record(true)
	b.Record(true)

	if b.Check(true) {
		t.Fatal("should reject file-analysis when file budget exhausted")
	}
	if !b.Check(false) {
		t.Fatal("plain LLM should still be allowed when only file budget is exhausted")
	}
}

func TestDateRollover(t *testing.T) {
	dir := t.TempDir()
	b := New(dir, 500, 50)

	// Record some usage.
	b.Record(false)
	b.Record(true)

	// Simulate a date rollover by writing a stale date into the file.
	path := filepath.Join(dir, budgetFileName)
	data := []byte(`{"date":"2020-01-01","llm_calls":499,"file_analysis_calls":49}`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	// Re-create budget to force file re-read.
	b2 := New(dir, 500, 50)
	s := b2.Status()
	if s.LLMUsed != 0 {
		t.Errorf("after date rollover LLMUsed = %d, want 0", s.LLMUsed)
	}
	if s.FileUsed != 0 {
		t.Errorf("after date rollover FileUsed = %d, want 0", s.FileUsed)
	}
}

func TestStatus_ReturnsLimits(t *testing.T) {
	dir := t.TempDir()
	b := New(dir, 500, 50)
	s := b.Status()
	if s.LLMLimit != 500 {
		t.Errorf("LLMLimit = %d, want 500", s.LLMLimit)
	}
	if s.FileLimit != 50 {
		t.Errorf("FileLimit = %d, want 50", s.FileLimit)
	}
}

func TestPersistence_AcrossInstances(t *testing.T) {
	dir := t.TempDir()
	b1 := New(dir, 500, 50)
	b1.Record(false)
	b1.Record(true)

	// New instance reads from same file.
	b2 := New(dir, 500, 50)
	s := b2.Status()
	if s.LLMUsed != 2 {
		t.Errorf("LLMUsed = %d, want 2 (persisted)", s.LLMUsed)
	}
	if s.FileUsed != 1 {
		t.Errorf("FileUsed = %d, want 1 (persisted)", s.FileUsed)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd ~/Documents/code/claude-guard && go test ./internal/budget/ -v`
Expected: compilation error — package does not exist yet.

- [ ] **Step 3: Write the implementation**

Create `internal/budget/budget.go`:

```go
// Package budget enforces daily call limits for the LLM tier.
// Two independent budgets: global LLM calls and file-analysis calls
// (a subset). File-analysis calls count against both.
//
// Storage is a single JSON file at <cacheDir>/daily-budget.json.
// Date-based rollover: if the stored date doesn't match today,
// counters reset to zero on first access.
package budget

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const budgetFileName = "daily-budget.json"

// StatusInfo holds current usage and limits for display.
type StatusInfo struct {
	LLMUsed   int
	LLMLimit  int
	FileUsed  int
	FileLimit int
}

// state is the on-disk shape of the budget file.
type state struct {
	Date              string `json:"date"`
	LLMCalls          int    `json:"llm_calls"`
	FileAnalysisCalls int    `json:"file_analysis_calls"`
}

// Budget tracks daily LLM call counts.
type Budget struct {
	path      string
	llmLimit  int
	fileLimit int
	mu        sync.Mutex
}

// New creates a budget tracker. cacheDir is typically
// ~/.cache/claude-guard. llmLimit and fileLimit are the daily caps.
func New(cacheDir string, llmLimit, fileLimit int) *Budget {
	return &Budget{
		path:      filepath.Join(cacheDir, budgetFileName),
		llmLimit:  llmLimit,
		fileLimit: fileLimit,
	}
}

// Check reports whether a call is within budget.
// If withFileContent is true, both global and file budgets are checked.
func (b *Budget) Check(withFileContent bool) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.load()
	if s.LLMCalls >= b.llmLimit {
		return false
	}
	if withFileContent && s.FileAnalysisCalls >= b.fileLimit {
		return false
	}
	return true
}

// Record increments counters after a successful call.
// If withFileContent is true, both counters are incremented.
func (b *Budget) Record(withFileContent bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.load()
	s.LLMCalls++
	if withFileContent {
		s.FileAnalysisCalls++
	}
	b.save(s)
}

// Status returns current usage and limits.
func (b *Budget) Status() StatusInfo {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.load()
	return StatusInfo{
		LLMUsed:   s.LLMCalls,
		LLMLimit:  b.llmLimit,
		FileUsed:  s.FileAnalysisCalls,
		FileLimit: b.fileLimit,
	}
}

func (b *Budget) load() state {
	data, err := os.ReadFile(b.path)
	if err != nil {
		return state{Date: today()}
	}
	var s state
	if err := json.Unmarshal(data, &s); err != nil {
		return state{Date: today()}
	}
	// Date rollover — reset counters.
	if s.Date != today() {
		return state{Date: today()}
	}
	return s
}

func (b *Budget) save(s state) {
	s.Date = today()
	data, err := json.Marshal(s)
	if err != nil {
		return
	}
	// Ensure directory exists (fresh install may not have it yet).
	if dir := filepath.Dir(b.path); dir != "" {
		_ = os.MkdirAll(dir, 0o755)
	}
	// Atomic write: tmp + rename.
	tmp := b.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		// Best effort — a lost write means slightly under-counted.
		return
	}
	_ = os.Rename(tmp, b.path)
}

func today() string {
	return time.Now().Format("2006-01-02")
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd ~/Documents/code/claude-guard && go test ./internal/budget/ -v`
Expected: all 6 tests PASS.

- [ ] **Step 5: Commit**

```bash
cd ~/Documents/code/claude-guard
git add internal/budget/budget.go internal/budget/budget_test.go
git commit -m "budget: daily LLM call limit with file-analysis sub-budget"
```

---

### Task 2: File Content Extraction Package (`internal/filectx/`)

**Files:**
- Create: `internal/filectx/filectx.go`
- Create: `internal/filectx/filectx_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/filectx/filectx_test.go`:

```go
package filectx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RobinUS2/claude-guard/internal/shellparse"
)

func parseFirst(t *testing.T, cmd string) shellparse.Call {
	t.Helper()
	p, err := shellparse.Parse(cmd)
	if err != nil {
		t.Fatalf("parse %q: %v", cmd, err)
	}
	if len(p.Calls) == 0 {
		t.Fatalf("no calls in %q", cmd)
	}
	return p.Calls[0]
}

func TestExtract_GoRun(t *testing.T) {
	f := filepath.Join(t.TempDir(), "main.go")
	os.WriteFile(f, []byte("package main\nfunc main() {}\n"), 0o644)

	call := parseFirst(t, "go run "+f)
	fc := Extract(call)
	if fc == nil {
		t.Fatal("expected FileContext for go run")
	}
	if fc.Skipped {
		t.Fatalf("unexpected skip: %s", fc.Reason)
	}
	if fc.Content == "" {
		t.Fatal("expected file content")
	}
	if fc.Path != f {
		t.Errorf("Path = %q, want %q", fc.Path, f)
	}
}

func TestExtract_PythonScript(t *testing.T) {
	f := filepath.Join(t.TempDir(), "script.py")
	os.WriteFile(f, []byte("print('hello')\n"), 0o644)

	call := parseFirst(t, "python3 "+f)
	fc := Extract(call)
	if fc == nil {
		t.Fatal("expected FileContext for python3")
	}
	if fc.Skipped {
		t.Fatalf("unexpected skip: %s", fc.Reason)
	}
	if !strings.Contains(fc.Content, "hello") {
		t.Errorf("content missing expected text: %q", fc.Content)
	}
}

func TestExtract_NodeScript(t *testing.T) {
	f := filepath.Join(t.TempDir(), "app.js")
	os.WriteFile(f, []byte("console.log('hi')\n"), 0o644)

	call := parseFirst(t, "node "+f)
	fc := Extract(call)
	if fc == nil {
		t.Fatal("expected FileContext for node")
	}
	if fc.Skipped {
		t.Fatalf("unexpected skip: %s", fc.Reason)
	}
}

func TestExtract_NotARunner(t *testing.T) {
	call := parseFirst(t, "git status")
	fc := Extract(call)
	if fc != nil {
		t.Fatalf("expected nil for non-runner, got %+v", fc)
	}
}

func TestExtract_FileTooLarge(t *testing.T) {
	f := filepath.Join(t.TempDir(), "big.go")
	os.WriteFile(f, make([]byte, MaxFileSize+1), 0o644)

	call := parseFirst(t, "go run "+f)
	fc := Extract(call)
	if fc == nil {
		t.Fatal("expected FileContext")
	}
	if !fc.Skipped {
		t.Fatal("expected Skipped for large file")
	}
	if !strings.Contains(fc.Reason, "exceeds") {
		t.Errorf("Reason = %q, want 'exceeds' substring", fc.Reason)
	}
}

func TestExtract_BinaryFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "binary.py")
	data := make([]byte, 100)
	data[50] = 0x00 // null byte
	os.WriteFile(f, data, 0o644)

	call := parseFirst(t, "python3 "+f)
	fc := Extract(call)
	if fc == nil {
		t.Fatal("expected FileContext")
	}
	if !fc.Skipped {
		t.Fatal("expected Skipped for binary file")
	}
	if !strings.Contains(fc.Reason, "binary") {
		t.Errorf("Reason = %q, want 'binary' substring", fc.Reason)
	}
}

func TestExtract_Symlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.go")
	link := filepath.Join(dir, "link.go")
	os.WriteFile(real, []byte("package main\n"), 0o644)
	os.Symlink(real, link)

	call := parseFirst(t, "go run "+link)
	fc := Extract(call)
	if fc == nil {
		t.Fatal("expected FileContext")
	}
	if !fc.Skipped {
		t.Fatal("expected Skipped for symlink")
	}
	if !strings.Contains(fc.Reason, "symlink") {
		t.Errorf("Reason = %q, want 'symlink' substring", fc.Reason)
	}
}

func TestExtract_FileNotFound(t *testing.T) {
	call := parseFirst(t, "go run /nonexistent/path/main.go")
	fc := Extract(call)
	if fc == nil {
		t.Fatal("expected FileContext")
	}
	if !fc.Skipped {
		t.Fatal("expected Skipped for missing file")
	}
	if !strings.Contains(fc.Reason, "not found") {
		t.Errorf("Reason = %q, want 'not found' substring", fc.Reason)
	}
}

func TestExtract_GoRunWithFlags(t *testing.T) {
	f := filepath.Join(t.TempDir(), "main.go")
	os.WriteFile(f, []byte("package main\nfunc main() {}\n"), 0o644)

	// go run -v main.go — flags before the file arg.
	call := parseFirst(t, "go run -v "+f)
	fc := Extract(call)
	if fc == nil {
		t.Fatal("expected FileContext for go run with flags")
	}
	if fc.Skipped {
		t.Fatalf("unexpected skip: %s", fc.Reason)
	}
}

func TestExtract_DenoRun(t *testing.T) {
	f := filepath.Join(t.TempDir(), "app.ts")
	os.WriteFile(f, []byte("console.log('deno')\n"), 0o644)

	call := parseFirst(t, "deno run "+f)
	fc := Extract(call)
	if fc == nil {
		t.Fatal("expected FileContext for deno run")
	}
	if fc.Skipped {
		t.Fatalf("unexpected skip: %s", fc.Reason)
	}
}

func TestExtract_RubyScript(t *testing.T) {
	f := filepath.Join(t.TempDir(), "script.rb")
	os.WriteFile(f, []byte("puts 'hello'\n"), 0o644)

	call := parseFirst(t, "ruby "+f)
	fc := Extract(call)
	if fc == nil {
		t.Fatal("expected FileContext for ruby")
	}
	if fc.Skipped {
		t.Fatalf("unexpected skip: %s", fc.Reason)
	}
}

func TestExtract_TsxScript(t *testing.T) {
	f := filepath.Join(t.TempDir(), "run.ts")
	os.WriteFile(f, []byte("console.log('tsx')\n"), 0o644)

	call := parseFirst(t, "tsx "+f)
	fc := Extract(call)
	if fc == nil {
		t.Fatal("expected FileContext for tsx")
	}
	if fc.Skipped {
		t.Fatalf("unexpected skip: %s", fc.Reason)
	}
}

func TestExtract_BunRunScriptName_ReturnsNil(t *testing.T) {
	// "bun run dev" is a package.json script, not a file — should return nil.
	call := parseFirst(t, "bun run dev")
	fc := Extract(call)
	if fc != nil {
		t.Fatalf("expected nil for bun run script name, got %+v", fc)
	}
}

func TestExtract_BunRunFilePath(t *testing.T) {
	f := filepath.Join(t.TempDir(), "app.ts")
	os.WriteFile(f, []byte("console.log('bun')\n"), 0o644)

	call := parseFirst(t, "bun run "+f)
	fc := Extract(call)
	if fc == nil {
		t.Fatal("expected FileContext for bun run with file path")
	}
	if fc.Skipped {
		t.Fatalf("unexpected skip: %s", fc.Reason)
	}
}

func TestExtract_CompoundCommand_FirstRunnerOnly(t *testing.T) {
	// "go run /tmp/test.go && echo done" — parseFirst returns "go" call.
	f := filepath.Join(t.TempDir(), "test.go")
	os.WriteFile(f, []byte("package main\nfunc main() {}\n"), 0o644)

	// Parse full compound command, extract from first call.
	p, err := shellparse.Parse("go run " + f + " && echo done")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Calls) < 1 {
		t.Fatal("expected at least 1 call")
	}
	fc := Extract(p.Calls[0])
	if fc == nil {
		t.Fatal("expected FileContext from first call of compound command")
	}
	if fc.Skipped {
		t.Fatalf("unexpected skip: %s", fc.Reason)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd ~/Documents/code/claude-guard && go test ./internal/filectx/ -v`
Expected: compilation error — package does not exist yet.

- [ ] **Step 3: Write the implementation**

Create `internal/filectx/filectx.go`:

```go
// Package filectx detects runner commands (go run, python, node, etc.)
// and extracts the contents of the referenced file for LLM analysis.
//
// Security constraints:
//   - No symlink following (os.Lstat, not os.Stat)
//   - Max file size enforced (20KB)
//   - Binary files detected and skipped (null byte check)
//   - Read-only: never modifies files
//   - Only the directly referenced file, no transitive imports
package filectx

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/RobinUS2/claude-guard/internal/shellparse"
)

// MaxFileSize is the largest file we'll read. Files exceeding this are
// skipped — the LLM classifies based on the command string alone.
const MaxFileSize = 20 * 1024 // 20KB

// FileContext holds the result of examining a runner command.
type FileContext struct {
	Path    string // absolute path of the file
	Content string // file contents (empty if skipped)
	Size    int64  // file size in bytes
	Skipped bool   // true if file was detected but not read
	Reason  string // why it was skipped
}

// runner defines a program that executes a file argument.
type runner struct {
	program   string // e.g. "go", "python3"
	subcmd    string // e.g. "run" (empty = file is first positional)
}

// runners is the known runner table. Order doesn't matter — we match
// on program name.
var runners = []runner{
	{program: "go", subcmd: "run"},
	{program: "python"},
	{program: "python3"},
	{program: "node"},
	{program: "tsx"},
	{program: "deno", subcmd: "run"},
	{program: "ruby"},
	{program: "bun", subcmd: "run"},
}

// Extract examines a parsed command and returns file context if the
// command is a runner with a readable file argument. Returns nil if
// the command is not a runner pattern.
func Extract(call shellparse.Call) *FileContext {
	prog := strings.ToLower(call.Program)
	if prog == "" {
		return nil
	}

	for _, r := range runners {
		if prog != r.program {
			continue
		}
		filePath := findFileArg(call, r)
		if filePath == "" {
			return nil
		}
		return readFile(filePath)
	}
	return nil
}

// findFileArg locates the file argument in the parsed call based on
// the runner definition.
func findFileArg(call shellparse.Call, r runner) string {
	positionals := call.Positional
	if len(positionals) == 0 {
		return ""
	}

	if r.subcmd == "" {
		// File is the first positional that looks like a file path
		// (not a flag). Positional already excludes flags.
		for _, p := range positionals {
			if p != "" {
				return p
			}
		}
		return ""
	}

	// Has subcommand (e.g. "go run"): find subcmd in positionals,
	// then the file arg is the next non-empty positional after it.
	found := false
	for _, p := range positionals {
		if !found {
			if strings.ToLower(p) == r.subcmd {
				found = true
			}
			continue
		}
		// Skip empty (unresolved) args.
		if p != "" {
			// For "bun run", distinguish script names from file paths.
			// File paths contain a slash or have a known extension.
			if r.program == "bun" && !looksLikeFilePath(p) {
				return ""
			}
			return p
		}
	}
	return ""
}

// looksLikeFilePath returns true if the argument looks like a file path
// rather than a package.json script name.
func looksLikeFilePath(arg string) bool {
	if strings.Contains(arg, "/") || strings.Contains(arg, "\\") {
		return true
	}
	// Check for common source file extensions.
	for _, ext := range []string{".go", ".py", ".js", ".ts", ".tsx", ".jsx", ".rb", ".mjs", ".cjs"} {
		if strings.HasSuffix(strings.ToLower(arg), ext) {
			return true
		}
	}
	return false
}

// readFile reads the file at path with all safety checks.
func readFile(path string) *FileContext {
	fc := &FileContext{Path: path}

	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		fc.Skipped = true
		fc.Reason = "file not found"
		return fc
	}
	if err != nil {
		fc.Skipped = true
		fc.Reason = fmt.Sprintf("stat error: %v", err)
		return fc
	}

	// No symlinks.
	if info.Mode()&os.ModeSymlink != 0 {
		fc.Skipped = true
		fc.Reason = "symlink — not followed for security"
		return fc
	}
	if !info.Mode().IsRegular() {
		fc.Skipped = true
		fc.Reason = "not a regular file"
		return fc
	}

	fc.Size = info.Size()
	if fc.Size > MaxFileSize {
		fc.Skipped = true
		fc.Reason = fmt.Sprintf("exceeds %dKB limit (%d bytes)", MaxFileSize/1024, fc.Size)
		return fc
	}

	data, err := os.ReadFile(path)
	if err != nil {
		fc.Skipped = true
		fc.Reason = fmt.Sprintf("read error: %v", err)
		return fc
	}

	// Binary check: look for null bytes in first 512 bytes.
	check := data
	if len(check) > 512 {
		check = check[:512]
	}
	if bytes.ContainsByte(check, 0) {
		fc.Skipped = true
		fc.Reason = "binary file detected (null bytes)"
		return fc
	}

	fc.Content = string(data)
	return fc
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd ~/Documents/code/claude-guard && go test ./internal/filectx/ -v`
Expected: all 12 tests PASS.

- [ ] **Step 5: Commit**

```bash
cd ~/Documents/code/claude-guard
git add internal/filectx/filectx.go internal/filectx/filectx_test.go
git commit -m "filectx: extract file contents from runner commands for LLM analysis"
```

---

### Task 3: Config Extension for Daily Budget

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/config/config_test.go`:

```go
func TestDefault_HasBudgetDefaults(t *testing.T) {
	cfg := Default()
	if cfg.DailyBudget.LLMCalls != 500 {
		t.Errorf("DailyBudget.LLMCalls = %d, want 500", cfg.DailyBudget.LLMCalls)
	}
	if cfg.DailyBudget.FileAnalysisCalls != 50 {
		t.Errorf("DailyBudget.FileAnalysisCalls = %d, want 50", cfg.DailyBudget.FileAnalysisCalls)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/Documents/code/claude-guard && go test ./internal/config/ -run TestDefault_HasBudgetDefaults -v`
Expected: FAIL — `cfg.DailyBudget` undefined.

- [ ] **Step 3: Add DailyBudget to config**

In `internal/config/config.go`, add the struct and field:

Add after the `Legacy` struct (around line 80):

```go
// DailyBudget caps daily LLM calls to control cost.
type DailyBudget struct {
	LLMCalls          int `yaml:"llm_calls"`
	FileAnalysisCalls int `yaml:"file_analysis_calls"`
}
```

Add to the `Config` struct (after the `Legacy` field on line 40):

```go
	DailyBudget DailyBudget `yaml:"daily_budget"`
```

Add defaults in `Default()` (inside the return block, after `Legacy`):

```go
		DailyBudget: DailyBudget{
			LLMCalls:          500,
			FileAnalysisCalls: 50,
		},
```

- [ ] **Step 4: Run all config tests**

Run: `cd ~/Documents/code/claude-guard && go test ./internal/config/ -v`
Expected: all tests PASS (including the new one).

- [ ] **Step 5: Commit**

```bash
cd ~/Documents/code/claude-guard
git add internal/config/config.go internal/config/config_test.go
git commit -m "config: add daily_budget section with LLM and file-analysis caps"
```

---

### Task 4: Cache Key Extension (FileContentHash)

**Files:**
- Modify: `internal/cache/cache.go`
- Modify: `internal/cache/cache_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/cache/cache_test.go`:

```go
func TestKey_DiffersWithFileContentHash(t *testing.T) {
	base := KeyInputs{
		Tool:    "Bash",
		Command: "go run /tmp/test.go",
		CWD:     "/home/user/project",
	}
	withHash := base
	withHash.FileContentHash = "abc123"

	k1 := Key(base)
	k2 := Key(withHash)
	if k1 == k2 {
		t.Fatal("keys should differ when FileContentHash differs")
	}
}

func TestSchemaVersion_Is7(t *testing.T) {
	if SchemaVersion != "7" {
		t.Errorf("SchemaVersion = %q, want \"7\"", SchemaVersion)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd ~/Documents/code/claude-guard && go test ./internal/cache/ -run "TestKey_DiffersWithFileContentHash|TestSchemaVersion_Is7" -v`
Expected: FAIL — `FileContentHash` undefined, `SchemaVersion` is "6".

- [ ] **Step 3: Add FileContentHash to KeyInputs**

In `internal/cache/cache.go`:

Add field to `KeyInputs` struct (after `MakefileHash` around line 157):

```go
	// FileContentHash is the SHA-256 of the file contents for runner
	// commands (go run, python, etc.). When populated, a change in the
	// file invalidates the cached verdict even when the command string
	// is identical. Empty for non-runner commands.
	FileContentHash string
```

Bump `SchemaVersion`:

```go
const SchemaVersion = "7"
```

In `keyWithDimensions()`, add `FileContentHash` to the hash computation. Find the function (around line 195) and add after the `MakefileHash` write:

```go
	b.WriteByte('\x00')
	b.WriteString(in.FileContentHash)
```

- [ ] **Step 4: Run all cache tests**

Run: `cd ~/Documents/code/claude-guard && go test ./internal/cache/ -v`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
cd ~/Documents/code/claude-guard
git add internal/cache/cache.go internal/cache/cache_test.go
git commit -m "cache: add FileContentHash to key inputs, bump schema to v7"
```

---

### Task 5: LLM ClassifyInput Extension + Prompt Update

**Files:**
- Modify: `internal/llm/llm.go`
- Modify: `internal/llm/classifier.md`
- Modify: `internal/llm/llm_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/llm/llm_test.go`:

```go
func TestBuildUserMessage_WithFileContent(t *testing.T) {
	in := ClassifyInput{
		Command:     "go run /tmp/test.go",
		Description: "Run test file",
		CWD:         "/home/user",
		FileContent: "package main\nfunc main() {}\n",
		FilePath:    "/tmp/test.go",
	}
	msg := buildUserMessage(in)
	if !strings.Contains(msg, "REFERENCED FILE") {
		t.Error("message should contain REFERENCED FILE section")
	}
	if !strings.Contains(msg, "/tmp/test.go") {
		t.Error("message should contain file path")
	}
	if !strings.Contains(msg, "package main") {
		t.Error("message should contain file content")
	}
}

func TestBuildUserMessage_WithoutFileContent(t *testing.T) {
	in := ClassifyInput{
		Command: "git status",
		CWD:     "/home/user",
	}
	msg := buildUserMessage(in)
	if strings.Contains(msg, "REFERENCED FILE") {
		t.Error("message should NOT contain REFERENCED FILE when no file content")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd ~/Documents/code/claude-guard && go test ./internal/llm/ -run "TestBuildUserMessage_With" -v`
Expected: FAIL — `FileContent` and `FilePath` undefined on `ClassifyInput`.

- [ ] **Step 3: Extend ClassifyInput and buildUserMessage**

In `internal/llm/llm.go`, add fields to `ClassifyInput` (around line 108):

```go
	// FileContent is the content of the file referenced by a runner
	// command (go run, python, etc.). Empty if not a runner, file too
	// large, or budget exhausted.
	FileContent string
	// FilePath is the path of the referenced file (for prompt context).
	FilePath string
```

In `buildUserMessage()`, insert between the `ProjectContext` block (line 263 in llm.go) and the `b.WriteString("\nReturn JSON only...")` line (line 265). The file content must appear BEFORE the JSON format instructions so the model sees the instructions last:

```go
	if in.FileContent != "" {
		b.WriteString(fmt.Sprintf("\nREFERENCED FILE (%s, %d bytes):\n", in.FilePath, len(in.FileContent)))
		b.WriteString(in.FileContent)
		b.WriteString("\n")
	}
```

Add `"fmt"` to the imports if not already present.

- [ ] **Step 4: Update classifier.md**

Append the following block at the end of `internal/llm/classifier.md` (after the existing redaction instruction on line 69):

```
When a command executes a file and the file contents are provided in
the REFERENCED FILE section, evaluate the file's actual behavior
instead of judging purely from the command pattern:

- If the file only does computation, string manipulation, printing,
  or reads from stdin, it is SAFE.
- If the file imports packages for network access, subprocess
  execution, or filesystem writes outside the working directory,
  classify as UNSAFE or UNSURE depending on how they are used.
- If the file contents appear truncated or incomplete, classify as
  UNSURE.
- The file contents show only the directly referenced file. Imported
  packages and modules are NOT provided. If the file imports
  unfamiliar third-party packages that could have side effects,
  classify as UNSURE.
- Standard library imports for testing, formatting, math, and data
  structures are SAFE.
```

- [ ] **Step 5: Run all LLM tests**

Run: `cd ~/Documents/code/claude-guard && go test ./internal/llm/ -v`
Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
cd ~/Documents/code/claude-guard
git add internal/llm/llm.go internal/llm/classifier.md internal/llm/llm_test.go
git commit -m "llm: extend ClassifyInput with file content, update classifier prompt"
```

---

### Task 6: Engine Integration

**Files:**
- Modify: `internal/engine/engine.go`
- Modify: `internal/engine/engine_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/engine/engine_test.go`:

```go
func TestDecide_RunnerCommand_PopulatesFileContent(t *testing.T) {
	// Create a safe Go file.
	f := filepath.Join(t.TempDir(), "test.go")
	os.WriteFile(f, []byte("package main\nimport \"fmt\"\nfunc main() { fmt.Println(\"hi\") }\n"), 0o644)

	var captured llm.ClassifyInput
	stub := &stubClassifier{
		verdict: llm.VerdictSafe,
		onCall: func(in llm.ClassifyInput) {
			captured = in
		},
	}
	e := newTestEngineWithClassifier(stub)

	e.Decide(engine.Input{
		ToolName: "Bash",
		Command:  "go run " + f,
		CWD:      t.TempDir(),
	})

	if captured.FileContent == "" {
		t.Fatal("expected FileContent to be populated for go run")
	}
	if captured.FilePath != f {
		t.Errorf("FilePath = %q, want %q", captured.FilePath, f)
	}
}

func TestDecide_NonRunner_NoFileContent(t *testing.T) {
	var captured llm.ClassifyInput
	stub := &stubClassifier{
		verdict: llm.VerdictSafe,
		onCall: func(in llm.ClassifyInput) {
			captured = in
		},
	}
	e := newTestEngineWithClassifier(stub)

	e.Decide(engine.Input{
		ToolName: "Bash",
		Command:  "git status",
		CWD:      t.TempDir(),
	})

	if captured.FileContent != "" {
		t.Error("expected no FileContent for git status")
	}
}

func TestDecide_RunnerLargeFile_NoFileContent(t *testing.T) {
	// File > 20KB — should skip file content, LLM still called.
	f := filepath.Join(t.TempDir(), "big.go")
	os.WriteFile(f, make([]byte, 21*1024), 0o644) // 21KB

	var captured llm.ClassifyInput
	stub := &stubClassifier{
		verdict: llm.VerdictUnsafe,
		onCall: func(in llm.ClassifyInput) {
			captured = in
		},
	}
	e := newTestEngineWithClassifier(stub)

	e.Decide(engine.Input{
		ToolName: "Bash",
		Command:  "go run " + f,
		CWD:      t.TempDir(),
	})

	if captured.FileContent != "" {
		t.Error("expected no FileContent for large file")
	}
	// LLM should still have been called (command-only classification).
	if captured.Command == "" {
		t.Error("expected LLM to be called even without file content")
	}
}

func TestDecide_FileBudgetExhausted_LLMStillCalled(t *testing.T) {
	f := filepath.Join(t.TempDir(), "test.go")
	os.WriteFile(f, []byte("package main\nfunc main() {}\n"), 0o644)

	var captured llm.ClassifyInput
	stub := &stubClassifier{
		verdict: llm.VerdictUnsafe,
		onCall: func(in llm.ClassifyInput) {
			captured = in
		},
	}

	// Create engine with file budget of 0 (immediately exhausted).
	bgt := budget.New(t.TempDir(), 500, 0)
	e := newTestEngineWithClassifierAndBudget(stub, bgt)

	e.Decide(engine.Input{
		ToolName: "Bash",
		Command:  "go run " + f,
		CWD:      t.TempDir(),
	})

	if captured.FileContent != "" {
		t.Error("expected no FileContent when file budget exhausted")
	}
	if captured.Command == "" {
		t.Error("expected LLM to still be called without file content")
	}
}
```

NOTE: The `stubClassifier` and `newTestEngineWithClassifier` helpers need to capture the input. Adapt to whatever test helpers already exist in the file — the `stubClassifier` at line 40 already has the signature. Add an `onCall` callback field:

```go
type stubClassifier struct {
	verdict llm.Verdict
	reason  string
	err     error
	onCall  func(in llm.ClassifyInput) // NEW: callback to capture input
}

func (s *stubClassifier) Classify(ctx context.Context, in llm.ClassifyInput) (*llm.Decision, error) {
	if s.onCall != nil {
		s.onCall(in)
	}
	// ... existing implementation
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd ~/Documents/code/claude-guard && go test ./internal/engine/ -run "TestDecide_RunnerCommand|TestDecide_NonRunner_NoFileContent" -v`
Expected: FAIL — `newTestEngineWithClassifier` doesn't exist or `FileContent` not populated.

- [ ] **Step 3: Wire file context and budget into engine**

In `internal/engine/engine.go`:

Add imports:

```go
	"crypto/sha256"
	"encoding/hex"

	"github.com/RobinUS2/claude-guard/internal/budget"
	"github.com/RobinUS2/claude-guard/internal/filectx"
```

Add `budget` field to `Engine` struct (around line 115):

```go
	budget *budget.Budget
```

Add `Budget` to `Options` struct (around line 153):

```go
	Budget *budget.Budget
```

Wire it in `NewWithOptions()` (around line 186):

```go
	e.budget = opts.Budget
```

In the `Decide()` method, between the cache miss (around line 532) and the tier 4 LLM call (line 535), add file context extraction:

```go
	// File content extraction for runner commands.
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
		keyInputs.FileContentHash = fileContentHash
	}
```

In the `runLLMTier()` call area (around line 535), pass file content to the LLM input. The `input` construction is inside `runLLMTier` at line 670. We need to either pass `fileContent`/`filePath` through or modify the Input struct. Cleaner approach: add fields to `engine.Input` and pass them through.

Add `FileContent` and `FilePath` to `engine.Input` struct (internal-only fields, not set by callers):

```go
	// FileContent and FilePath are populated by Decide() for runner
	// commands. Not set by external callers (decide.go).
	FileContent    string // file contents for LLM context
	RunnerFilePath string // path of the referenced file (distinct from FilePath used by Read/Write/Edit)
```

Set them in `Decide()` before the LLM call, right after the file context extraction block:

```go
	in.FileContent = fileContent
	in.RunnerFilePath = filePath
```

Then in `runLLMTier()`, at the `input := llm.ClassifyInput{` block (line 670), add the two new fields:

```go
		FileContent:    in.FileContent,
		FilePath:       in.RunnerFilePath,
```

After the LLM call returns, record budget usage. In `runLLMTier()` or back in `Decide()` after the LLM verdict is processed, add:

```go
	// Record budget usage after LLM call.
	if e.budget != nil {
		e.budget.Record(fileContent != "")
	}
```

Check global budget before calling LLM. Wrap the existing `if e.llm != nil {` block in a budget check:

```go
	llmBudgetOK := e.budget == nil || e.budget.Check(false)
	if e.llm != nil && llmBudgetOK {
		// ... existing LLM tier code (runLLMTier, persistLLMAllow, etc.) ...
	} else if !llmBudgetOK {
		e.appLog().Warn("llm_budget_exhausted", "tool_use_id", in.ToolUseID)
	}
```

Budget recording must happen in BOTH the sync and async LLM paths:

**Sync path** — in `Decide()` after the LLM verdict block:
```go
	if e.budget != nil {
		e.budget.Record(fileContent != "")
	}
```

**Async path** — in `runLLMTier()`'s timeout goroutine (around line 712), after a late-arriving "safe" verdict calls `persistLLMAllow`, also record:
```go
	if e.budget != nil {
		e.budget.Record(in.FileContent != "")
	}
```
This ensures async completions also count against the daily budget.

- [ ] **Step 4: Run all engine tests**

Run: `cd ~/Documents/code/claude-guard && go test ./internal/engine/ -v -count=1`
Expected: all tests PASS.

- [ ] **Step 5: Run full test suite**

Run: `cd ~/Documents/code/claude-guard && go test ./... -count=1`
Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
cd ~/Documents/code/claude-guard
git add internal/engine/engine.go internal/engine/engine_test.go
git commit -m "engine: wire file content extraction and daily budget into tier 4"
```

---

### Task 7: Wire Budget in decide.go + Doctor Output

**Files:**
- Modify: `cmd/claude-guard/decide.go`
- Modify: `cmd/claude-guard/doctor.go`

- [ ] **Step 1: Wire budget in decide.go**

In `cmd/claude-guard/decide.go`, after the cache setup (around line 80), create the budget:

```go
	bgt := budget.New(cacheRoot, cfg.DailyBudget.LLMCalls, cfg.DailyBudget.FileAnalysisCalls)
```

Add import:

```go
	"github.com/RobinUS2/claude-guard/internal/budget"
```

Pass it to the engine options. Find where `engine.NewWithOptions` is called (or `engine.Options` is constructed) and add:

```go
	Budget: bgt,
```

- [ ] **Step 2: Add budget status to doctor.go**

In `cmd/claude-guard/doctor.go`, after the cache stats section (around line 120), add:

```go
	// Budget status
	bgt := budget.New(cacheRoot, cfg.DailyBudget.LLMCalls, cfg.DailyBudget.FileAnalysisCalls)
	bs := bgt.Status()
	budgetDetail := fmt.Sprintf("%d/%d LLM, %d/%d file-analysis",
		bs.LLMUsed, bs.LLMLimit, bs.FileUsed, bs.FileLimit)
	if bs.LLMUsed >= bs.LLMLimit || bs.FileUsed >= bs.FileLimit {
		warn("budget", budgetDetail+" (EXHAUSTED)")
	} else {
		check("budget", true, budgetDetail)
	}
```

Add import:

```go
	"github.com/RobinUS2/claude-guard/internal/budget"
```

Need `cacheRoot` in doctor.go — derive it the same way as decide.go:

```go
	cacheRoot := filepath.Join(home, ".cache", "claude-guard")
```

(This is already effectively available via the `cacheDir` variable at line 104.)

- [ ] **Step 3: Build and verify**

Run: `cd ~/Documents/code/claude-guard && go build ./cmd/claude-guard/`
Expected: builds cleanly.

- [ ] **Step 4: Run full test suite**

Run: `cd ~/Documents/code/claude-guard && go test ./... -count=1`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
cd ~/Documents/code/claude-guard
git add cmd/claude-guard/decide.go cmd/claude-guard/doctor.go
git commit -m "decide+doctor: wire daily budget, show usage in health check"
```

---

### Task 8: Golden Corpus + Integration Smoke Test

**Files:**
- Modify: `internal/corpus/testdata/bash_allow.txt` (if runner commands should be added)
- Modify: `internal/engine/golden_test.go` (if needed)

- [ ] **Step 1: Verify golden corpus still passes**

Run: `cd ~/Documents/code/claude-guard && go test ./internal/corpus/ -v`
Run: `cd ~/Documents/code/claude-guard && go test ./internal/engine/ -run Golden -v`
Expected: all existing golden tests PASS unchanged.

- [ ] **Step 2: Full test suite with race detector**

Run: `cd ~/Documents/code/claude-guard && go test -race ./... -count=1`
Expected: no race conditions detected, all tests PASS.

- [ ] **Step 3: Build and install**

Run: `cd ~/Documents/code/claude-guard && make install`
Expected: binary installed to `~/.claude/bin/claude-guard`.

- [ ] **Step 4: Smoke test with doctor**

Run: `~/.claude/bin/claude-guard doctor`
Expected: output includes a `budget:` line showing `0/500 LLM, 0/50 file-analysis`.

- [ ] **Step 5: Smoke test with a runner command**

Run: `~/.claude/bin/claude-guard test "go run /tmp/test_compound.go"`
Expected: test output shows the command being evaluated. If `/tmp/test_compound.go` exists and is safe, the tier 4 verdict should include file context analysis.

- [ ] **Step 6: Commit any remaining changes**

```bash
cd ~/Documents/code/claude-guard
git add -A
git commit -m "test: verify golden corpus, race detector, and smoke tests pass"
```
