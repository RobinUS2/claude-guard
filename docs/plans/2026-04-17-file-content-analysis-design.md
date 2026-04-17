# Design: File Content Analysis for Runner Commands

**Created:** 2026-04-17
**Status:** Draft
**Context:** Tier 4 LLM classifies `go run /tmp/test.go` as unsafe because it can't see the file contents. Adding file context lets the LLM make informed decisions, reducing false positives for safe scripts.

## Problem

Commands like `go run /tmp/test_compound.go` trigger tier 4 LLM classification. The LLM only sees the command string, not the file being executed. It correctly classifies this as `unsafe` ("executing untrusted code from /tmp"), but in practice the file is often a harmless test script written by Claude Code moments earlier. The user gets prompted unnecessarily.

## Solution

Extend tier 4 to optionally include file contents in the LLM prompt. Add daily budgets to control LLM cost.

## Component 1: File Content Extraction (`internal/filectx/`)

### Runner Detection

Match parsed AST program + subcommand against a known runner table:

| Program | Subcommand | File arg position |
|---------|-----------|-------------------|
| `go` | `run` | after `run` |
| `python`, `python3` | _(none)_ | first positional |
| `node` | _(none)_ | first positional |
| `tsx` | _(none)_ | first positional |
| `deno` | `run` | after `run` |
| `ruby` | _(none)_ | first positional |
| `bun` | `run` | after `run` (only when arg is a file path, not a script name) |

The runner table is a Go slice in the package, not config-driven. Adding a new runner is a code change + test.

### File Reading Rules

1. Extract file path from the parsed `Call.Positional` args based on runner table position.
2. `os.Lstat()` the path — must be a regular file (no symlinks, no directories, no devices, no pipes).
3. Check file size — must be **<= 20KB**. If larger, skip with reason `"exceeds 20KB limit"`.
4. Read first 512 bytes — if any null byte is present, skip with reason `"binary file"`.
5. Read full file contents.
6. If multiple file args exist (e.g. `go run a.go b.go`), read only the first. One file per classification keeps token budget predictable.

### Output Type

```go
type FileContext struct {
    Path    string // absolute path of the file
    Content string // file contents (empty if skipped)
    Size    int64  // file size in bytes
    Skipped bool   // true if file was detected but not read
    Reason  string // why it was skipped (too large, binary, not found, symlink, budget)
}

// Extract examines a parsed command and returns file context if the
// command is a runner with a readable file argument. Returns nil if
// the command is not a runner pattern.
func Extract(call shellparse.Call) *FileContext
```

### Security Constraints

- **No symlink following.** `os.Lstat` + check `Mode().IsRegular()`. Symlinks could point to sensitive files (`~/.ssh/id_rsa`).
- **Read-only.** This package never modifies files.
- **No recursive imports.** We read the directly referenced file only. Transitive dependencies (Go imports, Python imports) are not analyzed. The classifier prompt notes this limitation.

## Component 2: LLM Integration

### ClassifyInput Extension

```go
type ClassifyInput struct {
    Command        string
    Description    string
    CWD            string
    GitBranch      string
    ProjectContext string
    // New fields:
    FileContent    string // file contents (empty if not a runner or skipped)
    FilePath       string // path of the file (for prompt context)
}
```

### User Message Format

When `FileContent` is non-empty, `buildUserMessage()` appends after the existing sections:

```
REFERENCED FILE (/tmp/test_compound.go, 847 bytes):
package main

import "fmt"

func main() {
    fmt.Println("hello")
}
```

### Classifier Prompt Update

Add to `classifier.md`:

```
When a command executes a file and the file contents are provided in
the REFERENCED FILE section, evaluate the file's actual behavior:

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

### Cache Key Change

Add `FileContentHash string` to `cache.KeyInputs`. When the file content is provided, hash it (SHA-256 of the raw bytes) and include in the key. When the file changes, the hash changes, the cache key changes, and the LLM re-evaluates.

Bump `SchemaVersion` from `"6"` to `"7"`.

When no file content is provided (not a runner, file too large, budget exhausted), `FileContentHash` stays empty — identical to today's behavior.

## Component 3: Daily Budget System (`internal/budget/`)

### Two Budgets

| Budget | Default | What it caps |
|--------|---------|-------------|
| Global LLM | 500/day | All tier 4 classify + verifier calls |
| File analysis | 50/day | Classify calls that include file content |

File analysis calls count against **both** budgets.

### Storage

Single JSON file at `~/.cache/claude-guard/daily-budget.json`:

```json
{
  "date": "2026-04-17",
  "llm_calls": 142,
  "file_analysis_calls": 8
}
```

Date field is checked on every access. If it doesn't match `time.Now().Format("2006-01-02")`, counters reset to zero.

### API

```go
type Budget struct {
    path string // file path
    mu   sync.Mutex
}

func New(cacheDir string) *Budget

// Check reports whether a call is within budget.
// withFileContent=true checks both budgets.
func (b *Budget) Check(withFileContent bool) (ok bool)

// Record increments counters after a successful call.
func (b *Budget) Record(withFileContent bool)

// Status returns current usage for doctor/stats.
func (b *Budget) Status() (llmUsed, llmLimit, fileUsed, fileLimit int)
```

### Concurrency

The budget file is process-local state (multiple Claude Code sessions may run concurrently). Use `sync.Mutex` for in-process safety. For cross-process safety, use read-modify-write with `os.Rename` (atomic write pattern already used by the cache package). Acceptable to have a small race window — a few extra calls over budget is harmless; exact enforcement isn't worth file locking complexity.

### Configuration

Defaults are compiled in. Override via the existing `~/.config/claude-guard/config.yaml` (integrated into `config.Config`):

```go
// In internal/config/config.go
type DailyBudget struct {
    LLMCalls          int `yaml:"llm_calls"`
    FileAnalysisCalls int `yaml:"file_analysis_calls"`
}
```

```yaml
# In config.yaml
daily_budget:
  llm_calls: 500
  file_analysis_calls: 50
```

The `budget.New()` constructor accepts the resolved limits from config, not raw YAML. This keeps the budget package free of config-loading concerns.

### Exhaustion Behavior

- **Global budget exhausted:** Tier 4 skipped entirely. Log warning to `app.jsonl`. Fall through to user prompt.
- **File analysis budget exhausted:** File content not included in LLM call. Regular command-only classification still runs (if global budget permits). Log warning.
- `claude-guard doctor` shows: `budget: 142/500 LLM, 8/50 file-analysis`

## Engine Integration

### Flow in `engine.Decide()`

Between tier 3 (cache miss) and the existing LLM call at line ~670:

1. If command is Bash and parsed successfully:
   - For each `Call` in `parsed.Calls`: check `filectx.Extract(call)`
   - If a `FileContext` is returned and `!Skipped`:
     - Check `budget.Check(true)` — if false, set `Skipped=true, Reason="daily file-analysis budget exhausted"`
     - Otherwise: populate `ClassifyInput.FileContent` and `ClassifyInput.FilePath`
     - Compute `FileContentHash` for cache key
2. After LLM call completes: `budget.Record(hasFileContent)`

### What Doesn't Change

- Tier 1 and 2 run before any of this — deterministic rules still win.
- Cache hits bypass file reading entirely — the hash is part of the cache key, so a hit means the file hasn't changed.
- The LLM remains APPROVE-ONLY. File content doesn't change this invariant.
- Verifier calls count against global budget but not file-analysis budget (verifier doesn't re-read the file).

## Testing

### Unit Tests

- `internal/filectx/filectx_test.go`:
  - Runner detection for each program in the table
  - Non-runner commands return nil
  - File too large → Skipped
  - Binary file → Skipped
  - Symlink → Skipped
  - File not found → Skipped with reason
  - Multiple file args → only first read
  - Flags between program and file arg handled correctly

- `internal/budget/budget_test.go`:
  - Counter increments correctly
  - Date rollover resets counters
  - Global budget exhaustion
  - File budget exhaustion (global still works)
  - Config override of defaults
  - Concurrent access safety

### Golden Corpus

Add to `internal/corpus/testdata/bash_allow.txt`:
```
# Runner commands with safe file content (tested via engine with mock file)
go run /tmp/test_safe.go
python3 /tmp/analyze.py
node /tmp/format.js
```

### Integration Tests

- Engine test with stub classifier that verifies `FileContent` field is populated
- Engine test with file over 20KB — verify `FileContent` is empty
- Engine test with budget exhausted — verify `FileContent` is empty but LLM still called
- Cache invalidation test: same command, different file content → cache miss

## Rollout

1. Ship with file analysis enabled by default (budget-controlled).
2. Monitor via `claude-guard monitor --file app` for budget exhaustion warnings.
3. Tune defaults based on real usage after 1 week.
