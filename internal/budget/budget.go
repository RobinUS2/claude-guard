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
