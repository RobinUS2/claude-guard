// Package budget tracks rolling resource consumption for gates that need
// pre-execution decisions. Currently: BigQuery estimated bytes per UTC day.
package budget

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// BQBudget tracks rolling daily BigQuery byte estimates. Each call to
// Record() adds the estimated bytes from a dry-run to a ledger keyed by
// UTC date. Check() returns whether the next query would exceed the daily
// limit.
//
// The ledger is a JSON file at cacheDir/bq-daily.json. Writes use
// atomic rename so a crash never leaves a corrupt file. Old day entries
// are pruned on load to keep the file small.
//
// Safe for concurrent use from a single process (sync.Mutex). Cross-process
// safety relies on atomic rename — concurrent processes may over-count by
// one write window, which is acceptable for a budget hint.
type BQBudget struct {
	mu           sync.Mutex
	path         string
	dailyLimitB  int64
}

// ledger is the on-disk JSON shape.
type ledger struct {
	Days map[string]int64 `json:"days"` // UTC date "YYYY-MM-DD" → bytes
}

// NewBQ creates a BQBudget backed by a file in cacheDir.
// dailyLimitBytes is the maximum estimated bytes per UTC day before Check
// returns false. A typical conservative default is 100 GB (100<<30).
func NewBQ(cacheDir string, dailyLimitBytes int64) *BQBudget {
	return &BQBudget{
		path:        filepath.Join(cacheDir, "bq-daily.json"),
		dailyLimitB: dailyLimitBytes,
	}
}

func today() string {
	return time.Now().UTC().Format("2006-01-02")
}

// load reads the ledger from disk. Returns empty ledger on missing/corrupt file.
func (b *BQBudget) load() ledger {
	data, err := os.ReadFile(b.path)
	if err != nil {
		return ledger{Days: map[string]int64{}}
	}
	var l ledger
	if err := json.Unmarshal(data, &l); err != nil || l.Days == nil {
		return ledger{Days: map[string]int64{}}
	}
	// Prune entries older than 2 days to keep the file small.
	cutoff := time.Now().UTC().AddDate(0, 0, -2).Format("2006-01-02")
	for k := range l.Days {
		if k < cutoff {
			delete(l.Days, k)
		}
	}
	return l
}

// save writes the ledger atomically.
func (b *BQBudget) save(l ledger) error {
	if err := os.MkdirAll(filepath.Dir(b.path), 0o750); err != nil {
		return err
	}
	data, err := json.Marshal(l)
	if err != nil {
		return err
	}
	tmp := b.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, b.path)
}

// CheckAndRecord checks whether adding estimatedBytes would exceed today's
// limit. If within budget it records the usage and returns (true, current
// total after recording, limit). If over budget it returns (false, current
// total before recording, limit) — and does NOT record.
//
// Always returns valid totals even when the underlying file is missing or
// corrupt (fails open: returns true so the query is not blocked on I/O error).
func (b *BQBudget) CheckAndRecord(estimatedBytes int64) (ok bool, usedBytes, limitBytes int64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	l := b.load()
	day := today()
	current := l.Days[day]

	if current+estimatedBytes > b.dailyLimitB {
		return false, current, b.dailyLimitB
	}

	l.Days[day] = current + estimatedBytes
	_ = b.save(l) // fail-open: budget miss is non-critical
	return true, l.Days[day], b.dailyLimitB
}

// Status returns the current day's usage and the daily limit without recording.
func (b *BQBudget) Status() (usedBytes, limitBytes int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	l := b.load()
	return l.Days[today()], b.dailyLimitB
}
