// Package log writes guard decisions as JSON Lines to a rotating file.
//
// Each record is a single JSON object written with O_APPEND in one
// write(2) syscall. For records under PIPE_BUF (typically 4096 bytes on
// Linux/macOS) the kernel guarantees atomicity with concurrent appenders,
// which is exactly what we need: the guard binary runs as a short-lived
// process invoked per hook call, and multiple Claude Code sessions can
// fire hooks concurrently (observed during Phase 0 verification).
//
// Size-based rotation keeps the current file under MaxSizeBytes; on
// overflow we rename log.jsonl → log.jsonl.1 (and .1 → .2, etc., up to
// KeepFiles generations).
package log

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Default write limit: stay well under typical PIPE_BUF so concurrent
// appends from multiple guard processes remain atomic.
const maxRecordBytes = 3500

// Record is the on-disk shape of a single decision entry.
type Record struct {
	Time         time.Time `json:"time"`
	GuardVersion string    `json:"guard_version"`
	SessionID    string    `json:"session_id,omitempty"`
	ToolUseID    string    `json:"tool_use_id,omitempty"`
	AgentID      string    `json:"agent_id,omitempty"`
	AgentType    string    `json:"agent_type,omitempty"`
	CWD          string    `json:"cwd,omitempty"`
	ToolName     string    `json:"tool_name"`
	Command      string    `json:"command,omitempty"`
	Description  string    `json:"description,omitempty"`
	Tier         string    `json:"tier"`
	Verdict      string    `json:"verdict"`
	Rule         string    `json:"rule,omitempty"`
	Reason       string    `json:"reason,omitempty"`
	LatencyUS    int64     `json:"latency_us,omitempty"`
	// Shadow mode only: what the verdict WOULD have been at each tier.
	// Useful during phase 1 to review before enforcement goes live.
	Shadow *ShadowRecord `json:"shadow,omitempty"`
}

// ShadowRecord captures what each tier would have said, for shadow-mode
// comparison against the legacy allow list.
type ShadowRecord struct {
	Tier1Block string `json:"tier1_block,omitempty"`
	Tier2Allow string `json:"tier2_allow,omitempty"`
	Tier4LLM   string `json:"tier4_llm,omitempty"`
	Tier5Legacy string `json:"tier5_legacy,omitempty"`
}

// Logger writes Records to a rotating JSONL file.
// Safe for concurrent use within a single process; atomicity across
// processes relies on the kernel's POSIX append guarantee for small writes.
type Logger struct {
	path         string
	maxSizeBytes int64
	keepFiles    int
	mu           sync.Mutex
}

// Open creates a Logger for the given path. The path's parent directory
// is created if it doesn't exist. maxSizeBytes <= 0 disables rotation.
func Open(path string, maxSizeBytes int64, keepFiles int) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir log dir: %w", err)
	}
	return &Logger{
		path:         path,
		maxSizeBytes: maxSizeBytes,
		keepFiles:    keepFiles,
	}, nil
}

// Write appends a record. Never blocks the caller for more than a file
// open/write/close; errors are returned for caller visibility but in
// practice the guard's decide path ignores them (the user must never be
// blocked by a logging bug).
func (l *Logger) Write(rec Record) error {
	if rec.Time.IsZero() {
		rec.Time = time.Now().UTC()
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal record: %w", err)
	}
	if len(data)+1 > maxRecordBytes {
		// Truncate command/reason to keep under atomic-append limit.
		rec = truncateRecord(rec, maxRecordBytes-512)
		data, err = json.Marshal(rec)
		if err != nil {
			return fmt.Errorf("marshal truncated record: %w", err)
		}
	}
	data = append(data, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.rotateIfNeeded(int64(len(data))); err != nil {
		// Log rotation failed but don't prevent the write: better to have
		// an over-sized file than to lose the entry.
		_ = err
	}

	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("open log: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write log: %w", err)
	}
	return nil
}

func (l *Logger) rotateIfNeeded(addBytes int64) error {
	if l.maxSizeBytes <= 0 {
		return nil
	}
	st, err := os.Stat(l.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if st.Size()+addBytes <= l.maxSizeBytes {
		return nil
	}
	// Shift rotated files: .N-1 → .N, ..., .1 → .2, base → .1
	for i := l.keepFiles; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", l.path, i)
		dst := fmt.Sprintf("%s.%d", l.path, i+1)
		if i == l.keepFiles {
			_ = os.Remove(src)
			continue
		}
		if _, err := os.Stat(src); err == nil {
			if err := os.Rename(src, dst); err != nil {
				return err
			}
		}
	}
	return os.Rename(l.path, l.path+".1")
}

// truncateRecord trims Command and Reason so the marshaled size fits budget.
func truncateRecord(rec Record, budget int) Record {
	if len(rec.Command) > budget/2 {
		rec.Command = rec.Command[:budget/2] + "…[truncated]"
	}
	if len(rec.Reason) > budget/4 {
		rec.Reason = rec.Reason[:budget/4] + "…[truncated]"
	}
	return rec
}
