// Package tokensnapshot provides a fast approximation of session token
// consumption by reading the Claude Code transcript file size.
package tokensnapshot

import (
	"os"
)

// Count returns an approximate token count for the Claude Code transcript at
// path. It uses the file size divided by 5 as a rough proxy
// (chars-per-token for JSON-wrapped content). A single stat syscall keeps
// latency under 1µs — safe to call on every PreToolUse decision.
// Returns 0 when path is empty, the file does not exist, or stat fails —
// callers treat 0 as "unknown" and omit the metric rather than logging a zero.
func Count(path string) int64 {
	if path == "" {
		return 0
	}
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	size := fi.Size()
	if size == 0 {
		return 0
	}
	return size / 5
}
