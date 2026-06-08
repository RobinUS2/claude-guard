// Package tokensnapshot provides a fast approximation of session token
// consumption by scanning the Claude Code transcript file.
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
	if sc.Err() != nil || total == 0 {
		return 0
	}
	return total / 5
}
