package log

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLogger_WriteAndRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log.jsonl")
	lg, err := Open(path, 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	rec := Record{
		GuardVersion: "test",
		SessionID:    "sess-1",
		ToolUseID:    "tu-1",
		ToolName:     "Bash",
		Command:      "ls -la",
		Tier:         "instant_allow",
		Verdict:      "allow",
		Rule:         "readonly",
	}
	if err := lg.Write(rec); err != nil {
		t.Fatal(err)
	}
	if err := lg.Write(Record{ToolName: "Bash", Tier: "default", Verdict: "continue"}); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// Count lines and parse each as JSON
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	var lines int
	for sc.Scan() {
		lines++
		var parsed map[string]any
		if err := json.Unmarshal(sc.Bytes(), &parsed); err != nil {
			t.Errorf("line %d not valid JSON: %v", lines, err)
		}
	}
	if lines != 2 {
		t.Errorf("want 2 lines, got %d", lines)
	}
}

func TestLogger_Rotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log.jsonl")
	lg, err := Open(path, 200, 2) // rotate every 200 bytes, keep 2 generations
	if err != nil {
		t.Fatal(err)
	}

	// Write enough to trigger two rotations.
	for i := 0; i < 20; i++ {
		rec := Record{
			GuardVersion: "test",
			SessionID:    "sess-rotation",
			ToolName:     "Bash",
			Command:      strings.Repeat("x", 50),
			Tier:         "default",
			Verdict:      "continue",
		}
		if err := lg.Write(rec); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	// Base file should exist.
	if _, err := os.Stat(path); err != nil {
		t.Errorf("base file missing: %v", err)
	}
	// .1 should exist.
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf(".1 missing: %v", err)
	}
}

func TestLogger_ConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log.jsonl")
	lg, err := Open(path, 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	const goroutines = 20
	const writes = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < writes; i++ {
				rec := Record{
					Time:     time.Now().UTC(),
					ToolName: "Bash",
					Command:  "test",
					Tier:     "default",
					Verdict:  "continue",
				}
				if err := lg.Write(rec); err != nil {
					t.Errorf("writer %d: %v", id, err)
					return
				}
			}
		}(g)
	}
	wg.Wait()

	// Verify every line is a complete JSON record (no interleaving corruption).
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 1<<16), 1<<16)
	var lines int
	for sc.Scan() {
		lines++
		var parsed map[string]any
		if err := json.Unmarshal(sc.Bytes(), &parsed); err != nil {
			t.Errorf("line %d not valid JSON: %v\nline: %s", lines, err, sc.Bytes())
		}
	}
	if lines != goroutines*writes {
		t.Errorf("want %d lines, got %d", goroutines*writes, lines)
	}
}

func TestLogger_TruncatesOversized(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "log.jsonl")
	lg, err := Open(path, 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	// A command longer than maxRecordBytes.
	huge := strings.Repeat("x", maxRecordBytes*2)
	rec := Record{
		ToolName: "Bash",
		Command:  huge,
		Reason:   strings.Repeat("r", maxRecordBytes),
		Tier:     "default",
		Verdict:  "continue",
	}
	if err := lg.Write(rec); err != nil {
		t.Fatalf("write: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > maxRecordBytes+100 {
		t.Errorf("line too large: %d bytes", len(data))
	}
	if !strings.Contains(string(data), "truncated") {
		t.Errorf("expected 'truncated' marker in output: %s", string(data))
	}
}
