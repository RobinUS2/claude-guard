package log

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestDecisionLogger_WritesToFirehose(t *testing.T) {
	dir := t.TempDir()
	paths := DefaultPaths(dir)

	dl, err := OpenDecisionLogger(paths, 10, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer dl.Close()

	dl.Decision(DecisionRecord{
		GuardVersion: "test",
		SessionID:    "s1",
		ToolUseID:    "tu1",
		ToolName:     "Bash",
		Command:      "git status",
		Tier:         "instant_allow",
		Verdict:      "allow",
		Rule:         "git-readonly",
		LatencyUS:    42,
	})
	dl.Decision(DecisionRecord{
		ToolName: "Bash",
		Command:  "go test ./...",
		Tier:     "default",
		Verdict:  "continue",
	})
	dl.Close()

	data, err := os.ReadFile(paths.Decisions)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), "\n") != 2 {
		t.Errorf("want 2 lines, got %d", strings.Count(string(data), "\n"))
	}

	// Parse first line, verify schema.
	firstLine := strings.SplitN(string(data), "\n", 2)[0]
	var rec map[string]any
	if err := json.Unmarshal([]byte(firstLine), &rec); err != nil {
		t.Fatalf("first line not valid JSON: %v", err)
	}
	if rec["msg"] != MsgDecision {
		t.Errorf("msg = %v", rec["msg"])
	}
	if rec["verdict"] != "allow" {
		t.Errorf("verdict = %v", rec["verdict"])
	}
	if rec["rule"] != "git-readonly" {
		t.Errorf("rule = %v", rec["rule"])
	}
}

func TestDecisionLogger_DenyGoesToBothFiles(t *testing.T) {
	dir := t.TempDir()
	paths := DefaultPaths(dir)

	dl, err := OpenDecisionLogger(paths, 10, 3)
	if err != nil {
		t.Fatal(err)
	}

	dl.Decision(DecisionRecord{
		ToolName: "Bash",
		Command:  "rm -rf /",
		Tier:     "instant_block",
		Verdict:  "deny",
		Rule:     "rm-rf-system",
		Reason:   "rm -rf on system/home directory",
	})
	dl.Decision(DecisionRecord{
		ToolName: "Bash",
		Command:  "ls",
		Tier:     "instant_allow",
		Verdict:  "allow",
	})
	dl.Close()

	decisionsData, _ := os.ReadFile(paths.Decisions)
	deniesData, _ := os.ReadFile(paths.Denies)

	// Both records in the firehose.
	if n := strings.Count(string(decisionsData), "\n"); n != 2 {
		t.Errorf("decisions.jsonl: want 2 lines, got %d", n)
	}
	// Only the deny in denies.
	if n := strings.Count(string(deniesData), "\n"); n != 1 {
		t.Errorf("denies.jsonl: want 1 line, got %d", n)
	}
	if !strings.Contains(string(deniesData), "rm-rf-system") {
		t.Errorf("denies.jsonl missing rule: %s", string(deniesData))
	}
}

func TestDecisionLogger_ShadowGroup(t *testing.T) {
	dir := t.TempDir()
	paths := DefaultPaths(dir)
	dl, _ := OpenDecisionLogger(paths, 10, 3)
	defer dl.Close()

	dl.Decision(DecisionRecord{
		ToolName: "Bash",
		Command:  "git status",
		Tier:     "default",
		Verdict:  "continue",
		Shadow: &ShadowFields{
			Tier2Allow: "git-readonly",
		},
	})
	dl.Close()

	data, _ := os.ReadFile(paths.Decisions)
	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &rec); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	shadow, ok := rec["shadow"].(map[string]any)
	if !ok {
		t.Fatalf("no shadow group: %v", rec)
	}
	if shadow["tier2_allow"] != "git-readonly" {
		t.Errorf("tier2_allow = %v", shadow["tier2_allow"])
	}
}

func TestDecisionLogger_ConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	paths := DefaultPaths(dir)
	dl, err := OpenDecisionLogger(paths, 10, 3)
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
				dl.Decision(DecisionRecord{
					ToolName: "Bash",
					Command:  "test",
					Tier:     "default",
					Verdict:  "continue",
				})
			}
		}(g)
	}
	wg.Wait()
	dl.Close()

	data, err := os.ReadFile(paths.Decisions)
	if err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 1<<16), 1<<16)
	var lines int
	for sc.Scan() {
		lines++
		var rec map[string]any
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Errorf("line %d: %v\n%s", lines, err, sc.Bytes())
		}
	}
	if lines != goroutines*writes {
		t.Errorf("want %d lines, got %d", goroutines*writes, lines)
	}
}

func TestDecisionLogger_NilSafe(t *testing.T) {
	var dl *DecisionLogger
	dl.Decision(DecisionRecord{Command: "ls"})   // must not panic
	dl.StopHook(StopHookRecord{SessionID: "s1"}) // must not panic
	dl.Close()                                   // must not panic
}

// The stop_hook record written by DecisionLogger.StopHook must round-trip
// cleanly through StopHookRecord — stats and hotspots read this shape
// back, so any drift in field names breaks both.
func TestDecisionLogger_StopHookRoundTrip(t *testing.T) {
	dir := t.TempDir()
	paths := DefaultPaths(dir)
	dl, err := OpenDecisionLogger(paths, 10, 3)
	if err != nil {
		t.Fatal(err)
	}

	dl.StopHook(StopHookRecord{
		SessionID:      "sess-1",
		StopHookActive: true,
		FiredRule:      "open-todo-items",
		Injected:       true,
		Suppressed:     "",
		ContinueCount:  2,
		LatencyUS:      12345,
	})
	dl.StopHook(StopHookRecord{
		SessionID:     "sess-2",
		Injected:      false,
		Suppressed:    "max_continues_reached",
		ContinueCount: 3,
		LatencyUS:     6789,
	})
	dl.Close()

	data, err := os.ReadFile(paths.Decisions)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d:\n%s", len(lines), data)
	}

	var r1 StopHookRecord
	if err := json.Unmarshal([]byte(lines[0]), &r1); err != nil {
		t.Fatalf("line 1 not valid StopHookRecord: %v", err)
	}
	if r1.Msg != MsgStopHook {
		t.Errorf("msg = %q, want %q", r1.Msg, MsgStopHook)
	}
	if r1.SessionID != "sess-1" || r1.FiredRule != "open-todo-items" ||
		!r1.Injected || !r1.StopHookActive || r1.ContinueCount != 2 || r1.LatencyUS != 12345 {
		t.Errorf("line 1 fields mismatch: %+v", r1)
	}

	var r2 StopHookRecord
	if err := json.Unmarshal([]byte(lines[1]), &r2); err != nil {
		t.Fatalf("line 2 not valid StopHookRecord: %v", err)
	}
	if r2.Suppressed != "max_continues_reached" || r2.Injected || r2.ContinueCount != 3 {
		t.Errorf("line 2 fields mismatch: %+v", r2)
	}

	// Verify denies.jsonl did NOT receive these — stop_hook is not a deny.
	deniesData, _ := os.ReadFile(paths.Denies)
	if strings.TrimSpace(string(deniesData)) != "" {
		t.Errorf("denies.jsonl should be empty, got:\n%s", deniesData)
	}
}

func TestOpenAppLogger(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.jsonl")
	logger, closer, err := OpenAppLogger(path, 10, 3)
	if err != nil {
		t.Fatal(err)
	}
	logger.Info("startup", "guard_version", "test", "shadow_mode", true)
	logger.Warn("config_fallback", "reason", "file not found")
	_ = closer.Close()

	data, _ := os.ReadFile(path)
	if strings.Count(string(data), "\n") != 2 {
		t.Errorf("want 2 lines, got:\n%s", data)
	}
	if !strings.Contains(string(data), "startup") {
		t.Errorf("startup message missing: %s", data)
	}
	if !strings.Contains(string(data), "config_fallback") {
		t.Errorf("config_fallback message missing: %s", data)
	}
}
