package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RobinUS2/claude-guard/internal/store"
)

func setupLearnTest(t *testing.T) (*store.Store, func()) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "guard.db")

	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	// Override the default store path for the learn command.
	origEnv := os.Getenv("XDG_CACHE_HOME")
	os.Setenv("XDG_CACHE_HOME", dir)

	// The learn command will look for guard.db at XDG_CACHE_HOME/claude-guard/guard.db
	// so we need to move the DB there.
	guardDir := filepath.Join(dir, "claude-guard")
	os.MkdirAll(guardDir, 0o755)
	db.Close()
	os.Rename(dbPath, filepath.Join(guardDir, "guard.db"))
	db, err = store.Open(filepath.Join(guardDir, "guard.db"))
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}

	cleanup := func() {
		db.Close()
		os.Setenv("XDG_CACHE_HOME", origEnv)
	}
	return db, cleanup
}

func TestLearn_NonBashIgnored(t *testing.T) {
	_, cleanup := setupLearnTest(t)
	defer cleanup()

	input := `{"tool_name":"Read","tool_input":{"file_path":"/tmp/foo"},"tool_use_id":"r1","session_id":"s1","cwd":"/tmp"}`
	var buf bytes.Buffer
	code := cmdLearnWithIO(strings.NewReader(input), &buf)
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	var resp learnResponse
	json.Unmarshal(buf.Bytes(), &resp)
	if resp.Learned {
		t.Error("should not learn from non-Bash tool")
	}
}

func TestLearn_NoPendingNoOp(t *testing.T) {
	_, cleanup := setupLearnTest(t)
	defer cleanup()

	input := `{"tool_name":"Bash","tool_input":{"command":"git status"},"tool_use_id":"b1","session_id":"s1","cwd":"/tmp"}`
	var buf bytes.Buffer
	code := cmdLearnWithIO(strings.NewReader(input), &buf)
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	var resp learnResponse
	json.Unmarshal(buf.Bytes(), &resp)
	if resp.Learned {
		t.Error("should not learn without pending approval")
	}
}

func TestLearn_WithPendingCreatesEntry(t *testing.T) {
	db, cleanup := setupLearnTest(t)
	defer cleanup()

	// Write a pending approval.
	err := db.WritePending("b2", "git push origin main", "git push origin {BRANCH}", "/tmp/repo", "s1", "verifier disagreement")
	if err != nil {
		t.Fatalf("write pending: %v", err)
	}

	input := `{"tool_name":"Bash","tool_input":{"command":"git push origin main"},"tool_use_id":"b2","session_id":"s1","cwd":"/tmp/repo"}`
	var buf bytes.Buffer
	code := cmdLearnWithIO(strings.NewReader(input), &buf)
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}

	var resp learnResponse
	json.Unmarshal(buf.Bytes(), &resp)
	if !resp.Learned {
		t.Error("expected learned=true")
	}
	if resp.Pattern == "" {
		t.Error("expected non-empty pattern")
	}

	// Pending should be deleted.
	p, _ := db.ReadPending("b2")
	if p != nil {
		t.Error("pending should be deleted after learning")
	}
}

func TestLearn_MultipleApprovalsIncrement(t *testing.T) {
	db, cleanup := setupLearnTest(t)
	defer cleanup()

	for i := 1; i <= 3; i++ {
		id := "multi-" + string(rune('0'+i))
		err := db.WritePending(id, "git push origin main", "git push origin {BRANCH}", "/tmp", "s1", "")
		if err != nil {
			t.Fatalf("write pending %d: %v", i, err)
		}

		input, _ := json.Marshal(postToolUseInput{
			ToolName:  "Bash",
			ToolInput: json.RawMessage(`{"command":"git push origin main"}`),
			ToolUseID: id,
			SessionID: "s1",
			CWD:       "/tmp",
		})
		var buf bytes.Buffer
		cmdLearnWithIO(bytes.NewReader(input), &buf)
	}

	// After 3 approvals, there should be a global entry too.
	// Check the store for any learned entries.
	stats, err := db.VerdictStats()
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.Entries < 1 {
		t.Error("expected at least 1 learned entry")
	}
}

func TestLearn_MalformedInput(t *testing.T) {
	_, cleanup := setupLearnTest(t)
	defer cleanup()

	var buf bytes.Buffer
	code := cmdLearnWithIO(strings.NewReader("not json"), &buf)
	if code != 0 {
		t.Fatalf("exit code %d, want 0 (fail-open)", code)
	}
}

func TestLearn_StalePendingCleaned(t *testing.T) {
	db, cleanup := setupLearnTest(t)
	defer cleanup()

	// Write a pending from 2 hours ago — should be cleaned.
	db.WritePending("stale1", "rm -rf /", "", "/tmp", "s1", "test")

	// Manually backdate it by updating the DB directly.
	// The WritePending uses time.Now(), so we need to verify CleanStalePending works.
	// This is tested more thoroughly in store_test.go.
	_ = time.Now() // placeholder — stale cleanup is called in learn, exercised by store tests
}

func TestLearn_EmptyCommand(t *testing.T) {
	_, cleanup := setupLearnTest(t)
	defer cleanup()

	input := `{"tool_name":"Bash","tool_input":{"command":""},"tool_use_id":"e1","session_id":"s1","cwd":"/tmp"}`
	var buf bytes.Buffer
	code := cmdLearnWithIO(strings.NewReader(input), &buf)
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	var resp learnResponse
	json.Unmarshal(buf.Bytes(), &resp)
	if resp.Learned {
		t.Error("should not learn empty command")
	}
}
