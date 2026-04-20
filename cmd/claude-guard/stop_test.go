package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RobinUS2/claude-guard/internal/stop"
)

func TestCmdStop_EmptyTranscript(t *testing.T) {
	payload := `{"session_id":"test-empty","stop_hook_active":false,"transcript":[]}`
	var buf bytes.Buffer
	code := cmdStopWithIO(strings.NewReader(payload), &buf)
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	// Must produce valid JSON. The uncommitted-changes rule has no text
	// pre-filter, so it always runs git status. In a dirty worktree
	// (common during development) it fires even with an empty transcript.
	var resp map[string]any
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
		t.Fatalf("response not valid JSON: %v (got %q)", err, buf.String())
	}
	if msg, ok := resp["userMessage"]; ok && msg != "" {
		// Acceptable: shell-based rules (uncommitted-changes, feature-branch-left,
		// committed-not-pushed, worktree-left-open) fire because test runs in a
		// real git repo that may be dirty or on a feature branch.
		s := msg.(string)
		known := strings.Contains(s, "uncommitted") ||
			strings.Contains(s, "Still on branch") ||
			strings.Contains(s, "unpushed commit") ||
			strings.Contains(s, "worktrees active")
		if !known {
			t.Errorf("unexpected userMessage: %q", s)
		}
	}
}

func TestCmdStop_MalformedInput(t *testing.T) {
	var buf bytes.Buffer
	code := cmdStopWithIO(strings.NewReader("not json"), &buf)
	if code != 0 {
		t.Fatalf("expected exit 0 (fail-open), got %d", code)
	}
}

func TestParseTranscript_ExtractsBashCalls(t *testing.T) {
	// Tool calls appear as type="tool_use" inside assistant content blocks.
	payload := []json.RawMessage{
		json.RawMessage(`{"role":"user","content":"push, merge, install"}`),
		json.RawMessage(`{"role":"assistant","content":[
			{"type":"text","text":"I'll push now."},
			{"type":"tool_use","name":"Bash","input":{"command":"git push"}}
		]}`),
	}
	tr := parseTranscript(payload)
	if tr.FirstUserText != "push, merge, install" {
		t.Errorf("FirstUserText = %q", tr.FirstUserText)
	}
	if tr.LastAssistantText != "I'll push now." {
		t.Errorf("LastAssistantText = %q", tr.LastAssistantText)
	}
	if len(tr.BashCalls) != 1 || tr.BashCalls[0] != "git push" {
		t.Errorf("BashCalls = %v", tr.BashCalls)
	}
}

func TestParseTranscript_ExtractsTodoWrite(t *testing.T) {
	payload := []json.RawMessage{
		json.RawMessage(`{"role":"assistant","content":[
			{"type":"tool_use","name":"TodoWrite","input":{"todos":[
				{"content":"step 1","status":"completed"},
				{"content":"step 2","status":"pending"}
			]}}
		]}`),
	}
	tr := parseTranscript(payload)
	if !tr.HasTodoWrite {
		t.Error("expected HasTodoWrite=true")
	}
	if len(tr.LastTodoItems) != 2 {
		t.Errorf("expected 2 todo items, got %d", len(tr.LastTodoItems))
	}
	if tr.LastTodoItems[1].Status != "pending" {
		t.Errorf("item[1].Status = %q", tr.LastTodoItems[1].Status)
	}
}

func TestParseTranscript_StringContent(t *testing.T) {
	payload := []json.RawMessage{
		json.RawMessage(`{"role":"user","content":"hello"}`),
		json.RawMessage(`{"role":"assistant","content":"All done."}`),
	}
	tr := parseTranscript(payload)
	if tr.FirstUserText != "hello" {
		t.Errorf("FirstUserText = %q", tr.FirstUserText)
	}
	if tr.LastAssistantText != "All done." {
		t.Errorf("LastAssistantText = %q", tr.LastAssistantText)
	}
}

func TestCmdStop_OpenTodosFires(t *testing.T) {
	// Remove any stale session state from prior runs so the cool-down doesn't skip the rule.
	stale := filepath.Join(os.TempDir(), "claude-guard-stop-todo-test.json")
	os.Remove(stale)
	t.Cleanup(func() { os.Remove(stale) })

	// A session with an uncompleted todo → open-todo-items rule should fire.
	payload := `{
		"session_id":"todo-test",
		"stop_hook_active":false,
		"transcript":[
			{"role":"assistant","content":[
				{"type":"tool_use","name":"TodoWrite","input":{"todos":[
					{"content":"step 1","status":"completed"},
					{"content":"step 2","status":"pending"}
				]}}
			]},
			{"role":"assistant","content":"Done with step 1."}
		]
	}`
	var buf bytes.Buffer
	cmdStopWithIO(strings.NewReader(payload), &buf)
	var resp struct {
		UserMessage string `json:"userMessage"`
	}
	json.Unmarshal(buf.Bytes(), &resp)
	if resp.UserMessage == "" {
		t.Error("expected open-todo-items rule to fire with pending items")
	}
	_ = stop.DefaultRules // ensure import used
}
