package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/RobinUS2/claude-guard/internal/config"
	"github.com/RobinUS2/claude-guard/internal/stop"
)

func TestCmdStop_EmptyTranscript(t *testing.T) {
	isolateStop(t, "")
	payload := `{"session_id":"test-empty","stop_hook_active":false,"transcript":[]}`
	var buf bytes.Buffer
	code := cmdStopWithIO(strings.NewReader(payload), &buf)
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	// Every shell-based rule is in log mode by default, so an empty
	// transcript must let the session stop with an empty object.
	if got := strings.TrimSpace(buf.String()); got != "{}" {
		t.Errorf("response = %q, want {}", got)
	}
}

func TestCmdStop_MalformedInput(t *testing.T) {
	isolateStop(t, "")
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
	// A session with an uncompleted todo matches open-todo-items.
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
	t.Run("log_mode_lets_it_stop", func(t *testing.T) {
		logPath := isolateStop(t, "")
		var buf bytes.Buffer
		cmdStopWithIO(strings.NewReader(payload), &buf)
		if got := strings.TrimSpace(buf.String()); got != "{}" {
			t.Errorf("response = %q, want {}", got)
		}
		if !strings.Contains(readFile(t, logPath), `"rule":"open-todo-items"`) {
			t.Error("expected a would-block record for open-todo-items")
		}
	})
	t.Run("enforce_mode_blocks", func(t *testing.T) {
		isolateStop(t, "open-todo-items: enforce")
		var buf bytes.Buffer
		cmdStopWithIO(strings.NewReader(payload), &buf)
		var resp struct {
			Decision string `json:"decision"`
			Reason   string `json:"reason"`
		}
		json.Unmarshal(buf.Bytes(), &resp)
		if resp.Decision != "block" || resp.Reason == "" {
			t.Errorf("response = %q, want a block with a reason", buf.String())
		}
	})
	_ = stop.DefaultRules // ensure import used
}

// isolateStop points the config, the decision log and the session state dir
// at a temp dir so tests never touch the real ones. modes is optional YAML
// placed under stop.modes. It returns the decisions.jsonl path.
func isolateStop(t *testing.T, modes string) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	logDir := filepath.Join(dir, "logs")
	cfg := "version: " + strconv.Itoa(config.SchemaVersion) + "\nlog:\n  dir: " + logDir + "\n"
	if modes != "" {
		cfg += "stop:\n  modes:\n    " + modes + "\n"
	}
	if err := os.MkdirAll(filepath.Join(dir, "claude-guard"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "claude-guard", "config.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(logDir, "decisions.jsonl")
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParseStopInput(t *testing.T) {
	t.Run("background_tasks_counted", func(t *testing.T) {
		_, tr, err := parseStopInput([]byte(`{"transcript":[],"background_tasks":[{"id":"a"},{"id":"b"}]}`))
		if err != nil {
			t.Fatal(err)
		}
		if tr.BackgroundTasks != 2 || tr.SessionCrons != 0 || !tr.RunningKnown {
			t.Errorf("got %+v", tr)
		}
	})
	t.Run("crons_counted", func(t *testing.T) {
		_, tr, err := parseStopInput([]byte(`{"transcript":[],"session_crons":[{"id":"c"}]}`))
		if err != nil {
			t.Fatal(err)
		}
		if tr.SessionCrons != 1 || tr.BackgroundTasks != 0 || !tr.RunningKnown {
			t.Errorf("got %+v", tr)
		}
	})
	t.Run("fields_missing_unknown", func(t *testing.T) {
		_, tr, err := parseStopInput([]byte(`{"transcript":[]}`))
		if err != nil {
			t.Fatal(err)
		}
		if tr.RunningKnown || tr.BackgroundTasks != 0 || tr.SessionCrons != 0 {
			t.Errorf("got %+v", tr)
		}
	})
}

func TestStopInput(t *testing.T) {
	t.Run("last_assistant_message_read", func(t *testing.T) {
		in, tr, err := parseStopInput([]byte(`{"session_id":"s1","transcript_path":"/x/t.jsonl","stop_hook_active":true,
			"last_assistant_message":"Waiting for CI.",
			"transcript":[{"role":"assistant","content":"old text"}]}`))
		if err != nil {
			t.Fatal(err)
		}
		if tr.LastAssistantText != "Waiting for CI." {
			t.Errorf("LastAssistantText = %q", tr.LastAssistantText)
		}
		if in.SessionID != "s1" || in.TranscriptPath != "/x/t.jsonl" || !in.StopHookActive {
			t.Errorf("input = %+v", in)
		}
		// Absent last_assistant_message falls back to the legacy array.
		_, tr, _ = parseStopInput([]byte(`{"transcript":[{"role":"assistant","content":"old text"}]}`))
		if tr.LastAssistantText != "old text" {
			t.Errorf("fallback LastAssistantText = %q", tr.LastAssistantText)
		}
	})
	t.Run("empty_arrays_known_nothing_running", func(t *testing.T) {
		_, tr, err := parseStopInput([]byte(`{"background_tasks":[],"session_crons":[]}`))
		if err != nil {
			t.Fatal(err)
		}
		if !tr.RunningKnown || tr.BackgroundTasks != 0 || tr.SessionCrons != 0 {
			t.Errorf("got %+v", tr)
		}
	})
	t.Run("null_fields_unknown", func(t *testing.T) {
		for _, body := range []string{`{"background_tasks":null,"session_crons":null}`, `{}`} {
			_, tr, err := parseStopInput([]byte(body))
			if err != nil {
				t.Fatal(err)
			}
			if tr.RunningKnown {
				t.Errorf("%s: RunningKnown = true", body)
			}
		}
	})
	t.Run("non_array_fields_unknown", func(t *testing.T) {
		for _, body := range []string{`{"background_tasks":"none","session_crons":3}`, `{"background_tasks":{},"session_crons":true}`} {
			_, tr, err := parseStopInput([]byte(body))
			if err != nil {
				t.Fatal(err)
			}
			if tr.RunningKnown {
				t.Errorf("%s: RunningKnown = true", body)
			}
		}
	})
}

func TestStopE2E(t *testing.T) {
	run := func(t *testing.T, body string) string {
		t.Helper()
		isolateStop(t, "")
		var buf bytes.Buffer
		if code := cmdStopWithIO(strings.NewReader(body), &buf); code != 0 {
			t.Fatalf("exit code %d", code)
		}
		return strings.TrimSpace(buf.String())
	}
	const msg = `"last_assistant_message":"Waiting for CI on PR 12."`
	t.Run("waiting_nothing_running_blocks", func(t *testing.T) {
		out := run(t, `{"session_id":"e2e-1","transcript_path":"/x/t.jsonl","stop_hook_active":false,`+msg+`,"background_tasks":[],"session_crons":[]}`)
		var resp map[string]string
		if err := json.Unmarshal([]byte(out), &resp); err != nil {
			t.Fatalf("not JSON: %q", out)
		}
		if resp["decision"] != "block" || !strings.Contains(resp["reason"], "nothing is running") || len(resp) != 2 {
			t.Errorf("response = %q", out)
		}
	})
	t.Run("background_task_lets_it_stop", func(t *testing.T) {
		out := run(t, `{"session_id":"e2e-2","stop_hook_active":false,`+msg+`,"background_tasks":[{"id":"b1"}],"session_crons":[]}`)
		if out != "{}" {
			t.Errorf("response = %q, want {}", out)
		}
	})
	t.Run("stop_hook_active_lets_it_stop", func(t *testing.T) {
		out := run(t, `{"session_id":"e2e-3","stop_hook_active":true,`+msg+`,"background_tasks":[],"session_crons":[]}`)
		if out != "{}" {
			t.Errorf("response = %q, want {}", out)
		}
	})
}

func TestRuleMode(t *testing.T) {
	t.Run("default_only_waiting_enforces", func(t *testing.T) {
		for _, r := range stop.DefaultRules() {
			want := stop.ModeLog
			if r.Name() == "waiting-nothing-running" {
				want = stop.ModeEnforce
			}
			if got := stop.RuleMode(r.Name(), nil); got != want {
				t.Errorf("%s mode = %s, want %s", r.Name(), got, want)
			}
		}
	})
	t.Run("log_mode_records_would_block", func(t *testing.T) {
		logPath := isolateStop(t, "")
		body := `{"session_id":"mode-sess","last_assistant_message":"done","transcript":[{"role":"assistant","content":[{"type":"tool_use","name":"TodoWrite","input":{"todos":[{"content":"x","status":"pending"}]}}]}]}`
		var buf bytes.Buffer
		cmdStopWithIO(strings.NewReader(body), &buf)
		if strings.TrimSpace(buf.String()) != "{}" {
			t.Errorf("response = %q, want {}", buf.String())
		}
		log := readFile(t, logPath)
		for _, want := range []string{`"msg":"stop_would_block"`, `"session_id":"mode-sess"`, `"rule":"open-todo-items"`, `"time":`} {
			if !strings.Contains(log, want) {
				t.Errorf("decision log lacks %s:\n%s", want, log)
			}
		}
	})
	t.Run("config_override_enforces", func(t *testing.T) {
		isolateStop(t, "open-todo-items: enforce")
		body := `{"session_id":"mode-sess2","last_assistant_message":"done","transcript":[{"role":"assistant","content":[{"type":"tool_use","name":"TodoWrite","input":{"todos":[{"content":"x","status":"pending"}]}}]}]}`
		var buf bytes.Buffer
		cmdStopWithIO(strings.NewReader(body), &buf)
		if !strings.Contains(buf.String(), `"decision":"block"`) {
			t.Errorf("response = %q, want a block", buf.String())
		}
	})
}
