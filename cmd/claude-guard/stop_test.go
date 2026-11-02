package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

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
		_, tr, err := parseStopInput([]byte(`{"transcript":[],"background_tasks":[{"id":"a"},{"id":"b"}],"session_crons":[]}`))
		if err != nil {
			t.Fatal(err)
		}
		if tr.BackgroundTasks != 2 || tr.SessionCrons != 0 || !tr.RunningKnown {
			t.Errorf("got %+v", tr)
		}
	})
	t.Run("crons_counted", func(t *testing.T) {
		_, tr, err := parseStopInput([]byte(`{"transcript":[],"background_tasks":[],"session_crons":[{"id":"c"}]}`))
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
		// Present but null or non-string: no fallback to the legacy array.
		for _, v := range []string{`null`, `5`, `{}`} {
			_, tr, _ = parseStopInput([]byte(`{"last_assistant_message":` + v + `,"transcript":[{"role":"assistant","content":"old text"}]}`))
			if tr.LastAssistantText != "" {
				t.Errorf("last_assistant_message=%s fell back to %q", v, tr.LastAssistantText)
			}
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
	t.Run("mixed_known_unknown", func(t *testing.T) {
		for _, body := range []string{
			`{"background_tasks":[]}`, `{"session_crons":[]}`,
			`{"background_tasks":[],"session_crons":null}`, `{"background_tasks":"x","session_crons":[]}`,
		} {
			_, tr, err := parseStopInput([]byte(body))
			if err != nil {
				t.Fatal(err)
			}
			if tr.RunningKnown {
				t.Errorf("%s: RunningKnown = true", body)
			}
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

func TestRuleModeHook(t *testing.T) {
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

func TestStopLogPrivacy(t *testing.T) {
	const secret = "customer-secret-phrase waiting for CI"
	run := func(t *testing.T) string {
		logPath := isolateStop(t, "")
		payload, _ := json.Marshal(map[string]any{
			"session_id":             "priv-1",
			"last_assistant_message": secret,
			"background_tasks":       []any{},
			"session_crons":          []any{},
		})
		var buf bytes.Buffer
		if code := cmdStopWithIO(bytes.NewReader(payload), &buf); code != 0 {
			t.Fatalf("exit code %d", code)
		}
		return readFile(t, logPath)
	}

	t.Run("no_message_text_logged", func(t *testing.T) {
		got := run(t)
		if strings.Contains(got, "customer-secret") || strings.Contains(got, "waiting for CI") {
			t.Errorf("decision log contains message text:\n%s", got)
		}
		if strings.Contains(got, "last_assistant_head") && !strings.Contains(got, `"last_assistant_head":""`) {
			t.Errorf("decision log carries a message head:\n%s", got)
		}
	})

	t.Run("message_length_logged", func(t *testing.T) {
		got := run(t)
		want := `"last_assistant_len":` + strconv.Itoa(len(secret))
		if !strings.Contains(got, want) {
			t.Errorf("decision log missing %s:\n%s", want, got)
		}
	})
}

func TestTranscriptRead(t *testing.T) {
	writeTranscript := func(t *testing.T, lines ...string) string {
		p := filepath.Join(t.TempDir(), "session.jsonl")
		if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	bashLine := func(cmd string) string {
		return `{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"Bash","input":{"command":"` + cmd + `"}}]}}`
	}
	parse := func(t *testing.T, path, msg string) stop.Transcript {
		payload, _ := json.Marshal(map[string]any{
			"session_id": "tr-1", "transcript_path": path, "last_assistant_message": msg,
		})
		_, tr, err := parseStopInput(payload)
		if err != nil {
			t.Fatal(err)
		}
		return tr
	}

	t.Run("bash_calls_from_transcript", func(t *testing.T) {
		p := writeTranscript(t,
			`{"type":"user","message":{"role":"user","content":"please install"}}`,
			bashLine("gh pr create"),
			`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"TodoWrite","input":{"todos":[{"content":"x","status":"pending"}]}}]}}`,
		)
		tr := parse(t, p, "done")
		if tr.TranscriptBlind {
			t.Error("transcript marked blind despite a readable file")
		}
		if len(tr.BashCalls) != 1 || tr.BashCalls[0] != "gh pr create" {
			t.Errorf("BashCalls = %v", tr.BashCalls)
		}
		if !tr.HasTodoWrite || len(tr.LastTodoItems) != 1 {
			t.Errorf("todos not read: %+v", tr.LastTodoItems)
		}
		if tr.TurnCount != 3 {
			t.Errorf("TurnCount = %d, want 3", tr.TurnCount)
		}
		if tr.LastAssistantText != "done" {
			t.Errorf("LastAssistantText = %q, want the hook message", tr.LastAssistantText)
		}
	})

	t.Run("missing_transcript_marks_blind", func(t *testing.T) {
		logPath := isolateStop(t, "open-todo-items: enforce")
		tr := parse(t, filepath.Join(t.TempDir(), "nope.jsonl"), "done")
		if !tr.TranscriptBlind {
			t.Fatal("missing transcript not marked blind")
		}
		payload, _ := json.Marshal(map[string]any{
			"session_id": "blind-1", "transcript_path": "/nonexistent/x.jsonl", "last_assistant_message": "done",
		})
		var buf bytes.Buffer
		cmdStopWithIO(bytes.NewReader(payload), &buf)
		log := readFile(t, logPath)
		if !strings.Contains(log, `"stop_blind"`) || !strings.Contains(log, `"rule":"open-todo-items"`) {
			t.Errorf("blind rules not logged:\n%s", log)
		}
		stats := collectStopStats(strings.NewReader(log), time.Now().Add(-time.Hour))
		if stats["open-todo-items"] == nil || stats["open-todo-items"].Blind != 1 {
			t.Errorf("stop-stats blind count wrong: %+v", stats["open-todo-items"])
		}
	})

	t.Run("proposed_test_run_does_not_fire", func(t *testing.T) {
		rule := stop.DefaultRules()
		var proposed stop.StopRule
		for _, r := range rule {
			if r.Name() == "proposed-test-not-run" {
				proposed = r
			}
		}
		msg := "Next, run go test ./... to verify."
		ran := parse(t, writeTranscript(t, bashLine("go test ./...")), msg)
		if fires, _ := proposed.Eval(ran, nil); fires {
			t.Error("fired although the transcript shows a test run")
		}
		textLine := `{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"` + msg + `"}]}}`
		after := parse(t, writeTranscript(t, textLine, bashLine("go test ./...")), msg)
		if fires, _ := proposed.Eval(after, nil); fires {
			t.Error("fired although a test ran after the proposal")
		}
		before := parse(t, writeTranscript(t, bashLine("go test ./..."), textLine), msg)
		if fires, _ := proposed.Eval(before, nil); !fires {
			t.Error("a test run before the proposal suppressed the rule")
		}
		notRan := parse(t, writeTranscript(t, bashLine("ls")), msg)
		if fires, _ := proposed.Eval(notRan, nil); !fires {
			t.Error("did not fire although no test ran")
		}
	})
}
