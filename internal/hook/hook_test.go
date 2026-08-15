package hook

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// Real payload captured during Phase 0 verification (2026-04-15).
// Fields match what Claude Code actually sends.
const realPayloadFromProbe = `{
  "session_id": "6f43eb4f-e4bf-4edc-8420-3259ada9d3db",
  "transcript_path": "/Users/robin/.claude/projects/-Users-robin-Documents-code-felix/6f43eb4f.jsonl",
  "cwd": "/Users/robin/Documents/code/felix",
  "permission_mode": "acceptEdits",
  "agent_id": "aaef45cc5e22c70f9",
  "agent_type": "Explore",
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": {
    "command": "find /tmp -type f -name '*.log' | head -5",
    "description": "List recent log files"
  },
  "tool_use_id": "toolu_01M9wcbZXhGaXa5eoSLe5XS9"
}`

func TestReadRequest_RealPayload(t *testing.T) {
	req, err := ReadRequest(strings.NewReader(realPayloadFromProbe))
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}

	if req.SessionID != "6f43eb4f-e4bf-4edc-8420-3259ada9d3db" {
		t.Errorf("SessionID = %q", req.SessionID)
	}
	if req.CWD != "/Users/robin/Documents/code/felix" {
		t.Errorf("CWD = %q", req.CWD)
	}
	if req.ToolName != "Bash" {
		t.Errorf("ToolName = %q", req.ToolName)
	}
	if req.AgentType != "Explore" {
		t.Errorf("AgentType = %q", req.AgentType)
	}
	if req.ToolUseID != "toolu_01M9wcbZXhGaXa5eoSLe5XS9" {
		t.Errorf("ToolUseID = %q", req.ToolUseID)
	}
}

func TestRequest_Bash(t *testing.T) {
	req, err := ReadRequest(strings.NewReader(realPayloadFromProbe))
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}

	bi, err := req.Bash()
	if err != nil {
		t.Fatalf("Bash(): %v", err)
	}
	if bi.Command != "find /tmp -type f -name '*.log' | head -5" {
		t.Errorf("Command = %q", bi.Command)
	}
	if bi.Description != "List recent log files" {
		t.Errorf("Description = %q", bi.Description)
	}
}

func TestRequest_Bash_WrongTool(t *testing.T) {
	req := &Request{ToolName: "Read"}
	if _, err := req.Bash(); err == nil {
		t.Error("expected error for non-Bash tool")
	}
}

func TestReadRequest_Empty(t *testing.T) {
	if _, err := ReadRequest(strings.NewReader("")); err == nil {
		t.Error("expected error for empty stdin")
	}
}

func TestReadRequest_Malformed(t *testing.T) {
	if _, err := ReadRequest(strings.NewReader("{not json")); err == nil {
		t.Error("expected error for malformed JSON")
	}
}

func TestWriteResponse_Continue(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteResponse(&buf, Continue()); err != nil {
		t.Fatalf("WriteResponse: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if _, ok := decoded["hookSpecificOutput"]; ok {
		t.Errorf("Continue response should not have hookSpecificOutput")
	}
}

func TestWriteResponse_Allow(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteResponse(&buf, Allow("tier=instant_allow rule=git-readonly")); err != nil {
		t.Fatalf("WriteResponse: %v", err)
	}
	var decoded struct {
		HSO struct {
			HookEventName            string `json:"hookEventName"`
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if decoded.HSO.PermissionDecision != "allow" {
		t.Errorf("PermissionDecision = %q", decoded.HSO.PermissionDecision)
	}
	if decoded.HSO.HookEventName != "PreToolUse" {
		t.Errorf("HookEventName = %q", decoded.HSO.HookEventName)
	}
	if decoded.HSO.PermissionDecisionReason != "tier=instant_allow rule=git-readonly" {
		t.Errorf("Reason = %q", decoded.HSO.PermissionDecisionReason)
	}
}

func TestWriteResponse_Ask(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteResponse(&buf, Ask("🧊 freeze active — confirm")); err != nil {
		t.Fatalf("WriteResponse: %v", err)
	}
	var decoded struct {
		HSO struct {
			HookEventName            string `json:"hookEventName"`
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if decoded.HSO.PermissionDecision != "ask" {
		t.Errorf("PermissionDecision = %q, want ask", decoded.HSO.PermissionDecision)
	}
	if decoded.HSO.HookEventName != "PreToolUse" {
		t.Errorf("HookEventName = %q", decoded.HSO.HookEventName)
	}
	if decoded.HSO.PermissionDecisionReason != "🧊 freeze active — confirm" {
		t.Errorf("Reason = %q", decoded.HSO.PermissionDecisionReason)
	}
}

func TestWriteResponse_Deny(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteResponse(&buf, Deny("rm -rf on system directory", "")); err != nil {
		t.Fatalf("WriteResponse: %v", err)
	}
	var decoded struct {
		HSO struct {
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if decoded.HSO.PermissionDecision != "deny" {
		t.Errorf("PermissionDecision = %q", decoded.HSO.PermissionDecision)
	}
	if decoded.HSO.PermissionDecisionReason != "rm -rf on system directory" {
		t.Errorf("Reason = %q", decoded.HSO.PermissionDecisionReason)
	}
}

// Deny with a non-empty hint composes `<reason>\n\nRewrite: <hint>`.
// This format is load-bearing: downstream deny-reason parsers treat the
// blank line as a section break and the `Rewrite:` prefix as an action cue.
// The raw-bytes golden pins the full wire format — changing it breaks the
// separator contract for every consumer.
func TestWriteResponse_Deny_WithHint(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteResponse(&buf, Deny("R", "H")); err != nil {
		t.Fatalf("WriteResponse: %v", err)
	}
	const golden = `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"R\n\nRewrite: H"}}` + "\n"
	if buf.String() != golden {
		t.Errorf("hint-path JSON drift:\n got: %q\nwant: %q", buf.String(), golden)
	}
}

// Deny with an empty hint produces byte-identical output to pre-hint Deny.
// Guards the backward-compat contract for the zero-hint path. The literal
// golden below is the exact wire format — if you edit it, understand that
// every Claude Code hook consumer sees this change.
func TestWriteResponse_Deny_EmptyHint_NoRewriteLine(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteResponse(&buf, Deny("R", "")); err != nil {
		t.Fatalf("WriteResponse: %v", err)
	}
	const golden = `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"R"}}` + "\n"
	if buf.String() != golden {
		t.Errorf("zero-hint JSON drift:\n got: %q\nwant: %q", buf.String(), golden)
	}
}

func TestAllowWithMessage(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteResponse(&buf, AllowWithMessage("tier=instant_allow rule=bq-dry-run", "BQ dry-run: will process 500 MB")); err != nil {
		t.Fatalf("WriteResponse: %v", err)
	}
	var decoded struct {
		HSO struct {
			PermissionDecision string `json:"permissionDecision"`
		} `json:"hookSpecificOutput"`
		UserMessage string `json:"userMessage"`
	}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if decoded.HSO.PermissionDecision != "allow" {
		t.Errorf("PermissionDecision = %q, want allow", decoded.HSO.PermissionDecision)
	}
	if decoded.UserMessage != "BQ dry-run: will process 500 MB" {
		t.Errorf("UserMessage = %q", decoded.UserMessage)
	}
}

func TestContinueWithMessage(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteResponse(&buf, ContinueWithMessage("BQ daily budget exhausted — consider adding LIMIT")); err != nil {
		t.Fatalf("WriteResponse: %v", err)
	}
	var decoded struct {
		HSO         *struct{} `json:"hookSpecificOutput"`
		UserMessage string    `json:"userMessage"`
	}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if decoded.HSO != nil {
		t.Error("hookSpecificOutput should be absent for ContinueWithMessage")
	}
	if decoded.UserMessage != "BQ daily budget exhausted — consider adding LIMIT" {
		t.Errorf("UserMessage = %q", decoded.UserMessage)
	}
}

// Monitor payloads, captured from a real PreToolUse probe. The command
// form is what a build-watch looks like; the ws form has no command at
// all.
const monitorCommandPayload = `{
  "session_id": "e284566e-3f24-4992-acb2-19b9f2aaabe3",
  "cwd": "/Users/robin/Documents/code/cto-as-a-service",
  "hook_event_name": "PreToolUse",
  "tool_name": "Monitor",
  "tool_input": {
    "command": "BUILD=75766224-6b67-4c68-9fe1-eabbc0000001; while true; do gcloud builds describe $BUILD --format='value(status)'; sleep 30; done",
    "description": "DR backup image build",
    "timeout_ms": 1800000,
    "persistent": false
  },
  "tool_use_id": "toolu_01MonitorProbe"
}`

const monitorWSPayload = `{
  "session_id": "e284566e-3f24-4992-acb2-19b9f2aaabe3",
  "cwd": "/tmp",
  "hook_event_name": "PreToolUse",
  "tool_name": "Monitor",
  "tool_input": {
    "ws": {"url": "wss://events.example.com/stream", "protocols": ["v1"]},
    "description": "deploy events",
    "timeout_ms": 300000,
    "persistent": true
  },
  "tool_use_id": "toolu_01MonitorWSProbe"
}`

func TestRequest_Monitor_Command(t *testing.T) {
	req, err := ReadRequest(strings.NewReader(monitorCommandPayload))
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	mi, err := req.Monitor()
	if err != nil {
		t.Fatalf("Monitor(): %v", err)
	}
	if !strings.Contains(mi.Command, "gcloud builds describe") {
		t.Errorf("Command = %q", mi.Command)
	}
	if mi.Description != "DR backup image build" {
		t.Errorf("Description = %q", mi.Description)
	}
	if mi.URL() != "" {
		t.Errorf("URL = %q, want empty for a command monitor", mi.URL())
	}
}

func TestRequest_Monitor_WS(t *testing.T) {
	req, err := ReadRequest(strings.NewReader(monitorWSPayload))
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	mi, err := req.Monitor()
	if err != nil {
		t.Fatalf("Monitor(): %v", err)
	}
	if mi.Command != "" {
		t.Errorf("Command = %q, want empty for a ws monitor", mi.Command)
	}
	if mi.URL() != "wss://events.example.com/stream" {
		t.Errorf("URL = %q", mi.URL())
	}
}

func TestRequest_Monitor_WrongTool(t *testing.T) {
	req := &Request{ToolName: "Bash"}
	if _, err := req.Monitor(); err == nil {
		t.Error("expected error for non-Monitor tool")
	}
}
