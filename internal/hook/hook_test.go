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

func TestWriteResponse_Deny(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteResponse(&buf, Deny("rm -rf on system directory")); err != nil {
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
