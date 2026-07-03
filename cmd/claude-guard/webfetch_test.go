package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// permissionResponse mirrors the wire format Claude Code expects from a
// PermissionRequest hook — top-level decision field, NOT hookSpecificOutput.
type permissionResponse struct {
	Decision           string      `json:"decision"`
	Reason             string      `json:"reason,omitempty"`
	HookSpecificOutput interface{} `json:"hookSpecificOutput,omitempty"` // must be absent
}

func invokeWebFetch(t *testing.T, input string) permissionResponse {
	t.Helper()
	var out, errOut bytes.Buffer
	runWebFetch(strings.NewReader(input), &out, &errOut)
	raw := bytes.TrimSpace(out.Bytes())
	var resp permissionResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("cmdWebFetch output is not valid JSON: %v\nraw: %s", err, raw)
	}
	// Regression guard: PermissionRequest hooks MUST NOT use hookSpecificOutput.
	// Using that format causes Claude Code to ignore the hook and always prompt.
	if resp.HookSpecificOutput != nil {
		t.Errorf("PermissionRequest response must NOT contain hookSpecificOutput — Claude Code will ignore it.\nraw: %s", raw)
	}
	return resp
}

func TestWebFetch_WireFormat_NonHTTPURL(t *testing.T) {
	// ftp:// is non-HTTP → fail-open → allow
	resp := invokeWebFetch(t, `{"tool_name":"WebFetch","hook_event_name":"PermissionRequest","tool_input":{"url":"ftp://example.com/file"}}`)
	if resp.Decision != "allow" {
		t.Errorf("decision = %q, want allow for non-http url", resp.Decision)
	}
}

func TestWebFetch_WireFormat_BadStdin(t *testing.T) {
	// Malformed JSON → fail-open → allow
	resp := invokeWebFetch(t, `not json`)
	if resp.Decision != "allow" {
		t.Errorf("decision = %q, want allow (fail-open on bad stdin)", resp.Decision)
	}
}

func TestWebFetch_WireFormat_NonWebFetchTool(t *testing.T) {
	// Bash hook accidentally routed here → allow through
	resp := invokeWebFetch(t, `{"tool_name":"Bash","hook_event_name":"PermissionRequest","tool_input":{"command":"ls"}}`)
	if resp.Decision != "allow" {
		t.Errorf("decision = %q, want allow for non-WebFetch tool", resp.Decision)
	}
}

func TestWebFetch_WireFormat_PrivateURL_BlockedAsAsk(t *testing.T) {
	// Private/loopback URLs are blocked by the SSRF guard and surface as
	// "ask" (user prompt) — never auto-approved, even via fail-open.
	resp := invokeWebFetch(t, `{"tool_name":"WebFetch","hook_event_name":"PermissionRequest","tool_input":{"url":"http://127.0.0.1:1/page"}}`)
	if resp.Decision != "ask" {
		t.Errorf("decision = %q, want ask for private URL (SSRF guard)", resp.Decision)
	}
}

func TestWebFetch_WireFormat_MetadataURL_BlockedAsAsk(t *testing.T) {
	// Cloud metadata endpoints must not be silently pre-fetched.
	resp := invokeWebFetch(t, `{"tool_name":"WebFetch","hook_event_name":"PermissionRequest","tool_input":{"url":"http://169.254.169.254/latest/meta-data/"}}`)
	if resp.Decision != "ask" {
		t.Errorf("decision = %q, want ask for metadata URL (SSRF guard)", resp.Decision)
	}
}

func TestWebFetch_WireFormat_EmptyURL(t *testing.T) {
	// Empty URL → fail-open → allow
	resp := invokeWebFetch(t, `{"tool_name":"WebFetch","hook_event_name":"PermissionRequest","tool_input":{"url":""}}`)
	if resp.Decision != "allow" {
		t.Errorf("decision = %q, want allow for empty url", resp.Decision)
	}
}
