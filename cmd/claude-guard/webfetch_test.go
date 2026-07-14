package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// Correct wire format for PermissionRequest hooks (per Claude Code docs):
//
//	allow: {"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}}
//	deny:  {"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny"}}}
//	ask:   {} (empty — falls through to user dialog)
type prDecision struct {
	Behavior string `json:"behavior"`
}

type prHookOutput struct {
	HookEventName string     `json:"hookEventName"`
	Decision      prDecision `json:"decision"`
}

type prResponse struct {
	HookSpecificOutput *prHookOutput `json:"hookSpecificOutput,omitempty"`
}

// behavior returns "allow", "deny", or "ask" (empty = fall-through dialog).
func (r prResponse) behavior() string {
	if r.HookSpecificOutput == nil {
		return "ask"
	}
	return r.HookSpecificOutput.Decision.Behavior
}

func invokeWebFetch(t *testing.T, input string) prResponse {
	t.Helper()
	var out, errOut bytes.Buffer
	runWebFetch(strings.NewReader(input), &out, &errOut)
	raw := bytes.TrimSpace(out.Bytes())
	var resp prResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("cmdWebFetch output is not valid JSON: %v\nraw: %s", err, raw)
	}
	// Regression guard: allow/deny MUST use hookSpecificOutput, not a top-level decision field.
	// A top-level {"decision":"allow"} is silently ignored by Claude Code for PermissionRequest.
	if resp.HookSpecificOutput != nil && resp.HookSpecificOutput.HookEventName != "PermissionRequest" {
		t.Errorf("hookEventName must be PermissionRequest, got %q\nraw: %s", resp.HookSpecificOutput.HookEventName, raw)
	}
	return resp
}

func TestWebFetch_WireFormat_NonHTTPURL(t *testing.T) {
	// ftp:// is non-HTTP → fail-open → allow
	resp := invokeWebFetch(t, `{"tool_name":"WebFetch","hook_event_name":"PermissionRequest","tool_input":{"url":"ftp://example.com/file"}}`)
	if resp.behavior() != "allow" {
		t.Errorf("behavior = %q, want allow for non-http url", resp.behavior())
	}
}

func TestWebFetch_WireFormat_BadStdin(t *testing.T) {
	// Malformed JSON → fail-open → allow
	resp := invokeWebFetch(t, `not json`)
	if resp.behavior() != "allow" {
		t.Errorf("behavior = %q, want allow (fail-open on bad stdin)", resp.behavior())
	}
}

func TestWebFetch_WireFormat_NonWebFetchTool(t *testing.T) {
	// Bash hook accidentally routed here → allow through
	resp := invokeWebFetch(t, `{"tool_name":"Bash","hook_event_name":"PermissionRequest","tool_input":{"command":"ls"}}`)
	if resp.behavior() != "allow" {
		t.Errorf("behavior = %q, want allow for non-WebFetch tool", resp.behavior())
	}
}

func TestWebFetch_WireFormat_PrivateURL_BlockedAsAsk(t *testing.T) {
	// Private/loopback URLs are blocked by the SSRF guard — falls through to
	// the user dialog (ask) so the user sees the permission prompt.
	resp := invokeWebFetch(t, `{"tool_name":"WebFetch","hook_event_name":"PermissionRequest","tool_input":{"url":"http://127.0.0.1:1/page"}}`)
	if resp.behavior() != "ask" {
		t.Errorf("behavior = %q, want ask for private URL (SSRF guard)", resp.behavior())
	}
}

func TestWebFetch_WireFormat_MetadataURL_BlockedAsAsk(t *testing.T) {
	// Cloud metadata endpoints must not be silently pre-fetched.
	resp := invokeWebFetch(t, `{"tool_name":"WebFetch","hook_event_name":"PermissionRequest","tool_input":{"url":"http://169.254.169.254/latest/meta-data/"}}`)
	if resp.behavior() != "ask" {
		t.Errorf("behavior = %q, want ask for metadata URL (SSRF guard)", resp.behavior())
	}
}

func TestWebFetch_WireFormat_EmptyURL(t *testing.T) {
	// Empty URL → fail-open → allow
	resp := invokeWebFetch(t, `{"tool_name":"WebFetch","hook_event_name":"PermissionRequest","tool_input":{"url":""}}`)
	if resp.behavior() != "allow" {
		t.Errorf("behavior = %q, want allow for empty url", resp.behavior())
	}
}
