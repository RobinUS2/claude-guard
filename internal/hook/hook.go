// Package hook speaks the Claude Code PreToolUse and PermissionRequest protocols.
//
// It reads a single JSON object from stdin (the tool-use request) and
// writes a single JSON object to stdout (the hook response). The response
// uses the native `hookSpecificOutput` shape Claude Code understands.
//
// This package has zero business logic — it is purely serialization.
package hook

import (
	"encoding/json"
	"fmt"
	"io"
)

// Request is the PreToolUse payload Claude Code writes to the hook's stdin.
// Field shapes verified empirically 2026-04-15 (see docs/plans/2026-04-15-claude-guard.md).
type Request struct {
	SessionID      string          `json:"session_id"`
	TranscriptPath string          `json:"transcript_path"`
	CWD            string          `json:"cwd"`
	PermissionMode string          `json:"permission_mode"`
	AgentID        string          `json:"agent_id,omitempty"`
	AgentType      string          `json:"agent_type,omitempty"`
	HookEventName  string          `json:"hook_event_name"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	ToolUseID      string          `json:"tool_use_id"`
}

// BashInput is the tool_input shape when ToolName == "Bash".
type BashInput struct {
	Command     string `json:"command"`
	Description string `json:"description,omitempty"`
}

// Bash returns the parsed Bash tool_input, or an error if ToolName is not Bash
// or the payload is malformed.
func (r *Request) Bash() (*BashInput, error) {
	if r.ToolName != "Bash" {
		return nil, fmt.Errorf("tool is %q, not Bash", r.ToolName)
	}
	var bi BashInput
	if err := json.Unmarshal(r.ToolInput, &bi); err != nil {
		return nil, fmt.Errorf("decode bash tool_input: %w", err)
	}
	return &bi, nil
}

// MonitorInput is the tool_input shape when ToolName == "Monitor".
//
// Monitor runs `command` in the same shell Bash does — it is a second
// Bash that streams stdout, not a reader attached to an already-approved
// process. Its command therefore gets the full Bash tier pipeline.
// The `ws` variant carries no command; it opens a socket to an arbitrary
// URL and is evaluated on the URL instead.
type MonitorInput struct {
	Command     string `json:"command,omitempty"`
	Description string `json:"description,omitempty"`
	WS          *struct {
		URL string `json:"url"`
	} `json:"ws,omitempty"`
}

// URL returns the WebSocket target, or "" when this is a command monitor.
func (m *MonitorInput) URL() string {
	if m.WS == nil {
		return ""
	}
	return m.WS.URL
}

// Monitor returns the parsed Monitor tool_input, or an error if ToolName
// is not Monitor or the payload is malformed.
func (r *Request) Monitor() (*MonitorInput, error) {
	if r.ToolName != "Monitor" {
		return nil, fmt.Errorf("tool is %q, not Monitor", r.ToolName)
	}
	var mi MonitorInput
	if err := json.Unmarshal(r.ToolInput, &mi); err != nil {
		return nil, fmt.Errorf("decode monitor tool_input: %w", err)
	}
	return &mi, nil
}

// WebFetchInput is the tool_input shape for WebFetch.
type WebFetchInput struct {
	URL    string `json:"url"`
	Prompt string `json:"prompt,omitempty"`
}

func (r *Request) WebFetch() (*WebFetchInput, error) {
	if r.ToolName != "WebFetch" {
		return nil, fmt.Errorf("tool is %q, not WebFetch", r.ToolName)
	}
	var wf WebFetchInput
	if err := json.Unmarshal(r.ToolInput, &wf); err != nil {
		return nil, fmt.Errorf("decode webfetch tool_input: %w", err)
	}
	return &wf, nil
}

// WebSearchInput is the tool_input shape for WebSearch.
type WebSearchInput struct {
	Query          string   `json:"query"`
	AllowedDomains []string `json:"allowed_domains,omitempty"`
}

func (r *Request) WebSearch() (*WebSearchInput, error) {
	if r.ToolName != "WebSearch" {
		return nil, fmt.Errorf("tool is %q, not WebSearch", r.ToolName)
	}
	var ws WebSearchInput
	if err := json.Unmarshal(r.ToolInput, &ws); err != nil {
		return nil, fmt.Errorf("decode websearch tool_input: %w", err)
	}
	return &ws, nil
}

// ReadInput is the tool_input shape for Read.
type ReadInput struct {
	FilePath string `json:"file_path"`
}

func (r *Request) Read() (*ReadInput, error) {
	if r.ToolName != "Read" {
		return nil, fmt.Errorf("tool is %q, not Read", r.ToolName)
	}
	var ri ReadInput
	if err := json.Unmarshal(r.ToolInput, &ri); err != nil {
		return nil, fmt.Errorf("decode read tool_input: %w", err)
	}
	return &ri, nil
}

// WriteInput is the tool_input shape for Write.
type WriteInput struct {
	FilePath string `json:"file_path"`
	Content  string `json:"content"`
}

func (r *Request) Write() (*WriteInput, error) {
	if r.ToolName != "Write" {
		return nil, fmt.Errorf("tool is %q, not Write", r.ToolName)
	}
	var wi WriteInput
	if err := json.Unmarshal(r.ToolInput, &wi); err != nil {
		return nil, fmt.Errorf("decode write tool_input: %w", err)
	}
	return &wi, nil
}

// EditInput is the tool_input shape for Edit.
type EditInput struct {
	FilePath  string `json:"file_path"`
	OldString string `json:"old_string"`
	NewString string `json:"new_string"`
}

func (r *Request) Edit() (*EditInput, error) {
	if r.ToolName != "Edit" {
		return nil, fmt.Errorf("tool is %q, not Edit", r.ToolName)
	}
	var ei EditInput
	if err := json.Unmarshal(r.ToolInput, &ei); err != nil {
		return nil, fmt.Errorf("decode edit tool_input: %w", err)
	}
	return &ei, nil
}

// Decision is an explicit verdict the guard wants to send back to Claude Code.
type Decision string

const (
	// DecisionContinue means: "no verdict, let Claude Code decide normally."
	// Emits an empty `{}` response.
	DecisionContinue Decision = ""
	// DecisionAllow auto-approves the tool use.
	DecisionAllow Decision = "allow"
	// DecisionDeny blocks the tool use. Reason is surfaced to Claude.
	DecisionDeny Decision = "deny"
)

// Response is the JSON shape Claude Code expects on stdout.
// We always emit the native `hookSpecificOutput` form; it's the most
// explicit and least likely to silently change semantics.
//
// UserMessage, when non-empty, is injected into Claude's conversation as
// a hook-side note before the next tool response. This is the Claude Code
// hook protocol's top-level `userMessage` field.
type Response struct {
	HookSpecificOutput *hookSpecificOutput `json:"hookSpecificOutput,omitempty"`
	UserMessage        string              `json:"userMessage,omitempty"`
}

type hookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

// Continue returns an empty response — no verdict, Claude Code prompts normally.
func Continue() Response {
	return Response{}
}

// Allow returns a response that auto-approves the tool use.
func Allow(reason string) Response {
	return Response{
		HookSpecificOutput: &hookSpecificOutput{
			HookEventName:            "PreToolUse",
			PermissionDecision:       "allow",
			PermissionDecisionReason: reason,
		},
	}
}

// Deny returns a response that blocks the tool use. Reason is shown to Claude.
// When hint is non-empty, it is appended to the reason on a new section
// (`<reason>\n\nRewrite: <hint>`) so Claude can self-correct on retry without
// user intervention. Empty hint preserves the pre-hint byte format.
func Deny(reason, hint string) Response {
	msg := reason
	if hint != "" {
		msg = reason + "\n\nRewrite: " + hint
	}
	return Response{
		HookSpecificOutput: &hookSpecificOutput{
			HookEventName:            "PreToolUse",
			PermissionDecision:       "deny",
			PermissionDecisionReason: msg,
		},
	}
}

// Ask surfaces Claude Code's normal permission dialog for the tool use, with
// reason shown to the user. Used by the release-freeze tier for ambiguous
// deploy commands ("in doubt, ask"): the user decides, and the dialog names the
// active freeze. PreToolUse accepts permissionDecision "ask"; if a given Claude
// Code build ignores it, the effect degrades to the normal prompt — still safe,
// and the freeze note also rides in the reason text.
func Ask(reason string) Response {
	return Response{
		HookSpecificOutput: &hookSpecificOutput{
			HookEventName:            "PreToolUse",
			PermissionDecision:       "ask",
			PermissionDecisionReason: reason,
		},
	}
}

// AllowWithMessage auto-approves the tool use and injects msg into Claude's conversation.
// Use for contextual hints (e.g. "will process 3.1 GB — 17.4 GB of 100 GB daily budget used").
func AllowWithMessage(reason, msg string) Response {
	r := Allow(reason)
	r.UserMessage = msg
	return r
}

// ContinueWithMessage falls through to the user prompt and injects msg into Claude's conversation.
// Use when the engine has no verdict but wants to hint Claude (e.g. budget exhausted, suggest rewrite).
func ContinueWithMessage(msg string) Response {
	return Response{UserMessage: msg}
}

// PermissionResponse is the JSON shape for PermissionRequest hook responses.
//
// Correct wire format (per Claude Code docs):
//
//	{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"}}}
//
// To fall through to the user prompt, return an empty PermissionResponse{} which
// serialises as {} — Claude Code shows its normal dialog when no decision is set.
type PermissionResponse struct {
	HookSpecificOutput *permissionHookOutput `json:"hookSpecificOutput,omitempty"`
}

type permissionHookOutput struct {
	HookEventName string             `json:"hookEventName"`
	Decision      permissionDecision `json:"decision"`
}

type permissionDecision struct {
	Behavior string `json:"behavior"`
}

// AllowPermission auto-approves a PermissionRequest event without showing the
// user a permission dialog.
func AllowPermission(_ string) PermissionResponse {
	return PermissionResponse{
		HookSpecificOutput: &permissionHookOutput{
			HookEventName: "PermissionRequest",
			Decision:      permissionDecision{Behavior: "allow"},
		},
	}
}

// DenyPermission blocks a PermissionRequest event.
func DenyPermission(_ string) PermissionResponse {
	return PermissionResponse{
		HookSpecificOutput: &permissionHookOutput{
			HookEventName: "PermissionRequest",
			Decision:      permissionDecision{Behavior: "deny"},
		},
	}
}

// AskPermission falls through to the normal user permission dialog by returning
// an empty response. Claude Code shows its normal prompt when no decision is set.
func AskPermission(_ string) PermissionResponse {
	return PermissionResponse{}
}

// WritePermissionResponse serialises a PermissionResponse to w.
// Use this (not WriteResponse) for PermissionRequest hooks.
func WritePermissionResponse(w io.Writer, resp PermissionResponse) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(resp)
}

// ReadRequest parses the PreToolUse JSON payload from r.
func ReadRequest(r io.Reader) (*Request, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("empty stdin")
	}
	var req Request
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("decode request: %w", err)
	}
	return &req, nil
}

// WriteResponse writes the JSON response to w and returns the number of bytes written.
// Always emits a trailing newline — easier for humans to read in logs.
func WriteResponse(w io.Writer, resp Response) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(resp)
}
