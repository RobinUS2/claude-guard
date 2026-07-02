package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/RobinUS2/claude-guard/internal/hook"
	"github.com/RobinUS2/claude-guard/internal/webinspect"
)

// cmdWebFetch is the PermissionRequest hook entrypoint for WebFetch calls.
//
// It reads the hook JSON from stdin, pre-fetches the URL with Chrome headers,
// asks Haiku whether the content is safe, and writes an allow/ask decision to
// stdout. Always fails open — any error returns Allow so legitimate work is
// never blocked by an inspector failure.
func cmdWebFetch(_ []string) int {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "claude-guard webfetch: panic: %v\n", r)
			_ = hook.WriteResponse(os.Stdout, hook.Allow("panic recovery"))
		}
	}()

	req, err := hook.ReadRequest(os.Stdin)
	if err != nil {
		_ = hook.WriteResponse(os.Stdout, hook.Allow("stdin parse error"))
		return 0
	}

	wf, err := req.WebFetch()
	if err != nil {
		// Not a WebFetch call — nothing to inspect, allow immediately.
		_ = hook.WriteResponse(os.Stdout, hook.Allow("not a webfetch call"))
		return 0
	}

	verdict := webinspect.Inspect(context.Background(), wf.URL, webinspect.Config{})

	if verdict.Allow {
		_ = hook.WriteResponse(os.Stdout, hook.AllowPermission(verdict.Reason))
	} else {
		// Fail to Continue so Claude Code surfaces the normal permission prompt.
		// Print the reason so it appears above the prompt.
		fmt.Fprintln(os.Stderr, "claude-guard webfetch:", verdict.Reason)
		_ = hook.WriteResponse(os.Stdout, hook.Continue())
	}

	return 0
}

// webfetchTestInput is used by cmdWebFetchTest to build a synthetic hook
// request for manual testing without running the full hook pipeline.
type webfetchTestInput struct {
	URL string `json:"url"`
}

// cmdWebFetchTest lets you test the inspector against a URL from the command
// line without triggering a real hook:
//
//	claude-guard webfetch-test https://example.com
func cmdWebFetchTest(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: claude-guard webfetch-test <url>")
		return 2
	}
	url := args[0]

	synthetic := map[string]interface{}{
		"tool_name":       "WebFetch",
		"hook_event_name": "PermissionRequest",
		"tool_input":      map[string]string{"url": url},
	}
	raw, _ := json.Marshal(synthetic)

	req, err := hook.ReadRequest(bytes.NewReader(raw))
	if err != nil {
		fmt.Fprintf(os.Stderr, "build request: %v\n", err)
		return 1
	}

	wf, err := req.WebFetch()
	if err != nil {
		fmt.Fprintf(os.Stderr, "webfetch parse: %v\n", err)
		return 1
	}

	verdict := webinspect.Inspect(context.Background(), wf.URL, webinspect.Config{})
	if verdict.Allow {
		fmt.Printf("ALLOW  %s\n", verdict.Reason)
	} else {
		fmt.Printf("ASK    %s\n", verdict.Reason)
	}
	return 0
}
