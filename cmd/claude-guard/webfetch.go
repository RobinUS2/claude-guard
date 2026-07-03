package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	return runWebFetch(os.Stdin, os.Stdout, os.Stderr)
}

// runWebFetch is the testable core of cmdWebFetch. It reads a PermissionRequest
// JSON from in, inspects the URL, and writes the decision to out.
func runWebFetch(in io.Reader, out io.Writer, errOut io.Writer) int {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(errOut, "claude-guard webfetch: panic: %v\n", r)
			_ = hook.WritePermissionResponse(out, hook.AllowPermission("panic recovery"))
		}
	}()

	req, err := hook.ReadRequest(in)
	if err != nil {
		_ = hook.WritePermissionResponse(out, hook.AllowPermission("stdin parse error"))
		return 0
	}

	wf, err := req.WebFetch()
	if err != nil {
		// Not a WebFetch call — nothing to inspect, allow immediately.
		_ = hook.WritePermissionResponse(out, hook.AllowPermission("not a webfetch call"))
		return 0
	}

	verdict := webinspect.Inspect(context.Background(), wf.URL, webinspect.Config{})

	if verdict.Allow {
		_ = hook.WritePermissionResponse(out, hook.AllowPermission(verdict.Reason))
	} else {
		// Surface the normal permission prompt so the user can decide.
		// Print to errOut so the reason appears above the prompt.
		fmt.Fprintln(errOut, "claude-guard webfetch:", verdict.Reason)
		_ = hook.WritePermissionResponse(out, hook.AskPermission(verdict.Reason))
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
