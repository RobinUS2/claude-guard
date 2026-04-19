//go:build integration

package main

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"testing"
)

// TestDecideBinary_StructuralAllowForAgent verifies the full path:
// PreToolUse JSON on stdin → engine decide → HookOutput on stdout.
//
// Unit tests cover engine.Decide() in-process. They don't catch wiring
// bugs in cmd/claude-guard/decide.go (JSON parsing, env handling,
// stdout response shape). This test exercises the actual binary via
// `go run .` so we don't depend on a built artifact.
//
// Build tag `integration` keeps it out of the default `go test ./...`
// run because it shells out and is slow. Invoke with:
//
//	go test -tags=integration ./cmd/claude-guard/... -v
func TestDecideBinary_StructuralAllowForAgent(t *testing.T) {
	payload := map[string]any{
		"tool_name":  "Agent",
		"tool_input": map[string]any{"description": "x", "prompt": "y"},
		"cwd":        t.TempDir(),
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	cmd := exec.Command("go", "run", ".", "decide")
	cmd.Stdin = bytes.NewReader(buf)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// cwd defaults to the package directory under `go test`, which is
	// already cmd/claude-guard — `go run .` resolves to this package.
	if err := cmd.Run(); err != nil {
		t.Fatalf("decide exited non-zero: %v\nstderr: %s\nstdout: %s",
			err, stderr.String(), stdout.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON on stdout: %v\nraw: %s", err, stdout.String())
	}
	hso, ok := resp["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatalf("missing hookSpecificOutput in response: %s", stdout.String())
	}
	if got := hso["permissionDecision"]; got != "allow" {
		t.Errorf("permissionDecision = %v, want \"allow\" — Agent should auto-allow via safe-builtin-tool\nresp: %s",
			got, stdout.String())
	}
}
