package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/RobinUS2/claude-guard/internal/config"
	clog "github.com/RobinUS2/claude-guard/internal/log"
	"github.com/RobinUS2/claude-guard/internal/stop"
)

const stopShellTimeoutMs = 500

type stopInput struct {
	SessionID      string            `json:"session_id"`
	StopHookActive bool              `json:"stop_hook_active"`
	Transcript     []json.RawMessage `json:"transcript"`
}

type stopResponse struct {
	UserMessage string `json:"userMessage,omitempty"`
}

func cmdStop(_ []string) int {
	return cmdStopWithIO(os.Stdin, os.Stdout)
}

func cmdStopWithIO(r io.Reader, w io.Writer) int {
	start := time.Now()

	// Resolve the app log path from config (same file decide writes to).
	// A failure to open the logger must never block Claude — fall back
	// to a discarding slog so the rest of the flow is unchanged.
	logger := openStopAppLogger()

	data, err := io.ReadAll(r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stop: read stdin: %v\n", err)
		logger.Error("stop_read_error", "error", err.Error())
		return 1
	}

	var in stopInput
	if err := json.Unmarshal(data, &in); err != nil {
		// Malformed input: fail-open, let Claude stop.
		fmt.Fprintf(os.Stderr, "stop: parse input: %v\n", err)
		logger.Warn("stop_parse_error", "error", err.Error())
		return writeStopResp(w, "")
	}

	tr := parseTranscript(in.Transcript)
	timeout := time.Duration(stopShellTimeoutMs) * time.Millisecond

	res := stop.EvaluateResult(
		in.SessionID,
		os.TempDir(),
		in.StopHookActive,
		tr,
		stop.DefaultRules(),
		timeout,
	)

	logger.Info("stop_decision",
		"session_id", in.SessionID,
		"stop_hook_active", in.StopHookActive,
		"rule", res.Rule,
		"fired", res.Message != "",
		"cap_reached", res.CapReached,
		"rules_seen", res.RulesSeen,
		"bash_calls", len(tr.BashCalls),
		"has_todo_write", tr.HasTodoWrite,
		"reason", res.Message,
		"latency_ms", time.Since(start).Milliseconds(),
	)

	return writeStopResp(w, res.Message)
}

// openStopAppLogger returns a logger that appends to the same app.jsonl
// the decide path uses. Failures degrade to a no-op logger so the stop
// hook still runs.
func openStopAppLogger() *slog.Logger {
	result := config.Load("")
	cfg := result.Config

	logDir := cfg.Log.Dir
	if logDir == "" {
		logDir = config.DefaultLogDir()
	}
	paths := clog.DefaultPaths(logDir)

	lg, _, err := clog.OpenAppLogger(paths.App, cfg.Log.MaxSizeMB, cfg.Log.KeepFiles)
	if err != nil || lg == nil {
		return slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	return lg
}

func writeStopResp(w io.Writer, msg string) int {
	data, _ := json.Marshal(stopResponse{UserMessage: msg})
	fmt.Fprintln(w, string(data))
	return 0
}

// parseTranscript extracts the Transcript fields claude-guard rules need.
//
// Claude Code transcript format:
//   - role="user":      string or []content-block
//   - role="assistant": string or []content-block, which includes type="text"
//     AND type="tool_use" blocks (this is where Bash/TodoWrite calls live)
//
// Tool calls appear inside assistant content as type="tool_use" — NOT as
// separate role="tool" entries. This is the key structural fact.
func parseTranscript(raw []json.RawMessage) stop.Transcript {
	var tr stop.Transcript

	type contentBlock struct {
		Type  string          `json:"type"`
		Text  string          `json:"text"`
		Name  string          `json:"name"`
		Input json.RawMessage `json:"input"`
	}
	type turn struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	}
	type bashInput struct {
		Command string `json:"command"`
	}
	type todoInput struct {
		Todos []stop.TodoItem `json:"todos"`
	}

	var lastAssistantParts []string
	firstUser := true

	for _, rawTurn := range raw {
		var t turn
		if err := json.Unmarshal(rawTurn, &t); err != nil {
			continue
		}

		switch t.Role {
		case "user":
			if firstUser {
				firstUser = false
				var s string
				if err := json.Unmarshal(t.Content, &s); err == nil {
					tr.FirstUserText = s
				}
			}

		case "assistant":
			lastAssistantParts = nil

			var s string
			if err := json.Unmarshal(t.Content, &s); err == nil {
				lastAssistantParts = append(lastAssistantParts, s)
				break
			}

			var blocks []contentBlock
			if err := json.Unmarshal(t.Content, &blocks); err != nil {
				break
			}
			for _, blk := range blocks {
				switch blk.Type {
				case "text":
					if blk.Text != "" {
						lastAssistantParts = append(lastAssistantParts, blk.Text)
					}
				case "tool_use":
					if blk.Name == "Bash" {
						var inp bashInput
						if err := json.Unmarshal(blk.Input, &inp); err == nil && inp.Command != "" {
							tr.BashCalls = append(tr.BashCalls, inp.Command)
						}
					}
					if blk.Name == "TodoWrite" {
						var inp todoInput
						if err := json.Unmarshal(blk.Input, &inp); err == nil && len(inp.Todos) > 0 {
							tr.HasTodoWrite = true
							tr.LastTodoItems = inp.Todos
						}
					}
				}
			}
		}
	}
	tr.LastAssistantText = strings.Join(lastAssistantParts, "\n")
	return tr
}
