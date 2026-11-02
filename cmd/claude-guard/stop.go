package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/RobinUS2/claude-guard/internal/config"
	clog "github.com/RobinUS2/claude-guard/internal/log"
	"github.com/RobinUS2/claude-guard/internal/stop"
)

const stopShellTimeoutMs = 500

// stopInput is the documented Stop hook input. Transcript is the legacy
// inline array, used only when last_assistant_message is absent.
type stopInput struct {
	SessionID            string            `json:"session_id"`
	TranscriptPath       string            `json:"transcript_path"`
	StopHookActive       bool              `json:"stop_hook_active"`
	LastAssistantMessage json.RawMessage   `json:"last_assistant_message"`
	Transcript           []json.RawMessage `json:"transcript"`
	// BackgroundTasks and SessionCrons are kept raw so a missing field
	// (older Claude Code) can be told apart from an empty array.
	BackgroundTasks json.RawMessage `json:"background_tasks"`
	SessionCrons    json.RawMessage `json:"session_crons"`
}

// stopResponse is the documented Stop hook output: decision "block" with a
// reason sends the session back to work; an empty object lets it stop.
type stopResponse struct {
	Decision string `json:"decision,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

func cmdStop(_ []string) int {
	return cmdStopWithIO(os.Stdin, os.Stdout)
}

func cmdStopWithIO(r io.Reader, w io.Writer) int {
	start := time.Now()

	// Open the decision logger so we can emit a stop_hook record to
	// decisions.jsonl — same file `stats` and `hotspots` read. Failure
	// to open must never block Claude: a nil logger is a safe no-op.
	cfg := config.Load("").Config
	dlog := openStopDecisionLogger(cfg)
	defer dlog.Close()

	data, err := io.ReadAll(r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stop: read stdin: %v\n", err)
		return 1
	}

	in, tr, err := parseStopInput(data)
	if err != nil {
		// Malformed input: fail-open, let Claude stop.
		fmt.Fprintf(os.Stderr, "stop: parse input: %v\n", err)
		return writeStopResp(w, "")
	}

	timeout := time.Duration(stopShellTimeoutMs) * time.Millisecond

	// Build rule list: deterministic rules first, LLM semantic review last.
	// LLM rule only fires after all deterministic rules return false,
	// and at most once per session (MaxContinues=1 enforced by EvaluateResult).
	rules := stop.DefaultRules()
	if llmRule := stop.NewLLMStopRule(); llmRule != nil {
		rules = append(rules, llmRule)
	}

	res := stop.EvaluateModes(
		in.SessionID,
		os.TempDir(),
		in.StopHookActive,
		tr,
		rules,
		timeout,
		cfg.Stop.Modes,
	)
	for _, name := range res.WouldBlock {
		dlog.StopWouldBlock(clog.StopWouldBlockRecord{SessionID: in.SessionID, Rule: name})
	}

	suppressed := ""
	if res.CapReached {
		suppressed = "max_continues_reached"
	}

	// Truncate last assistant text for logging.
	head := tr.LastAssistantText
	if len(head) > 200 {
		head = head[:200]
	}
	dlog.StopHook(clog.StopHookRecord{
		SessionID:         in.SessionID,
		StopHookActive:    in.StopHookActive,
		FiredRule:         res.Rule,
		Injected:          res.Message != "",
		Suppressed:        suppressed,
		ContinueCount:     res.ContinueCount,
		LatencyUS:         time.Since(start).Microseconds(),
		TranscriptTurns:   len(in.Transcript),
		LastAssistantLen:  len(tr.LastAssistantText),
		LastAssistantHead: head,
		BashCallCount:     len(tr.BashCalls),
		HasTodoWrite:      tr.HasTodoWrite,
	})

	return writeStopResp(w, res.Message)
}

// openStopDecisionLogger opens the same decisions.jsonl + denies.jsonl
// pair the decide path uses. Returns nil on failure so callers can
// treat the logger as a no-op and never block Claude.
func openStopDecisionLogger(cfg *config.Config) *clog.DecisionLogger {
	logDir := cfg.Log.Dir
	if logDir == "" {
		logDir = config.DefaultLogDir()
	}
	paths := clog.DefaultPaths(logDir)

	lg, err := clog.OpenDecisionLogger(paths, cfg.Log.MaxSizeMB, cfg.Log.KeepFiles)
	if err != nil {
		return nil
	}
	return lg
}

func writeStopResp(w io.Writer, msg string) int {
	resp := stopResponse{}
	if msg != "" {
		resp = stopResponse{Decision: "block", Reason: msg}
	}
	data, _ := json.Marshal(resp)
	fmt.Fprintln(w, string(data))
	return 0
}

// applyRunning copies the running-work counts from the Stop hook input onto
// the transcript. RunningKnown stays false unless at least one of the two
// fields is present as an array, so older Claude Code never triggers rules
// that depend on it.
func applyRunning(tr *stop.Transcript, in stopInput) {
	if n, ok := arrayLen(in.BackgroundTasks); ok {
		tr.BackgroundTasks = n
		tr.RunningKnown = true
	}
	if n, ok := arrayLen(in.SessionCrons); ok {
		tr.SessionCrons = n
		tr.RunningKnown = true
	}
}

// arrayLen returns the element count of a raw JSON array, and false when the
// field is absent, null or not an array.
func arrayLen(raw json.RawMessage) (int, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil || arr == nil {
		return 0, false
	}
	return len(arr), true
}

// parseStopInput decodes the Stop hook JSON into the input and the
// transcript rules evaluate, including the running-work fields.
// last_assistant_message wins over the legacy transcript array.
func parseStopInput(data []byte) (stopInput, stop.Transcript, error) {
	var in stopInput
	if err := json.Unmarshal(data, &in); err != nil {
		return in, stop.Transcript{}, err
	}
	tr := parseTranscript(in.Transcript)
	var msg string
	if string(in.LastAssistantMessage) != "null" && json.Unmarshal(in.LastAssistantMessage, &msg) == nil {
		tr.LastAssistantText = msg
	}
	applyRunning(&tr, in)
	return in, tr, nil
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
	tr.TurnCount = len(raw)
	// Approximate transcript size — sum of raw JSON bytes.
	for _, r := range raw {
		tr.TranscriptBytes += len(r)
	}
	return tr
}
