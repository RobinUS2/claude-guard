package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
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
	stop.RecordWouldBlock(dlog, in.SessionID, res)

	suppressed := ""
	if res.CapReached {
		suppressed = "max_continues_reached"
	}

	// Only the message length is logged, never any of its text.
	dlog.StopHook(clog.StopHookRecord{
		SessionID:        in.SessionID,
		StopHookActive:   in.StopHookActive,
		FiredRule:        res.Rule,
		Injected:         res.Message != "",
		Suppressed:       suppressed,
		ContinueCount:    res.ContinueCount,
		LatencyUS:        time.Since(start).Microseconds(),
		TranscriptTurns:  tr.TurnCount,
		LastAssistantLen: len(tr.LastAssistantText),
		BashCallCount:    len(tr.BashCalls),
		HasTodoWrite:     tr.HasTodoWrite,
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
// the transcript. RunningKnown is true only when BOTH background_tasks and
// session_crons are arrays; if either is absent, null or not an array, what
// is running is unknown and rules that depend on it stay quiet.
func applyRunning(tr *stop.Transcript, in stopInput) {
	tasks, okTasks := arrayLen(in.BackgroundTasks)
	crons, okCrons := arrayLen(in.SessionCrons)
	if !okTasks || !okCrons {
		return
	}
	tr.BackgroundTasks = tasks
	tr.SessionCrons = crons
	tr.RunningKnown = true
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
	// Without an inline transcript, the transcript file is the data source.
	// When it cannot be read either, the transcript rules are blind.
	if len(in.Transcript) == 0 {
		if fileTurns, ok := readTranscriptFile(in.TranscriptPath); ok {
			tr = parseTranscript(fileTurns.turns)
			if fileTurns.truncated {
				// The first user message was cut off with the head of the file.
				tr.FirstUserText = ""
			}
		} else {
			tr.TranscriptBlind = true
		}
	}
	// The legacy transcript text is used only when the field is absent. A
	// present but null or non-string value counts as an empty message.
	if len(in.LastAssistantMessage) > 0 {
		var msg string
		_ = json.Unmarshal(in.LastAssistantMessage, &msg)
		tr.LastAssistantText = msg
	}
	applyRunning(&tr, in)
	return in, tr, nil
}

// maxTranscriptBytes bounds how much of the transcript file is read: the last
// 2 MB, so a long session cannot slow the hook down.
const maxTranscriptBytes = 2 << 20

type transcriptFile struct {
	turns     []json.RawMessage
	truncated bool // only the tail of the file was read
}

// readTranscriptFile reads the Claude Code transcript JSONL at path (last
// maxTranscriptBytes only) and returns its turns in the {role, content}
// shape parseTranscript expects. Each line wraps its turn in "message".
// ok is false when the path is empty, missing or unreadable.
func readTranscriptFile(path string) (transcriptFile, bool) {
	var out transcriptFile
	if path == "" {
		return out, false
	}
	f, err := os.Open(path)
	if err != nil {
		return out, false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		return out, false
	}
	if st.Size() > maxTranscriptBytes {
		if _, err := f.Seek(st.Size()-maxTranscriptBytes, io.SeekStart); err != nil {
			return out, false
		}
		out.truncated = true
	}
	data, err := io.ReadAll(io.LimitReader(f, maxTranscriptBytes))
	if err != nil {
		return out, false
	}
	if out.truncated {
		// Drop the partial first line.
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data = data[i+1:]
		} else {
			data = nil
		}
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		var entry struct {
			Message json.RawMessage `json:"message"`
		}
		if err := json.Unmarshal(line, &entry); err != nil || len(entry.Message) == 0 {
			continue
		}
		var turn struct {
			Role string `json:"role"`
		}
		if err := json.Unmarshal(entry.Message, &turn); err != nil || turn.Role == "" {
			continue
		}
		out.turns = append(out.turns, entry.Message)
	}
	return out, true
}

// parseTranscript extracts the Transcript fields claude-guard rules need.
func parseTranscript(raw []json.RawMessage) stop.Transcript {
	return stop.ParseTranscript(raw)
}
