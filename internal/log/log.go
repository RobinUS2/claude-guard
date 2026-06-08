// Package log wires the claude-guard logging pipeline on top of slog.
//
// There are three log files, all JSON Lines:
//
//   - decisions.jsonl  — every decision the engine makes (allow, deny,
//     continue, parse_error). Size-rotated via lumberjack. This is the
//     firehose.
//   - denies.jsonl     — only verdict=deny entries. Append-only, never
//     rotated — blocks are rare and important for audit. Trivial tail
//     target.
//   - app.jsonl        — application messages: config warnings, LLM
//     errors, panic recovery, startup. slog Info/Warn/Error.
//
// Decision records live on their own logger (DecisionLogger) so the
// engine can emit them without app-level level filtering getting in the
// way. Application messages live on a standard *slog.Logger.
package log

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	// MsgDecision is the slog msg used for every decision event.
	// Monitor/explain/stats filter on this to separate decisions from
	// app-level messages that might share a file.
	MsgDecision = "decision"

	// MsgStopHook is the slog msg used for Stop hook evaluation events.
	MsgStopHook = "stop_hook"
)

// StopHookRecord is the shape for reading stop_hook events from decisions.jsonl.
type StopHookRecord struct {
	Time           string `json:"time"`
	Msg            string `json:"msg"`
	SessionID      string `json:"session_id,omitempty"`
	StopHookActive bool   `json:"stop_hook_active"`
	FiredRule      string `json:"fired_rule,omitempty"`
	Injected       bool   `json:"injected"`
	Suppressed     string `json:"suppressed,omitempty"` // "max_continues_reached" or ""
	ContinueCount  int    `json:"continue_count"`
	LatencyUS      int64  `json:"latency_us"`

	// Diagnostic fields for debugging rule misses.
	TranscriptTurns    int    `json:"transcript_turns,omitempty"`
	LastAssistantLen   int    `json:"last_assistant_len,omitempty"`
	LastAssistantHead  string `json:"last_assistant_head,omitempty"` // first 200 chars
	BashCallCount      int    `json:"bash_call_count,omitempty"`
	HasTodoWrite       bool   `json:"has_todo_write,omitempty"`
}

// ReadRecord is the shape for reading decision records back from the
// JSONL log. It mirrors the attribute list produced by decisionAttrs,
// with slog's standard envelope fields (time, level, msg) at the top.
type ReadRecord struct {
	Time         string      `json:"time"`
	Level        string      `json:"level"`
	Msg          string      `json:"msg"`
	GuardVersion string      `json:"guard_version,omitempty"`
	SessionID    string      `json:"session_id,omitempty"`
	ToolUseID    string      `json:"tool_use_id,omitempty"`
	AgentID      string      `json:"agent_id,omitempty"`
	AgentType    string      `json:"agent_type,omitempty"`
	CWD          string      `json:"cwd,omitempty"`
	ToolName     string      `json:"tool_name,omitempty"`
	Command      string      `json:"command,omitempty"`
	Description  string      `json:"description,omitempty"`
	Tier         string      `json:"tier,omitempty"`
	Verdict      string      `json:"verdict,omitempty"`
	Rule         string      `json:"rule,omitempty"`
	Reason       string      `json:"reason,omitempty"`
	LatencyUS     int64       `json:"latency_us,omitempty"`
	SessionTokens int64       `json:"session_tokens,omitempty"`
	Shadow        *ReadShadow `json:"shadow,omitempty"`
}

// ReadShadow mirrors the shadow group written by decisionAttrs.
type ReadShadow struct {
	Tier1Block  string `json:"tier1_block,omitempty"`
	Tier2Allow  string `json:"tier2_allow,omitempty"`
	Tier4LLM    string `json:"tier4_llm,omitempty"`
	Tier5Legacy string `json:"tier5_legacy,omitempty"`
}

// DecisionRecord is the typed shape engine passes to Decision.
// Attribute names are the wire schema — do not rename without bumping
// a schema version.
type DecisionRecord struct {
	GuardVersion string
	SessionID    string
	ToolUseID    string
	AgentID      string
	AgentType    string
	CWD          string
	ToolName     string
	Command      string
	Description  string
	Tier         string
	Verdict      string
	Rule         string
	Reason       string
	SkipReason   string `json:"skip_reason,omitempty"`
	LatencyUS    int64
	// SessionTokens is an approximate count of tokens in the Claude Code
	// transcript at decision time, derived from transcript file byte length / 5.
	// Zero means the transcript path was unavailable or the file was empty.
	// Omitted from the log entry when zero.
	SessionTokens int64

	// Shadow fields: populated when shadow mode runs a tier it didn't enforce.
	Shadow *ShadowFields
}

// ShadowFields captures each tier's hypothetical verdict for shadow-mode
// diffing against the legacy allow list.
type ShadowFields struct {
	Tier1Block  string
	Tier2Allow  string
	Tier4LLM    string
	Tier5Legacy string
}

// DecisionLogger writes decision records to two files: the firehose
// (decisions.jsonl) and the deny-only audit trail (denies.jsonl).
// Writes to each file go through a slog.JSONHandler, producing
// schema-stable JSON Lines output.
//
// A single DecisionLogger is safe for concurrent use from multiple
// goroutines within one process. Across processes, slog.JSONHandler
// writes each record in one Write call; for records under PIPE_BUF
// (4KiB on Linux/macOS) the kernel guarantees atomicity on O_APPEND,
// which is what lumberjack uses.
type DecisionLogger struct {
	firehose *slog.Logger
	denies   *slog.Logger
	// Keep writers accessible for Close.
	firehoseW io.Closer
	deniesW   io.Closer
}

// Paths describes where the three log files live.
type Paths struct {
	Dir       string // base directory
	Decisions string // decisions.jsonl (full path)
	Denies    string // denies.jsonl    (full path)
	App       string // app.jsonl       (full path)
}

// DefaultPaths returns the default file layout inside a base directory.
func DefaultPaths(dir string) Paths {
	return Paths{
		Dir:       dir,
		Decisions: filepath.Join(dir, "decisions.jsonl"),
		Denies:    filepath.Join(dir, "denies.jsonl"),
		App:       filepath.Join(dir, "app.jsonl"),
	}
}

// OpenDecisionLogger wires lumberjack + slog.JSONHandler for the two
// decision-event files. maxSizeMB <= 0 disables size rotation on the
// firehose (not recommended).
func OpenDecisionLogger(paths Paths, maxSizeMB, keepFiles int) (*DecisionLogger, error) {
	if err := os.MkdirAll(paths.Dir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir log dir: %w", err)
	}

	firehose := &lumberjack.Logger{
		Filename:   paths.Decisions,
		MaxSize:    maxSizeMB,
		MaxBackups: keepFiles,
		LocalTime:  false,
		Compress:   false,
	}
	denies := &lumberjack.Logger{
		Filename:   paths.Denies,
		MaxSize:    500, // cap but keep forever — blocks are rare
		MaxBackups: 1000,
		LocalTime:  false,
		Compress:   true, // old deny files compress well
	}

	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
		// Rewrite "time" to RFC3339Nano UTC for consistency with the rest of
		// the JSONL ecosystem (jq, Datadog, etc. handle it natively).
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey && len(groups) == 0 {
				if t, ok := a.Value.Any().(time.Time); ok {
					return slog.String(slog.TimeKey, t.UTC().Format(time.RFC3339Nano))
				}
			}
			return a
		},
	}

	// Wrap each JSON handler so the `command` attr is redacted before
	// hitting disk. See redact_handler.go — single chokepoint for command
	// secrets across decisions.jsonl and denies.jsonl.
	return &DecisionLogger{
		firehose:  slog.New(newRedactingHandler(slog.NewJSONHandler(firehose, opts))),
		denies:    slog.New(newRedactingHandler(slog.NewJSONHandler(denies, opts))),
		firehoseW: firehose,
		deniesW:   denies,
	}, nil
}

// Close releases the underlying file writers. Safe to call on nil.
func (l *DecisionLogger) Close() {
	if l == nil {
		return
	}
	if l.firehoseW != nil {
		_ = l.firehoseW.Close()
	}
	if l.deniesW != nil {
		_ = l.deniesW.Close()
	}
}

// Decision writes a decision record. Always goes to the firehose;
// additionally written to denies.jsonl when Verdict == "deny".
func (l *DecisionLogger) Decision(rec DecisionRecord) {
	if l == nil {
		return
	}
	ctx := context.Background()
	attrs := decisionAttrs(rec)
	l.firehose.LogAttrs(ctx, slog.LevelInfo, MsgDecision, attrs...)
	if rec.Verdict == "deny" {
		l.denies.LogAttrs(ctx, slog.LevelInfo, MsgDecision, attrs...)
	}
}

// StopHook writes a Stop-hook evaluation record to the firehose. Field
// names and order must match StopHookRecord exactly — both stats and
// hotspots read this shape back, and operators grep the raw JSONL.
// A stable, schema-declared order keeps lines diffable.
func (l *DecisionLogger) StopHook(rec StopHookRecord) {
	if l == nil {
		return
	}
	// Attrs appear in this exact order in the output, matching the
	// json-tag order of StopHookRecord. Optional strings ("") are
	// omitted to stay consistent with the `,omitempty` tags.
	attrs := make([]slog.Attr, 0, 6)
	if rec.SessionID != "" {
		attrs = append(attrs, slog.String("session_id", rec.SessionID))
	}
	attrs = append(attrs, slog.Bool("stop_hook_active", rec.StopHookActive))
	if rec.FiredRule != "" {
		attrs = append(attrs, slog.String("fired_rule", rec.FiredRule))
	}
	attrs = append(attrs, slog.Bool("injected", rec.Injected))
	if rec.Suppressed != "" {
		attrs = append(attrs, slog.String("suppressed", rec.Suppressed))
	}
	attrs = append(attrs,
		slog.Int("continue_count", rec.ContinueCount),
		slog.Int64("latency_us", rec.LatencyUS),
	)
	// Diagnostic fields — omit when zero to keep existing log lines short.
	if rec.TranscriptTurns > 0 {
		attrs = append(attrs, slog.Int("transcript_turns", rec.TranscriptTurns))
	}
	if rec.LastAssistantLen > 0 {
		attrs = append(attrs,
			slog.Int("last_assistant_len", rec.LastAssistantLen),
			slog.String("last_assistant_head", rec.LastAssistantHead),
		)
	}
	if rec.BashCallCount > 0 {
		attrs = append(attrs, slog.Int("bash_call_count", rec.BashCallCount))
	}
	if rec.HasTodoWrite {
		attrs = append(attrs, slog.Bool("has_todo_write", true))
	}
	l.firehose.LogAttrs(context.Background(), slog.LevelInfo, MsgStopHook, attrs...)
}

// decisionAttrs produces the stable attribute list. Field names here
// are the wire schema — do not rename without a schema version bump.
func decisionAttrs(rec DecisionRecord) []slog.Attr {
	attrs := []slog.Attr{
		slog.String("guard_version", rec.GuardVersion),
		slog.String("tool_name", rec.ToolName),
		slog.String("tier", rec.Tier),
		slog.String("verdict", rec.Verdict),
		slog.Int64("latency_us", rec.LatencyUS),
	}
	if rec.SessionID != "" {
		attrs = append(attrs, slog.String("session_id", rec.SessionID))
	}
	if rec.ToolUseID != "" {
		attrs = append(attrs, slog.String("tool_use_id", rec.ToolUseID))
	}
	if rec.AgentID != "" {
		attrs = append(attrs, slog.String("agent_id", rec.AgentID))
	}
	if rec.AgentType != "" {
		attrs = append(attrs, slog.String("agent_type", rec.AgentType))
	}
	if rec.CWD != "" {
		attrs = append(attrs, slog.String("cwd", rec.CWD))
	}
	if rec.Command != "" {
		cmd := rec.Command
		if len(cmd) > 2000 {
			cmd = cmd[:1997] + "..."
		}
		attrs = append(attrs, slog.String("command", cmd))
	}
	if rec.Description != "" {
		attrs = append(attrs, slog.String("description", rec.Description))
	}
	if rec.Rule != "" {
		attrs = append(attrs, slog.String("rule", rec.Rule))
	}
	if rec.Reason != "" {
		reason := rec.Reason
		if len(reason) > 500 {
			reason = reason[:497] + "..."
		}
		attrs = append(attrs, slog.String("reason", reason))
	}
	if rec.SessionTokens > 0 {
		attrs = append(attrs, slog.Int64("session_tokens", rec.SessionTokens))
	}
	if rec.Shadow != nil {
		var sub []any
		if rec.Shadow.Tier1Block != "" {
			sub = append(sub, slog.String("tier1_block", rec.Shadow.Tier1Block))
		}
		if rec.Shadow.Tier2Allow != "" {
			sub = append(sub, slog.String("tier2_allow", rec.Shadow.Tier2Allow))
		}
		if rec.Shadow.Tier4LLM != "" {
			sub = append(sub, slog.String("tier4_llm", rec.Shadow.Tier4LLM))
		}
		if rec.Shadow.Tier5Legacy != "" {
			sub = append(sub, slog.String("tier5_legacy", rec.Shadow.Tier5Legacy))
		}
		if len(sub) > 0 {
			attrs = append(attrs, slog.Group("shadow", sub...))
		}
	}
	return attrs
}

// OpenAppLogger wires lumberjack + slog.JSONHandler for app-level events.
// Returns a vanilla *slog.Logger that should be used (or passed to
// slog.SetDefault) for everything that is not a decision record.
func OpenAppLogger(path string, maxSizeMB, keepFiles int) (*slog.Logger, io.Closer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, nil, fmt.Errorf("mkdir log dir: %w", err)
	}
	w := &lumberjack.Logger{
		Filename:   path,
		MaxSize:    maxSizeMB,
		MaxBackups: keepFiles,
		LocalTime:  false,
	}
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey && len(groups) == 0 {
				if t, ok := a.Value.Any().(time.Time); ok {
					return slog.String(slog.TimeKey, t.UTC().Format(time.RFC3339Nano))
				}
			}
			return a
		},
	}
	// Wrap so `command` attrs passed by engine callsites (e.g.
	// llm_budget_exhausted) are redacted before reaching app.jsonl.
	return slog.New(newRedactingHandler(slog.NewJSONHandler(w, opts))), w, nil
}
