package log

import (
	"context"
	"log/slog"

	"github.com/RobinUS2/claude-guard/internal/redact"
)

// redactingHandler wraps a slog.Handler and applies redact.Apply to the
// value of any attr named "command" before delegating to the underlying
// handler. This is the single chokepoint for command redaction in
// claude-guard's persisted logs — decisions.jsonl, denies.jsonl, and
// app.jsonl all flow through it.
//
// Rationale (defense in depth): callsites that pass a `command` attr
// live in multiple packages (engine, log, future code). A future
// contributor adding a new log site cannot accidentally leak secrets
// as long as they use the conventional attr name. Wrapping the handler
// makes the privacy property a property of the writer, not of every
// caller.
//
// Field-name scope is deliberately narrow: only "command" is redacted.
// Wholesale string redaction would mangle reasons, version strings,
// rule names, etc. — fields that should be readable for monitoring.
// If future leak sources surface other fields (verifier_reason,
// last_assistant_head, …), add them here explicitly.
type redactingHandler struct {
	inner slog.Handler
}

func newRedactingHandler(inner slog.Handler) slog.Handler {
	return &redactingHandler{inner: inner}
}

func (h *redactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *redactingHandler) Handle(ctx context.Context, r slog.Record) error {
	// Build a new Record with the same envelope but rewritten attrs.
	// slog.Record.AddAttrs appends; there is no in-place attr edit API,
	// so we copy. Allocation per record is unavoidable here.
	clone := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		clone.AddAttrs(redactAttr(a))
		return true
	})
	return h.inner.Handle(ctx, clone)
}

func (h *redactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	redacted := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		redacted[i] = redactAttr(a)
	}
	return &redactingHandler{inner: h.inner.WithAttrs(redacted)}
}

func (h *redactingHandler) WithGroup(name string) slog.Handler {
	return &redactingHandler{inner: h.inner.WithGroup(name)}
}

// redactAttr returns the attr unchanged unless it names a known
// command-bearing field with a string value, in which case the value
// is replaced with redact.Apply(value).
func redactAttr(a slog.Attr) slog.Attr {
	if a.Key != "command" {
		return a
	}
	if a.Value.Kind() != slog.KindString {
		return a
	}
	return slog.String("command", redact.Apply(a.Value.String()))
}
