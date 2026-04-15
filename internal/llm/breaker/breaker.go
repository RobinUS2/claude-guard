// Package breaker implements a file-backed circuit breaker for the LLM
// tier. State persists across hook invocations because the guard is a
// short-lived process — there is no in-memory state to share.
//
// The state file lives at ~/.cache/claude-guard/llm-circuit.json and is
// updated atomically (write to *.tmp + Rename). Two concurrent guard
// processes can race on writes; the loser's update is harmlessly
// overwritten by the next successful classify call.
//
// State machine:
//
//	closed      → all calls allowed
//	open        → all calls skipped until OpenUntil
//	half-open   → next single call is a probe; success closes, failure
//	              re-opens with extended cooldown (handled inline by the
//	              caller via RecordSuccess / RecordFailure)
//
// The breaker is instantiated per call (cheap: read one small JSON
// file, parse, return). It is not a long-lived object and does not
// hold OS resources.
package breaker

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// State represents the circuit's persisted state.
type State struct {
	// Status is "closed", "open", or "half_open".
	Status string `json:"status"`

	// OpenUntil is the deadline after which the next call may be
	// attempted as a probe. Zero when Status == "closed".
	OpenUntil time.Time `json:"open_until,omitempty"`

	// ConsecutiveFailures counts unsuccessful calls since the last
	// success. Reset on RecordSuccess.
	ConsecutiveFailures int `json:"consecutive_failures"`

	// Reason is a short tag for why the circuit opened ("rate_limit",
	// "server_error", "timeout").
	Reason string `json:"reason,omitempty"`

	// LastError is the most recent error message. Surfaced by doctor.
	LastError string `json:"last_error,omitempty"`

	// LastFailureAt is when the most recent failure occurred.
	LastFailureAt time.Time `json:"last_failure_at,omitempty"`

	// LastSuccessAt is when the most recent success occurred.
	LastSuccessAt time.Time `json:"last_success_at,omitempty"`
}

// Breaker manages the circuit state file at Path.
type Breaker struct {
	Path string

	// Tunables — sensible defaults; can be overridden in tests.
	FailuresBeforeOpen int
	DefaultCooldown    time.Duration

	// now is injectable for testing.
	now func() time.Time
}

// New returns a Breaker rooted at path. Defaults: 3 failures → open,
// 60-second cooldown for non-rate-limit errors.
func New(path string) *Breaker {
	return &Breaker{
		Path:               path,
		FailuresBeforeOpen: 3,
		DefaultCooldown:    60 * time.Second,
		now:                time.Now,
	}
}

// Check returns whether the circuit currently permits a call. When false,
// reason carries a short user-readable explanation including the deadline.
//
// "permitted" semantics:
//   - closed                          → true
//   - open + now <  OpenUntil         → false (deadline not reached)
//   - open + now >= OpenUntil         → true  (probe call permitted)
//   - half_open                       → true  (probe permitted)
func (b *Breaker) Check() (permitted bool, deadline time.Time, reason string) {
	state, err := b.load()
	if err != nil || state == nil || state.Status == "" || state.Status == "closed" {
		return true, time.Time{}, ""
	}
	now := b.now()
	if !state.OpenUntil.IsZero() && now.Before(state.OpenUntil) {
		return false, state.OpenUntil, fmt.Sprintf("circuit open until %s (%s)", state.OpenUntil.Format(time.RFC3339), state.Reason)
	}
	// Either status was open with deadline reached, or already half_open.
	// Permit a probe.
	return true, time.Time{}, ""
}

// State returns the current persisted state (read-only). Returns nil
// state and nil error if the file does not exist (which is the
// healthy/closed default).
func (b *Breaker) State() (*State, error) {
	return b.load()
}

// RecordSuccess closes the circuit and clears failure counters.
// Idempotent — safe to call when already closed.
func (b *Breaker) RecordSuccess() error {
	now := b.now()
	return b.save(&State{
		Status:        "closed",
		LastSuccessAt: now,
	})
}

// RecordFailure increments the failure counter and, if the threshold
// has been reached, opens the circuit. The cooldown is determined by
// the error: a *RateLimitError carries an explicit deadline; other
// errors use DefaultCooldown.
//
// Returns the resulting State so callers can log the new state.
func (b *Breaker) RecordFailure(err error) (*State, error) {
	prev, _ := b.load()
	if prev == nil {
		prev = &State{}
	}
	now := b.now()
	prev.ConsecutiveFailures++
	prev.LastError = err.Error()
	prev.LastFailureAt = now

	var rl *RateLimitError
	if errors.As(err, &rl) && !rl.RetryAfter.IsZero() {
		// Rate limit always opens the circuit (one failure is enough —
		// we know exactly when it'll be safe to retry).
		prev.Status = "open"
		prev.OpenUntil = rl.RetryAfter
		prev.Reason = "rate_limit"
	} else if prev.ConsecutiveFailures >= b.FailuresBeforeOpen {
		prev.Status = "open"
		prev.OpenUntil = now.Add(b.DefaultCooldown)
		prev.Reason = classifyError(err)
	} else {
		// Below threshold — record but stay closed.
		prev.Status = "closed"
		prev.OpenUntil = time.Time{}
	}

	if err := b.save(prev); err != nil {
		return prev, err
	}
	return prev, nil
}

// load reads and parses the state file. Returns (nil, nil) if the file
// does not exist (which means "healthy / closed").
func (b *Breaker) load() (*State, error) {
	data, err := os.ReadFile(b.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read circuit state: %w", err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		// Corrupted file — treat as closed and overwrite next time.
		return nil, nil
	}
	return &s, nil
}

// save atomically writes the state file (tmp + rename).
func (b *Breaker) save(s *State) error {
	if err := os.MkdirAll(filepath.Dir(b.Path), 0o755); err != nil {
		return fmt.Errorf("mkdir circuit dir: %w", err)
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	tmp := b.Path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmp, b.Path); err != nil {
		return fmt.Errorf("rename tmp: %w", err)
	}
	return nil
}

// classifyError maps an error to a short reason tag.
func classifyError(err error) string {
	if err == nil {
		return ""
	}
	var srv *ServerError
	if errors.As(err, &srv) {
		return "server_error"
	}
	var t *TimeoutError
	if errors.As(err, &t) {
		return "timeout"
	}
	return "unknown"
}

// --- error types ---

// RateLimitError carries an explicit retry deadline from the LLM API.
type RateLimitError struct {
	RetryAfter time.Time
	Detail     string
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("rate limited; retry after %s: %s", e.RetryAfter.Format(time.RFC3339), e.Detail)
}

// ServerError represents a 5xx response.
type ServerError struct {
	StatusCode int
	Detail     string
}

func (e *ServerError) Error() string {
	return fmt.Sprintf("server error %d: %s", e.StatusCode, e.Detail)
}

// TimeoutError represents a network or context timeout.
type TimeoutError struct {
	After time.Duration
}

func (e *TimeoutError) Error() string {
	return fmt.Sprintf("timeout after %s", e.After)
}
