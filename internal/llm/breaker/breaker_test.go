package breaker

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestBreaker(t *testing.T, fixedNow time.Time) *Breaker {
	t.Helper()
	dir := t.TempDir()
	b := New(filepath.Join(dir, "circuit.json"))
	b.FailuresBeforeOpen = 3
	b.DefaultCooldown = 30 * time.Second
	b.now = func() time.Time { return fixedNow }
	return b
}

func TestNew_DefaultClosed(t *testing.T) {
	b := newTestBreaker(t, time.Now())
	permitted, _, _ := b.Check()
	if !permitted {
		t.Error("fresh breaker should permit calls")
	}
}

func TestRecordFailure_OpensAfterThreshold(t *testing.T) {
	now := time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)
	b := newTestBreaker(t, now)

	srv := &ServerError{StatusCode: 503, Detail: "overloaded"}
	for i := 0; i < 2; i++ {
		_, err := b.RecordFailure(srv)
		if err != nil {
			t.Fatal(err)
		}
		permitted, _, _ := b.Check()
		if !permitted {
			t.Errorf("after %d failures should still permit", i+1)
		}
	}

	// 3rd failure → opens
	state, err := b.RecordFailure(srv)
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != "open" {
		t.Errorf("Status = %q after 3 failures, want open", state.Status)
	}
	if state.Reason != "server_error" {
		t.Errorf("Reason = %q, want server_error", state.Reason)
	}

	permitted, deadline, reason := b.Check()
	if permitted {
		t.Error("Check should be false right after opening")
	}
	if !deadline.Equal(now.Add(30 * time.Second)) {
		t.Errorf("deadline = %v, want %v", deadline, now.Add(30*time.Second))
	}
	if reason == "" {
		t.Error("reason should be populated")
	}
}

func TestRecordFailure_RateLimitOpensImmediatelyToHeaderDeadline(t *testing.T) {
	now := time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)
	b := newTestBreaker(t, now)

	resetAt := now.Add(15 * time.Minute) // typical Anthropic limit reset
	rl := &RateLimitError{RetryAfter: resetAt, Detail: "usage limit exceeded"}

	state, err := b.RecordFailure(rl)
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != "open" {
		t.Errorf("rate limit should open circuit immediately; got %q", state.Status)
	}
	if !state.OpenUntil.Equal(resetAt) {
		t.Errorf("OpenUntil = %v, want %v (header deadline)", state.OpenUntil, resetAt)
	}
	if state.Reason != "rate_limit" {
		t.Errorf("Reason = %q, want rate_limit", state.Reason)
	}
}

func TestCheck_ReopensAfterDeadline(t *testing.T) {
	start := time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)
	b := newTestBreaker(t, start)

	// Open with rate limit
	_, _ = b.RecordFailure(&RateLimitError{
		RetryAfter: start.Add(5 * time.Minute),
		Detail:     "limit",
	})

	// Still open while we're before the deadline
	permitted, _, _ := b.Check()
	if permitted {
		t.Error("should be blocked before deadline")
	}

	// Advance past the deadline → probe permitted
	b.now = func() time.Time { return start.Add(6 * time.Minute) }
	permitted, _, _ = b.Check()
	if !permitted {
		t.Error("should permit probe after deadline")
	}
}

func TestRecordSuccess_ClosesCircuit(t *testing.T) {
	now := time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)
	b := newTestBreaker(t, now)

	// Open it
	_, _ = b.RecordFailure(&RateLimitError{RetryAfter: now.Add(time.Hour), Detail: "x"})
	if permitted, _, _ := b.Check(); permitted {
		t.Fatal("should be blocked")
	}

	// Successful probe closes it
	if err := b.RecordSuccess(); err != nil {
		t.Fatal(err)
	}
	if permitted, _, _ := b.Check(); !permitted {
		t.Error("should be permitted after success")
	}

	state, _ := b.State()
	if state.ConsecutiveFailures != 0 {
		t.Errorf("ConsecutiveFailures = %d, want 0", state.ConsecutiveFailures)
	}
}

func TestStateFile_NonExistent_IsHealthy(t *testing.T) {
	dir := t.TempDir()
	b := New(filepath.Join(dir, "nope.json"))
	state, err := b.State()
	if err != nil {
		t.Fatal(err)
	}
	if state != nil {
		t.Errorf("nonexistent file should return nil state; got %+v", state)
	}
	if permitted, _, _ := b.Check(); !permitted {
		t.Error("should permit when no state file")
	}
}

func TestStateFile_Corrupt_TreatedAsClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "circuit.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	b := New(path)
	if permitted, _, _ := b.Check(); !permitted {
		t.Error("corrupt file should be treated as closed (permitted)")
	}
}

func TestPersistedAcrossInstances(t *testing.T) {
	now := time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	path := filepath.Join(dir, "circuit.json")

	b1 := New(path)
	b1.now = func() time.Time { return now }
	_, _ = b1.RecordFailure(&RateLimitError{RetryAfter: now.Add(time.Hour), Detail: "x"})

	// New instance reads the same file
	b2 := New(path)
	b2.now = func() time.Time { return now }
	state, err := b2.State()
	if err != nil {
		t.Fatal(err)
	}
	if state == nil || state.Status != "open" {
		t.Errorf("state did not persist: %+v", state)
	}
}
