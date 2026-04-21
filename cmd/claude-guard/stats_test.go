package main

import (
	"testing"
	"time"

	clog "github.com/RobinUS2/claude-guard/internal/log"
)

func TestAggregateStopHook(t *testing.T) {
	agg := newAggregation()
	agg.addStopHook(&clog.StopHookRecord{
		Msg: clog.MsgStopHook, Injected: true, FiredRule: "uncommitted-changes", ContinueCount: 1,
	})
	agg.addStopHook(&clog.StopHookRecord{
		Msg: clog.MsgStopHook, Injected: false,
	})
	agg.addStopHook(&clog.StopHookRecord{
		Msg: clog.MsgStopHook, Injected: false, Suppressed: "max_continues_reached",
	})

	if agg.stopTotal != 3 {
		t.Errorf("stopTotal=%d, want 3", agg.stopTotal)
	}
	if agg.stopInjected != 1 {
		t.Errorf("stopInjected=%d, want 1", agg.stopInjected)
	}
	if agg.stopCapped != 1 {
		t.Errorf("stopCapped=%d, want 1", agg.stopCapped)
	}
	if agg.stopByRule["uncommitted-changes"] != 1 {
		t.Errorf("stopByRule=%v", agg.stopByRule)
	}
}

func TestAggregateStopHook_Empty(t *testing.T) {
	agg := newAggregation()
	if agg.stopTotal != 0 || agg.stopInjected != 0 {
		t.Error("fresh aggregation should have zero stop counts")
	}
}

func TestComputeTimeSaved(t *testing.T) {
	agg := newAggregation()
	agg.byTier["instant_allow"] = 10
	agg.byTier["cache"] = 5
	agg.byTier["llm"] = 3
	agg.byTier["bq_preflight"] = 2
	agg.byTier["legacy"] = 1
	agg.byTier["default"] = 4 // user-prompted, should not count

	avoided, savedMin := computeTimeSaved(agg)
	wantAvoided := 10 + 5 + 3 + 2 + 1 // 21
	wantMin := wantAvoided * minutesPerInterruptAvoided
	if avoided != wantAvoided {
		t.Errorf("avoided=%d, want %d", avoided, wantAvoided)
	}
	if savedMin != wantMin {
		t.Errorf("savedMin=%d, want %d", savedMin, wantMin)
	}
}

func TestComputeTimeSaved_Empty(t *testing.T) {
	agg := newAggregation()
	avoided, savedMin := computeTimeSaved(agg)
	if avoided != 0 || savedMin != 0 {
		t.Errorf("empty agg: avoided=%d savedMin=%d, want 0 0", avoided, savedMin)
	}
}

// --- Flow metrics tests ---

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{0, "0s"},
		{-5 * time.Second, "0s"},
		{30 * time.Second, "30s"},
		{45 * time.Second, "45s"},
		{1 * time.Minute, "1m 00s"},
		{1*time.Minute + 30*time.Second, "1m 30s"},
		{12*time.Minute + 30*time.Second, "12m 30s"},
		{59*time.Minute + 59*time.Second, "59m 59s"},
		{1 * time.Hour, "1h 00m"},
		{2*time.Hour + 15*time.Minute, "2h 15m"},
		{2*time.Hour + 15*time.Minute + 30*time.Second, "2h 15m"}, // seconds dropped for hours
		{10*time.Hour + 5*time.Minute, "10h 05m"},
	}
	for _, tt := range tests {
		got := formatDuration(tt.d)
		if got != tt.want {
			t.Errorf("formatDuration(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}

func TestComputeStretches_SingleSession(t *testing.T) {
	agg := newAggregation()
	base := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)

	// Session with 3 interrupts at t+5m, t+20m, t+45m.
	// Session runs from t+0 to t+60m.
	sid := "sess-1"
	agg.sessionFirst[sid] = base
	agg.sessionLast[sid] = base.Add(60 * time.Minute)
	agg.interruptTimes[sid] = []time.Time{
		base.Add(5 * time.Minute),
		base.Add(20 * time.Minute),
		base.Add(45 * time.Minute),
	}

	stretches := computeStretches(agg)

	// Expected stretches:
	// start→first: 5m
	// first→second: 15m
	// second→third: 25m
	// third→end: 15m
	if len(stretches) != 4 {
		t.Fatalf("got %d stretches, want 4: %v", len(stretches), stretches)
	}

	expected := []time.Duration{
		5 * time.Minute,
		15 * time.Minute,
		25 * time.Minute,
		15 * time.Minute,
	}
	for i, want := range expected {
		if stretches[i] != want {
			t.Errorf("stretch[%d] = %v, want %v", i, stretches[i], want)
		}
	}
}

func TestComputeStretches_NoInterrupts(t *testing.T) {
	agg := newAggregation()
	base := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)

	// Session with no interrupts, 30m long.
	sid := "sess-clean"
	agg.sessionFirst[sid] = base
	agg.sessionLast[sid] = base.Add(30 * time.Minute)

	stretches := computeStretches(agg)
	if len(stretches) != 1 {
		t.Fatalf("got %d stretches, want 1", len(stretches))
	}
	if stretches[0] != 30*time.Minute {
		t.Errorf("stretch = %v, want 30m", stretches[0])
	}
}

func TestComputeStretches_MultipleSessions(t *testing.T) {
	agg := newAggregation()
	base := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)

	// Session 1: 1 interrupt at t+10m, session spans 0-20m.
	agg.sessionFirst["s1"] = base
	agg.sessionLast["s1"] = base.Add(20 * time.Minute)
	agg.interruptTimes["s1"] = []time.Time{base.Add(10 * time.Minute)}

	// Session 2: no interrupts, 45m long.
	agg.sessionFirst["s2"] = base.Add(1 * time.Hour)
	agg.sessionLast["s2"] = base.Add(1*time.Hour + 45*time.Minute)

	stretches := computeStretches(agg)
	// s1: start→interrupt (10m), interrupt→end (10m) = 2 stretches
	// s2: full session (45m) = 1 stretch
	if len(stretches) != 3 {
		t.Fatalf("got %d stretches, want 3: %v", len(stretches), stretches)
	}
}

func TestComputeStretches_Empty(t *testing.T) {
	agg := newAggregation()
	stretches := computeStretches(agg)
	if len(stretches) != 0 {
		t.Errorf("empty agg: got %d stretches, want 0", len(stretches))
	}
}

func TestPercentileDuration(t *testing.T) {
	durations := []time.Duration{
		1 * time.Minute,
		5 * time.Minute,
		10 * time.Minute,
		20 * time.Minute,
		60 * time.Minute,
	}

	// p50 of 5 sorted values → index 2 → 10m
	if got := percentileDuration(durations, 0.50); got != 10*time.Minute {
		t.Errorf("p50 = %v, want 10m", got)
	}

	// p100 → last → 60m
	if got := percentileDuration(durations, 1.0); got != 60*time.Minute {
		t.Errorf("p100 = %v, want 60m", got)
	}

	// Empty input.
	if got := percentileDuration(nil, 0.50); got != 0 {
		t.Errorf("empty p50 = %v, want 0", got)
	}
}

func TestPercentileDuration_SingleValue(t *testing.T) {
	durations := []time.Duration{42 * time.Second}
	if got := percentileDuration(durations, 0.50); got != 42*time.Second {
		t.Errorf("p50 of single = %v, want 42s", got)
	}
	if got := percentileDuration(durations, 0.95); got != 42*time.Second {
		t.Errorf("p95 of single = %v, want 42s", got)
	}
}

func TestAggregationFlowTracking(t *testing.T) {
	agg := newAggregation()
	base := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)

	// Add some records with session IDs.
	recs := []clog.ReadRecord{
		{Time: base.Format(time.RFC3339Nano), Msg: "decision", SessionID: "s1", Verdict: "allow", Tier: "cache"},
		{Time: base.Add(5 * time.Minute).Format(time.RFC3339Nano), Msg: "decision", SessionID: "s1", Verdict: "continue", Tier: "default"},
		{Time: base.Add(10 * time.Minute).Format(time.RFC3339Nano), Msg: "decision", SessionID: "s1", Verdict: "allow", Tier: "llm"},
		{Time: base.Add(15 * time.Minute).Format(time.RFC3339Nano), Msg: "decision", SessionID: "s1", Verdict: "continue", Tier: "default"},
	}
	for i := range recs {
		agg.add(&recs[i])
	}

	if agg.interruptCount != 2 {
		t.Errorf("interruptCount = %d, want 2", agg.interruptCount)
	}
	if len(agg.interruptTimes["s1"]) != 2 {
		t.Errorf("interruptTimes[s1] len = %d, want 2", len(agg.interruptTimes["s1"]))
	}
	if agg.sessionFirst["s1"] != base {
		t.Errorf("sessionFirst[s1] = %v, want %v", agg.sessionFirst["s1"], base)
	}
	if agg.sessionLast["s1"] != base.Add(15*time.Minute) {
		t.Errorf("sessionLast[s1] = %v, want %v", agg.sessionLast["s1"], base.Add(15*time.Minute))
	}
}

func TestAggregationFlowTracking_NoSessionID(t *testing.T) {
	agg := newAggregation()
	base := time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC)

	// Records without session_id should not populate flow maps.
	rec := clog.ReadRecord{
		Time: base.Format(time.RFC3339Nano), Msg: "decision", Verdict: "continue", Tier: "default",
	}
	agg.add(&rec)

	if agg.interruptCount != 0 {
		t.Errorf("interruptCount = %d, want 0 (no session_id)", agg.interruptCount)
	}
	if len(agg.sessionFirst) != 0 {
		t.Errorf("sessionFirst should be empty, got %d entries", len(agg.sessionFirst))
	}
}
