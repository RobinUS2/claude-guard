package main

import (
	"testing"

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
