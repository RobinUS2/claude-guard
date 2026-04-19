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
