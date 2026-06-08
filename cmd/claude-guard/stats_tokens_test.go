package main

import (
	"testing"
	"time"

	clog "github.com/RobinUS2/claude-guard/internal/log"
)

func TestTokenStretches_BasicDeltas(t *testing.T) {
	agg := newAggregation()

	base := time.Now()
	records := []clog.ReadRecord{
		{Msg: "decision", Time: base.Add(0).Format(time.RFC3339Nano), SessionID: "s1", Verdict: "allow", SessionTokens: 800},
		{Msg: "decision", Time: base.Add(10 * time.Second).Format(time.RFC3339Nano), SessionID: "s1", Verdict: "allow", SessionTokens: 1600},
		{Msg: "decision", Time: base.Add(20 * time.Second).Format(time.RFC3339Nano), SessionID: "s1", Verdict: "continue", SessionTokens: 3000}, // +3000 from 0
		{Msg: "decision", Time: base.Add(30 * time.Second).Format(time.RFC3339Nano), SessionID: "s1", Verdict: "allow", SessionTokens: 4000},
		{Msg: "decision", Time: base.Add(40 * time.Second).Format(time.RFC3339Nano), SessionID: "s1", Verdict: "continue", SessionTokens: 5500}, // +2500 from 3000
	}
	for i := range records {
		agg.add(&records[i])
	}

	stretches := agg.tokenStretches
	if len(stretches) != 2 {
		t.Fatalf("want 2 stretches, got %d: %v", len(stretches), stretches)
	}
	if stretches[0] != 3000 {
		t.Fatalf("first stretch: want 3000, got %d", stretches[0])
	}
	if stretches[1] != 2500 {
		t.Fatalf("second stretch: want 2500, got %d", stretches[1])
	}
}

func TestTokenStretches_ZeroTokensSkipped(t *testing.T) {
	agg := newAggregation()

	base := time.Now()
	records := []clog.ReadRecord{
		// Old-format records with no session_tokens — must not produce a stretch.
		{Msg: "decision", Time: base.Format(time.RFC3339Nano), SessionID: "s1", Verdict: "continue", SessionTokens: 0},
		{Msg: "decision", Time: base.Add(10 * time.Second).Format(time.RFC3339Nano), SessionID: "s1", Verdict: "continue", SessionTokens: 0},
	}
	for i := range records {
		agg.add(&records[i])
	}

	if len(agg.tokenStretches) != 0 {
		t.Fatalf("want 0 token stretches for zero-token records, got %d", len(agg.tokenStretches))
	}
}

func TestTokenStretches_MultiSession(t *testing.T) {
	agg := newAggregation()

	base := time.Now()
	records := []clog.ReadRecord{
		{Msg: "decision", Time: base.Format(time.RFC3339Nano), SessionID: "s1", Verdict: "continue", SessionTokens: 1000},
		{Msg: "decision", Time: base.Add(5 * time.Second).Format(time.RFC3339Nano), SessionID: "s2", Verdict: "continue", SessionTokens: 2000},
		{Msg: "decision", Time: base.Add(10 * time.Second).Format(time.RFC3339Nano), SessionID: "s1", Verdict: "continue", SessionTokens: 4000},
	}
	for i := range records {
		agg.add(&records[i])
	}

	// s1: 1000 (first interrupt), then 4000-1000=3000 (second)
	// s2: 2000 (first interrupt)
	if len(agg.tokenStretches) != 3 {
		t.Fatalf("want 3 stretches, got %d: %v", len(agg.tokenStretches), agg.tokenStretches)
	}
	var has1000, has2000, has3000 bool
	for _, s := range agg.tokenStretches {
		switch s {
		case 1000:
			has1000 = true
		case 2000:
			has2000 = true
		case 3000:
			has3000 = true
		}
	}
	if !has1000 || !has2000 || !has3000 {
		t.Fatalf("want stretches [1000, 2000, 3000] in any order, got %v", agg.tokenStretches)
	}
}
