package lock

import (
	"context"
	"testing"
	"time"
)

func TestCachingChecker_CachesWithinTTL(t *testing.T) {
	inner := &fakeChecker{info: &Info{Who: "someone"}}
	c := &CachingChecker{Inner: inner, TTL: time.Minute}

	if _, err := c.Status(context.Background(), "owner/repo", "prod"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := c.Status(context.Background(), "owner/repo", "prod"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(inner.calls) != 1 {
		t.Errorf("expected 1 underlying call within TTL, got %d", len(inner.calls))
	}
}

func TestCachingChecker_ExpiresAfterTTL(t *testing.T) {
	inner := &fakeChecker{info: &Info{Who: "someone"}}
	c := &CachingChecker{Inner: inner, TTL: 10 * time.Millisecond}

	if _, err := c.Status(context.Background(), "owner/repo", "prod"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := c.Status(context.Background(), "owner/repo", "prod"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(inner.calls) != 2 {
		t.Errorf("expected 2 underlying calls after TTL expiry, got %d", len(inner.calls))
	}
}

func TestCachingChecker_SeparatesByRepoAndEnv(t *testing.T) {
	inner := &fakeChecker{info: &Info{Who: "someone"}}
	c := &CachingChecker{Inner: inner, TTL: time.Minute}

	if _, err := c.Status(context.Background(), "owner/repo", "prod"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := c.Status(context.Background(), "owner/repo", "staging"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := c.Status(context.Background(), "other/repo", "prod"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(inner.calls) != 3 {
		t.Errorf("expected 3 distinct cache keys to each hit the underlying checker, got %d", len(inner.calls))
	}
}

func TestParseBody(t *testing.T) {
	body := "who: Robin Verlangen <robin@taufinity.io>\nhost: mac.home\nagent: claude-code\ntask: docs/release-lock-design\nreason: WVS meeting release"
	info := parseBody(body)
	if info.Who != "Robin Verlangen <robin@taufinity.io>" {
		t.Errorf("who = %q", info.Who)
	}
	if info.Host != "mac.home" {
		t.Errorf("host = %q", info.Host)
	}
	if info.Agent != "claude-code" {
		t.Errorf("agent = %q", info.Agent)
	}
	if info.Task != "docs/release-lock-design" {
		t.Errorf("task = %q", info.Task)
	}
	if info.Reason != "WVS meeting release" {
		t.Errorf("reason = %q", info.Reason)
	}
}
