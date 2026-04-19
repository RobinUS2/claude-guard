package stop

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSession_IncrementAndCap(t *testing.T) {
	dir := t.TempDir()
	sess := newSession("test-session", dir)

	for i := 1; i <= 3; i++ {
		n, ok := sess.increment()
		if !ok {
			t.Fatalf("increment %d: got suppressed, want ok", i)
		}
		if n != i {
			t.Errorf("count=%d, want %d", n, i)
		}
	}

	_, ok := sess.increment()
	if ok {
		t.Error("expected cap to be hit at 3, got ok")
	}
}

func TestSession_FiredRule(t *testing.T) {
	dir := t.TempDir()
	sess := newSession("test-session", dir)
	sess.increment()

	if sess.hasFired("rule-a") {
		t.Error("rule-a should not have fired yet")
	}
	sess.markFired("rule-a", "sha1")
	if !sess.hasFired("rule-a") {
		t.Error("rule-a should be marked fired")
	}
	if sess.shellHashChanged("rule-a", "sha1") {
		t.Error("same hash should not show as changed")
	}
	if !sess.shellHashChanged("rule-a", "sha2") {
		t.Error("different hash should show as changed")
	}
}

func TestSession_EmptySessionID(t *testing.T) {
	dir := t.TempDir()
	sess := newSession("", dir)
	_, ok := sess.increment()
	if !ok {
		t.Error("first increment should succeed")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) == 0 {
		t.Error("expected session file to be created")
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" && len(e.Name()) <= 5 {
			t.Errorf("bad session filename: %s", e.Name())
		}
	}
}
