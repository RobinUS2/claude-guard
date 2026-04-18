package budget

import (
	"os"
	"testing"
)

func TestBQBudget_CheckAndRecord(t *testing.T) {
	dir := t.TempDir()
	b := NewBQ(dir, 100)

	// First two recordings within budget.
	ok, used, limit := b.CheckAndRecord(30)
	if !ok || used != 30 || limit != 100 {
		t.Errorf("first record: ok=%v used=%d limit=%d", ok, used, limit)
	}
	ok, used, limit = b.CheckAndRecord(40)
	if !ok || used != 70 || limit != 100 {
		t.Errorf("second record: ok=%v used=%d limit=%d", ok, used, limit)
	}

	// Third would exceed budget (70+40=110 > 100).
	ok, used, limit = b.CheckAndRecord(40)
	if ok || used != 70 || limit != 100 {
		t.Errorf("over-budget: ok=%v used=%d limit=%d", ok, used, limit)
	}

	// Fourth within remaining budget (70+20=90 ≤ 100).
	ok, used, limit = b.CheckAndRecord(20)
	if !ok || used != 90 || limit != 100 {
		t.Errorf("fourth record: ok=%v used=%d limit=%d", ok, used, limit)
	}
}

func TestBQBudget_Status(t *testing.T) {
	dir := t.TempDir()
	b := NewBQ(dir, 1000)

	used, limit := b.Status()
	if used != 0 || limit != 1000 {
		t.Errorf("initial status: used=%d limit=%d", used, limit)
	}

	b.CheckAndRecord(500) //nolint
	used, limit = b.Status()
	if used != 500 || limit != 1000 {
		t.Errorf("after record: used=%d limit=%d", used, limit)
	}
}

func TestBQBudget_CorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/bq-daily.json"
	if err := os.WriteFile(path, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	b := NewBQ(dir, 100)
	ok, _, _ := b.CheckAndRecord(10)
	if !ok {
		t.Error("should fail-open on corrupt file")
	}
}

func TestBQBudget_MissingDir(t *testing.T) {
	b := NewBQ("/tmp/claude-guard-test-nonexistent-dir", 100)
	ok, _, _ := b.CheckAndRecord(10)
	if !ok {
		t.Error("should fail-open when dir doesn't exist yet (creates it)")
	}
}
