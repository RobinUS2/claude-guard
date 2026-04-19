package budget

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheck_UnderBudget(t *testing.T) {
	dir := t.TempDir()
	b := New(dir, 500, 50)
	if !b.Check(false) {
		t.Fatal("fresh budget should allow LLM calls")
	}
	if !b.Check(true) {
		t.Fatal("fresh budget should allow file-analysis calls")
	}
}

func TestRecord_IncrementsCounters(t *testing.T) {
	dir := t.TempDir()
	b := New(dir, 500, 50)

	b.Record(false) // LLM-only
	b.Record(true)  // LLM + file

	s := b.Status()
	if s.LLMUsed != 2 {
		t.Errorf("LLMUsed = %d, want 2", s.LLMUsed)
	}
	if s.FileUsed != 1 {
		t.Errorf("FileUsed = %d, want 1", s.FileUsed)
	}
}

func TestCheck_GlobalBudgetExhausted(t *testing.T) {
	dir := t.TempDir()
	b := New(dir, 3, 50) // 3 LLM calls max

	b.Record(false)
	b.Record(false)
	b.Record(false)

	if b.Check(false) {
		t.Fatal("should reject when global LLM budget exhausted")
	}
	// File analysis also rejected because it consumes a global call too.
	if b.Check(true) {
		t.Fatal("file-analysis should also reject when global budget exhausted")
	}
}

func TestCheck_FileBudgetExhausted_LLMStillAllowed(t *testing.T) {
	dir := t.TempDir()
	b := New(dir, 500, 2) // 2 file-analysis calls max

	b.Record(true)
	b.Record(true)

	if b.Check(true) {
		t.Fatal("should reject file-analysis when file budget exhausted")
	}
	if !b.Check(false) {
		t.Fatal("plain LLM should still be allowed when only file budget is exhausted")
	}
}

func TestDateRollover(t *testing.T) {
	dir := t.TempDir()
	b := New(dir, 500, 50)

	// Record some usage.
	b.Record(false)
	b.Record(true)

	// Simulate a date rollover by writing a stale date into the file.
	path := filepath.Join(dir, budgetFileName)
	data := []byte(`{"date":"2020-01-01","llm_calls":499,"file_analysis_calls":49}`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	// Re-create budget to force file re-read.
	b2 := New(dir, 500, 50)
	s := b2.Status()
	if s.LLMUsed != 0 {
		t.Errorf("after date rollover LLMUsed = %d, want 0", s.LLMUsed)
	}
	if s.FileUsed != 0 {
		t.Errorf("after date rollover FileUsed = %d, want 0", s.FileUsed)
	}
}

func TestStatus_ReturnsLimits(t *testing.T) {
	dir := t.TempDir()
	b := New(dir, 500, 50)
	s := b.Status()
	if s.LLMLimit != 500 {
		t.Errorf("LLMLimit = %d, want 500", s.LLMLimit)
	}
	if s.FileLimit != 50 {
		t.Errorf("FileLimit = %d, want 50", s.FileLimit)
	}
}

func TestPersistence_AcrossInstances(t *testing.T) {
	dir := t.TempDir()
	b1 := New(dir, 500, 50)
	b1.Record(false)
	b1.Record(true)

	// New instance reads from same file.
	b2 := New(dir, 500, 50)
	s := b2.Status()
	if s.LLMUsed != 2 {
		t.Errorf("LLMUsed = %d, want 2 (persisted)", s.LLMUsed)
	}
	if s.FileUsed != 1 {
		t.Errorf("FileUsed = %d, want 1 (persisted)", s.FileUsed)
	}
}
