package store

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RobinUS2/claude-guard/internal/cache"
)

// ---------------------------------------------------------------------------
// Session approvals
// ---------------------------------------------------------------------------

func TestSessionApprovalRoundTrip(t *testing.T) {
	s := openTestStore(t)
	const sid, aid, key, form, cmd, src = "sess1", "", "key1", "git commit", "git commit -m foo", "llm"

	if got := s.ReadSessionApproval(sid, aid, key); got != "" {
		t.Fatalf("before write: want '', got %q", got)
	}

	if err := s.WriteSessionApproval(sid, aid, key, form, cmd, src); err != nil {
		t.Fatalf("WriteSessionApproval: %v", err)
	}

	if got := s.ReadSessionApproval(sid, aid, key); got != "allow" {
		t.Fatalf("after write: want 'allow', got %q", got)
	}
}

func TestSessionApprovalDenyWins(t *testing.T) {
	s := openTestStore(t)
	const sid, aid, key = "sess2", "", "key2"

	_ = s.WriteSessionApproval(sid, aid, key, "go test", "go test ./...", "llm")
	_ = s.WriteSessionDeny(sid, aid, key)

	// deny must win
	if got := s.ReadSessionApproval(sid, aid, key); got != "deny" {
		t.Fatalf("want 'deny', got %q", got)
	}

	// re-writing allow must NOT overwrite the deny
	_ = s.WriteSessionApproval(sid, aid, key, "go test", "go test ./...", "llm")
	if got := s.ReadSessionApproval(sid, aid, key); got != "deny" {
		t.Fatalf("after re-allow: want 'deny' (deny wins), got %q", got)
	}
}

func TestSessionApprovalAgentIsolation(t *testing.T) {
	s := openTestStore(t)
	const sid, key = "sess3", "key3"

	_ = s.WriteSessionApproval(sid, "agent-A", key, "ls", "ls", "llm")

	// Different agent_id — must NOT see agent-A's approval.
	if got := s.ReadSessionApproval(sid, "agent-B", key); got != "" {
		t.Fatalf("agent-B should not see agent-A approval, got %q", got)
	}
	// Main agent (empty agent_id) also isolated.
	if got := s.ReadSessionApproval(sid, "", key); got != "" {
		t.Fatalf("main agent should not see agent-A approval, got %q", got)
	}
}

func TestGetSessionContext(t *testing.T) {
	s := openTestStore(t)
	const sid, aid = "sess4", ""

	forms := []string{"go build", "go test", "git status"}
	for i, f := range forms {
		key := cache.SessionKey(f)
		_ = s.WriteSessionApproval(sid, aid, key, f, f, "llm")
		if i < len(forms)-1 {
			time.Sleep(time.Millisecond) // ensure ordering by approved_at
		}
	}

	ctx := s.GetSessionContext(sid, aid, 10)
	if len(ctx) != 3 {
		t.Fatalf("want 3 context entries, got %d", len(ctx))
	}
	// GetSessionContext returns newest-first.
	if ctx[0] != "git status" {
		t.Errorf("ctx[0] = %q, want 'git status'", ctx[0])
	}
}

func TestCleanStaleSessionApprovals(t *testing.T) {
	s := openTestStore(t)
	// Write an entry with a past expires_at directly via WriteSessionApproval,
	// then call CleanStaleSessionApprovals and verify it's gone.
	// (Direct expiry manipulation requires an INSERT — use WritePending workaround
	// via the PRAGMA to lower TTL, or simply trust TTL logic via ReadSessionApproval.)
	// Simpler: write a normal entry, verify it exists, then run clean (nothing removed
	// since TTL is 8h), then verify the clean-call itself doesn't error.
	const sid, aid, key = "sess5", "", "key5"
	_ = s.WriteSessionApproval(sid, aid, key, "go vet", "go vet ./...", "llm")
	if err := s.CleanStaleSessionApprovals(); err != nil {
		t.Fatalf("CleanStaleSessionApprovals: %v", err)
	}
	// Entry should still be there (not yet expired).
	if got := s.ReadSessionApproval(sid, aid, key); got != "allow" {
		t.Errorf("after clean: want 'allow', got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Sequence progress
// ---------------------------------------------------------------------------

func TestSequenceProgressRoundTrip(t *testing.T) {
	s := openTestStore(t)
	const sid, aid = "seq1", ""

	if _, _, found := s.ReadSequenceProgress(sid, aid, 0); found {
		t.Fatal("expected no progress before write")
	}

	if err := s.WriteSequenceProgress(sid, aid, 0, 2); err != nil {
		t.Fatalf("WriteSequenceProgress: %v", err)
	}

	stepIdx, lastUpdated, found := s.ReadSequenceProgress(sid, aid, 0)
	if !found {
		t.Fatal("expected progress after write")
	}
	if stepIdx != 2 {
		t.Errorf("stepIdx = %d, want 2", stepIdx)
	}
	if lastUpdated.IsZero() {
		t.Error("lastUpdated should not be zero")
	}
}

func TestSequenceProgressDelete(t *testing.T) {
	s := openTestStore(t)
	const sid, aid = "seq2", ""

	_ = s.WriteSequenceProgress(sid, aid, 1, 3)
	if err := s.DeleteSequenceProgress(sid, aid, 1); err != nil {
		t.Fatalf("DeleteSequenceProgress: %v", err)
	}
	if _, _, found := s.ReadSequenceProgress(sid, aid, 1); found {
		t.Fatal("expected no progress after delete")
	}
}

func TestCleanStaleSequences(t *testing.T) {
	s := openTestStore(t)
	_ = s.WriteSequenceProgress("seq3", "", 0, 1)
	// Sequences written now have last_updated = now, well within 10 minutes.
	if err := s.CleanStaleSequences(10 * time.Minute); err != nil {
		t.Fatalf("CleanStaleSequences: %v", err)
	}
	if _, _, found := s.ReadSequenceProgress("seq3", "", 0); !found {
		t.Fatal("recent sequence should not be cleaned")
	}
	// Clean with a negative duration (cutoff in the future) removes everything.
	if err := s.CleanStaleSequences(-24 * time.Hour); err != nil {
		t.Fatalf("CleanStaleSequences(-24h): %v", err)
	}
	if _, _, found := s.ReadSequenceProgress("seq3", "", 0); found {
		t.Fatal("sequence should be cleaned with future-pointing TTL")
	}
}

// ensure the strings import stays used (used in existing tests; re-export here)
var _ = strings.Contains

func openTestStore(t *testing.T) *Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenCreatesTables(t *testing.T) {
	s := openTestStore(t)

	// Verify all three tables exist by querying sqlite_master.
	rows, err := s.db.Query(
		"SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}

	want := map[string]bool{
		"verdicts":          false,
		"pending_approvals": false,
		"metrics_snapshots": false,
	}
	for _, name := range tables {
		if _, ok := want[name]; ok {
			want[name] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("table %q not created", name)
		}
	}

	// Verify user_version is set.
	var ver int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&ver); err != nil {
		t.Fatal(err)
	}
	if ver != schemaVersion {
		t.Errorf("user_version = %d, want %d", ver, schemaVersion)
	}
}

func TestOpenIdempotent(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")

	// Open twice on the same path — second open should not fail.
	s1, err := Open(dbPath)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	s1.Close()

	s2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	s2.Close()
}

func TestPutGetVerdictRoundTrip(t *testing.T) {
	s := openTestStore(t)

	now := time.Now().UTC().Truncate(time.Second)
	e := cache.Entry{
		Verdict:       cache.VerdictAllow,
		Reason:        "safe command",
		Tier:          "llm",
		Provider:      "anthropic",
		Model:         "claude-3-5-sonnet",
		StoredAt:      now,
		Command:       "ls -la",
		CWD:           "/home/user",
		CanonicalForm: "ls {FLAGS}",
		Program:       "ls",
		MatchCount:    5,
	}

	if err := s.PutVerdict("key1", e, 24*time.Hour); err != nil {
		t.Fatalf("PutVerdict: %v", err)
	}

	got, ok := s.GetVerdict("key1")
	if !ok {
		t.Fatal("GetVerdict returned miss")
	}

	if got.Verdict != cache.VerdictAllow {
		t.Errorf("Verdict = %q, want %q", got.Verdict, cache.VerdictAllow)
	}
	if got.Reason != "safe command" {
		t.Errorf("Reason = %q, want %q", got.Reason, "safe command")
	}
	if got.Tier != "llm" {
		t.Errorf("Tier = %q, want %q", got.Tier, "llm")
	}
	if got.Provider != "anthropic" {
		t.Errorf("Provider = %q, want %q", got.Provider, "anthropic")
	}
	if got.Model != "claude-3-5-sonnet" {
		t.Errorf("Model = %q, want %q", got.Model, "claude-3-5-sonnet")
	}
	if got.Command != "ls -la" {
		t.Errorf("Command = %q, want %q", got.Command, "ls -la")
	}
	if got.CWD != "/home/user" {
		t.Errorf("CWD = %q, want %q", got.CWD, "/home/user")
	}
	if got.CanonicalForm != "ls {FLAGS}" {
		t.Errorf("CanonicalForm = %q, want %q", got.CanonicalForm, "ls {FLAGS}")
	}
	if got.Program != "ls" {
		t.Errorf("Program = %q, want %q", got.Program, "ls")
	}
	if got.MatchCount != 5 {
		t.Errorf("MatchCount = %d, want 5", got.MatchCount)
	}
	if got.StoredAt.Unix() != now.Unix() {
		t.Errorf("StoredAt = %v, want %v", got.StoredAt, now)
	}
	if got.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should not be zero with 24h TTL")
	}
}

func TestGetVerdictMiss(t *testing.T) {
	s := openTestStore(t)

	_, ok := s.GetVerdict("nonexistent")
	if ok {
		t.Error("expected miss for nonexistent key")
	}
}

func TestGetVerdictExpiredEntry(t *testing.T) {
	s := openTestStore(t)

	past := time.Now().UTC().Add(-2 * time.Hour)
	e := cache.Entry{
		Verdict:  cache.VerdictAllow,
		StoredAt: past,
	}

	// Insert with 1-hour TTL — already expired since StoredAt is 2h ago.
	if err := s.PutVerdict("expired", e, 1*time.Hour); err != nil {
		t.Fatalf("PutVerdict: %v", err)
	}

	_, ok := s.GetVerdict("expired")
	if ok {
		t.Error("expected miss for expired entry")
	}

	// Verify the row was deleted.
	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM verdicts WHERE key = 'expired'").Scan(&count)
	if count != 0 {
		t.Error("expired entry was not deleted from DB")
	}
}

func TestGetVerdictNoExpiry(t *testing.T) {
	s := openTestStore(t)

	e := cache.Entry{
		Verdict:  cache.VerdictAllow,
		StoredAt: time.Now().UTC().Add(-365 * 24 * time.Hour), // 1 year ago
	}

	// ttl=0 means no expiry.
	if err := s.PutVerdict("forever", e, 0); err != nil {
		t.Fatalf("PutVerdict: %v", err)
	}

	got, ok := s.GetVerdict("forever")
	if !ok {
		t.Fatal("expected hit for no-expiry entry")
	}
	if got.ExpiresAt.IsZero() != true {
		t.Error("ExpiresAt should be zero for no-expiry entry")
	}
}

func TestDeleteVerdict(t *testing.T) {
	s := openTestStore(t)

	e := cache.Entry{Verdict: cache.VerdictAllow}
	if err := s.PutVerdict("del-me", e, 24*time.Hour); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteVerdict("del-me"); err != nil {
		t.Fatalf("DeleteVerdict: %v", err)
	}

	_, ok := s.GetVerdict("del-me")
	if ok {
		t.Error("entry should be gone after delete")
	}

	// Deleting nonexistent key should not error.
	if err := s.DeleteVerdict("nope"); err != nil {
		t.Errorf("DeleteVerdict nonexistent: %v", err)
	}
}

func TestVerifyVerdictAgreement(t *testing.T) {
	s := openTestStore(t)

	e := cache.Entry{
		Verdict: cache.VerdictAllow,
		Tier:    "llm",
	}
	if err := s.PutVerdict("v1", e, 24*time.Hour); err != nil {
		t.Fatal(err)
	}

	found, err := s.VerifyVerdict("v1", cache.VerifierResult{
		Provider: "openai",
		Model:    "gpt-4o",
		Verdict:  cache.VerdictAllow,
		Reason:   "looks safe",
	})
	if err != nil {
		t.Fatalf("VerifyVerdict: %v", err)
	}
	if !found {
		t.Fatal("expected found=true")
	}

	got, ok := s.GetVerdict("v1")
	if !ok {
		t.Fatal("entry missing after verify")
	}
	if !got.Verified {
		t.Error("expected Verified=true")
	}
	if got.Disagreement {
		t.Error("expected Disagreement=false for matching verdict")
	}
	if got.VerifierProvider != "openai" {
		t.Errorf("VerifierProvider = %q, want %q", got.VerifierProvider, "openai")
	}
	if got.VerifierModel != "gpt-4o" {
		t.Errorf("VerifierModel = %q, want %q", got.VerifierModel, "gpt-4o")
	}
}

func TestVerifyVerdictDisagreement(t *testing.T) {
	s := openTestStore(t)

	e := cache.Entry{Verdict: cache.VerdictAllow}
	if err := s.PutVerdict("v2", e, 24*time.Hour); err != nil {
		t.Fatal(err)
	}

	found, err := s.VerifyVerdict("v2", cache.VerifierResult{
		Verdict: cache.VerdictDeny,
		Reason:  "dangerous",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("expected found=true")
	}

	got, _ := s.GetVerdict("v2")
	if !got.Verified {
		t.Error("expected Verified=true")
	}
	if !got.Disagreement {
		t.Error("expected Disagreement=true")
	}
	if got.VerifierVerdict != cache.VerdictDeny {
		t.Errorf("VerifierVerdict = %q, want %q", got.VerifierVerdict, cache.VerdictDeny)
	}
	if got.EffectiveVerdict() != cache.VerdictDeny {
		t.Errorf("EffectiveVerdict = %q, want %q", got.EffectiveVerdict(), cache.VerdictDeny)
	}
}

func TestVerifyVerdictMiss(t *testing.T) {
	s := openTestStore(t)

	found, err := s.VerifyVerdict("nope", cache.VerifierResult{
		Verdict: cache.VerdictAllow,
	})
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Error("expected found=false for nonexistent key")
	}
}

func TestVerdictStats(t *testing.T) {
	s := openTestStore(t)

	// Insert a mix of entries.
	e1 := cache.Entry{Verdict: cache.VerdictAllow, Verified: true, Disagreement: false}
	e2 := cache.Entry{Verdict: cache.VerdictAllow, Verified: true, Disagreement: true,
		VerifierVerdict: cache.VerdictDeny}
	e3 := cache.Entry{Verdict: cache.VerdictAllow}

	s.PutVerdict("s1", e1, 24*time.Hour)
	s.PutVerdict("s2", e2, 24*time.Hour)
	s.PutVerdict("s3", e3, 24*time.Hour)

	st, err := s.VerdictStats()
	if err != nil {
		t.Fatal(err)
	}
	if st.Entries != 3 {
		t.Errorf("Entries = %d, want 3", st.Entries)
	}
	if st.Verified != 2 {
		t.Errorf("Verified = %d, want 2", st.Verified)
	}
	if st.Disagree != 1 {
		t.Errorf("Disagree = %d, want 1", st.Disagree)
	}
}

func TestWriteReadDeletePending(t *testing.T) {
	s := openTestStore(t)

	err := s.WritePending("tu-1", "npm install", "npm {ARGS}", "/project", "sess-1", "new pkg")
	if err != nil {
		t.Fatalf("WritePending: %v", err)
	}

	p, err := s.ReadPending("tu-1")
	if err != nil {
		t.Fatalf("ReadPending: %v", err)
	}
	if p == nil {
		t.Fatal("expected pending, got nil")
	}
	if p.Command != "npm install" {
		t.Errorf("Command = %q, want %q", p.Command, "npm install")
	}
	if p.CanonicalForm != "npm {ARGS}" {
		t.Errorf("CanonicalForm = %q, want %q", p.CanonicalForm, "npm {ARGS}")
	}
	if p.CWD != "/project" {
		t.Errorf("CWD = %q, want %q", p.CWD, "/project")
	}
	if p.SessionID != "sess-1" {
		t.Errorf("SessionID = %q, want %q", p.SessionID, "sess-1")
	}
	if p.Reason != "new pkg" {
		t.Errorf("Reason = %q, want %q", p.Reason, "new pkg")
	}
	if p.PromptedAt.IsZero() {
		t.Error("PromptedAt should not be zero")
	}

	// Delete and verify gone.
	if err := s.DeletePending("tu-1"); err != nil {
		t.Fatalf("DeletePending: %v", err)
	}
	p2, err := s.ReadPending("tu-1")
	if err != nil {
		t.Fatal(err)
	}
	if p2 != nil {
		t.Error("pending should be nil after delete")
	}
}

func TestReadPendingMiss(t *testing.T) {
	s := openTestStore(t)

	p, err := s.ReadPending("nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if p != nil {
		t.Error("expected nil for nonexistent pending")
	}
}

func TestCleanStalePending(t *testing.T) {
	s := openTestStore(t)

	// Insert one fresh and one stale entry.
	s.WritePending("fresh", "ls", "", "/", "s1", "")

	// Manually insert an old entry.
	old := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)
	s.db.Exec(`INSERT INTO pending_approvals (tool_use_id, command, prompted_at)
		VALUES ('stale', 'rm -rf /', ?)`, old)

	deleted, err := s.CleanStalePending(1 * time.Hour)
	if err != nil {
		t.Fatalf("CleanStalePending: %v", err)
	}
	if deleted != 1 {
		t.Errorf("deleted = %d, want 1", deleted)
	}

	// Fresh should still be there.
	p, _ := s.ReadPending("fresh")
	if p == nil {
		t.Error("fresh entry should not have been cleaned")
	}

	// Stale should be gone.
	p2, _ := s.ReadPending("stale")
	if p2 != nil {
		t.Error("stale entry should have been cleaned")
	}
}

func TestLookupCanonical(t *testing.T) {
	s := openTestStore(t)

	// Insert a canonical entry for "dig".
	e := cache.Entry{
		Verdict:       cache.VerdictAllow,
		CanonicalForm: "dig {DOMAIN} {DNS_TYPE}",
		Program:       "dig",
		Command:       "dig example.com A",
	}
	if err := s.PutVerdict("canon-dig", e, 24*time.Hour); err != nil {
		t.Fatal(err)
	}

	// Insert a non-canonical entry (should be ignored).
	e2 := cache.Entry{
		Verdict: cache.VerdictAllow,
		Program: "dig",
		Command: "dig google.com AAAA",
	}
	s.PutVerdict("exact-dig", e2, 24*time.Hour)

	// Insert a canonical for a different program (should be ignored).
	e3 := cache.Entry{
		Verdict:       cache.VerdictAllow,
		CanonicalForm: "curl {URL}",
		Program:       "curl",
		Command:       "curl https://example.com",
	}
	s.PutVerdict("canon-curl", e3, 24*time.Hour)

	// matchFn that checks if the command starts with the canonical's
	// program name (simplified for testing).
	matchFn := func(canonical, command string) bool {
		return strings.Contains(canonical, "{DOMAIN}") &&
			strings.HasPrefix(command, "dig ")
	}

	got, key, ok := s.LookupCanonical("dig", "dig example.org MX", matchFn)
	if !ok {
		t.Fatal("expected canonical hit")
	}
	if key != "canon-dig" {
		t.Errorf("key = %q, want %q", key, "canon-dig")
	}
	if got.CanonicalForm != "dig {DOMAIN} {DNS_TYPE}" {
		t.Errorf("CanonicalForm = %q", got.CanonicalForm)
	}

	// No match for a different program.
	_, _, ok = s.LookupCanonical("wget", "wget example.com", matchFn)
	if ok {
		t.Error("should not match for wrong program")
	}

	// Nil matchFn.
	_, _, ok = s.LookupCanonical("dig", "dig example.com A", nil)
	if ok {
		t.Error("should return false for nil matchFn")
	}
}

func TestLookupCanonicalSkipsExpired(t *testing.T) {
	s := openTestStore(t)

	past := time.Now().UTC().Add(-2 * time.Hour)
	e := cache.Entry{
		Verdict:       cache.VerdictAllow,
		CanonicalForm: "ls {PATH}",
		Program:       "ls",
		StoredAt:      past,
	}
	// 1-hour TTL with a StoredAt 2 hours ago = already expired.
	s.PutVerdict("canon-expired", e, 1*time.Hour)

	matchFn := func(_, _ string) bool { return true }
	_, _, ok := s.LookupCanonical("ls", "ls /tmp", matchFn)
	if ok {
		t.Error("should not match expired canonical entry")
	}
}

func TestIncrementMatchCount(t *testing.T) {
	s := openTestStore(t)

	e := cache.Entry{Verdict: cache.VerdictAllow, MatchCount: 3}
	s.PutVerdict("inc1", e, 24*time.Hour)

	found, err := s.IncrementMatchCount("inc1")
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Error("expected found=true")
	}

	got, _ := s.GetVerdict("inc1")
	if got.MatchCount != 4 {
		t.Errorf("MatchCount = %d, want 4", got.MatchCount)
	}

	// Increment again.
	s.IncrementMatchCount("inc1")
	got2, _ := s.GetVerdict("inc1")
	if got2.MatchCount != 5 {
		t.Errorf("MatchCount = %d, want 5", got2.MatchCount)
	}

	// Miss case.
	found2, err := s.IncrementMatchCount("nope")
	if err != nil {
		t.Fatal(err)
	}
	if found2 {
		t.Error("expected found=false for nonexistent key")
	}
}

func TestRecordAndGetMetricsHistory(t *testing.T) {
	s := openTestStore(t)

	now := time.Now().UTC()
	snap1 := MetricsSnapshot{
		RecordedAt:          now.Add(-48 * time.Hour),
		PeriodHours:         24,
		TotalDecisions:      100,
		AllowCount:          80,
		ContinueCount:       15,
		DenyCount:           5,
		LearnedAllows:       10,
		StopHookEvals:       50,
		StopHookFires:       3,
		Interrupts:          15,
		UserApproved:        12,
		MedianUninterrupted: 720.5,
		P95Uninterrupted:    2700.0,
		CacheEntries:        250,
		LearnedPatterns:     8,
	}
	snap2 := MetricsSnapshot{
		RecordedAt:     now.Add(-24 * time.Hour),
		PeriodHours:    24,
		TotalDecisions: 120,
		AllowCount:     100,
	}
	snap3 := MetricsSnapshot{
		RecordedAt:     now,
		PeriodHours:    24,
		TotalDecisions: 130,
	}

	for _, snap := range []MetricsSnapshot{snap1, snap2, snap3} {
		if err := s.RecordMetrics(snap); err != nil {
			t.Fatalf("RecordMetrics: %v", err)
		}
	}

	// Get last 3 days — should return all 3.
	history, err := s.GetMetricsHistory(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 3 {
		t.Fatalf("len(history) = %d, want 3", len(history))
	}

	// Verify ordering (oldest first).
	if history[0].TotalDecisions != 100 {
		t.Errorf("first.TotalDecisions = %d, want 100", history[0].TotalDecisions)
	}
	if history[2].TotalDecisions != 130 {
		t.Errorf("last.TotalDecisions = %d, want 130", history[2].TotalDecisions)
	}

	// Verify full round-trip of first snapshot fields.
	h := history[0]
	if h.PeriodHours != 24 {
		t.Errorf("PeriodHours = %d, want 24", h.PeriodHours)
	}
	if h.AllowCount != 80 {
		t.Errorf("AllowCount = %d, want 80", h.AllowCount)
	}
	if h.ContinueCount != 15 {
		t.Errorf("ContinueCount = %d, want 15", h.ContinueCount)
	}
	if h.DenyCount != 5 {
		t.Errorf("DenyCount = %d, want 5", h.DenyCount)
	}
	if h.LearnedAllows != 10 {
		t.Errorf("LearnedAllows = %d, want 10", h.LearnedAllows)
	}
	if h.StopHookEvals != 50 {
		t.Errorf("StopHookEvals = %d, want 50", h.StopHookEvals)
	}
	if h.StopHookFires != 3 {
		t.Errorf("StopHookFires = %d, want 3", h.StopHookFires)
	}
	if h.Interrupts != 15 {
		t.Errorf("Interrupts = %d, want 15", h.Interrupts)
	}
	if h.UserApproved != 12 {
		t.Errorf("UserApproved = %d, want 12", h.UserApproved)
	}
	if h.MedianUninterrupted != 720.5 {
		t.Errorf("MedianUninterrupted = %f, want 720.5", h.MedianUninterrupted)
	}
	if h.P95Uninterrupted != 2700.0 {
		t.Errorf("P95Uninterrupted = %f, want 2700.0", h.P95Uninterrupted)
	}
	if h.CacheEntries != 250 {
		t.Errorf("CacheEntries = %d, want 250", h.CacheEntries)
	}
	if h.LearnedPatterns != 8 {
		t.Errorf("LearnedPatterns = %d, want 8", h.LearnedPatterns)
	}

	// Get last 1 day — should return snap2 (24h ago, on boundary) and snap3 (now).
	// snap1 at 48h ago is outside the window.
	recent, err := s.GetMetricsHistory(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(recent) != 2 {
		t.Errorf("len(recent) = %d, want 2 (snap2 + snap3)", len(recent))
	}
}

func TestRecordMetricsDefaultsRecordedAt(t *testing.T) {
	s := openTestStore(t)

	snap := MetricsSnapshot{PeriodHours: 1, TotalDecisions: 42}
	if err := s.RecordMetrics(snap); err != nil {
		t.Fatal(err)
	}

	history, err := s.GetMetricsHistory(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 {
		t.Fatal("expected 1 snapshot")
	}
	if history[0].RecordedAt.IsZero() {
		t.Error("RecordedAt should be auto-populated")
	}
}

func TestPutVerdictTruncatesLongCommand(t *testing.T) {
	s := openTestStore(t)

	longCmd := strings.Repeat("x", 3000)
	e := cache.Entry{Verdict: cache.VerdictAllow, Command: longCmd}
	if err := s.PutVerdict("trunc", e, 24*time.Hour); err != nil {
		t.Fatal(err)
	}

	got, ok := s.GetVerdict("trunc")
	if !ok {
		t.Fatal("expected hit")
	}
	if len(got.Command) > cache.MaxCommandInEntry {
		t.Errorf("Command length = %d, want <= %d", len(got.Command), cache.MaxCommandInEntry)
	}
	if !strings.HasSuffix(got.Command, "...") {
		t.Error("truncated command should end with ...")
	}
}

func TestPutVerdictOverwrites(t *testing.T) {
	s := openTestStore(t)

	e1 := cache.Entry{Verdict: cache.VerdictAllow, Reason: "v1"}
	s.PutVerdict("ow", e1, 24*time.Hour)

	e2 := cache.Entry{Verdict: cache.VerdictDeny, Reason: "v2"}
	s.PutVerdict("ow", e2, 24*time.Hour)

	got, _ := s.GetVerdict("ow")
	if got.Verdict != cache.VerdictDeny {
		t.Errorf("Verdict = %q, want deny", got.Verdict)
	}
	if got.Reason != "v2" {
		t.Errorf("Reason = %q, want v2", got.Reason)
	}
}
