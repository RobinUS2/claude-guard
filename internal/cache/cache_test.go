package cache

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func newTestCache(t *testing.T, fixedNow time.Time) *Cache {
	t.Helper()
	dir := t.TempDir()
	c := New(filepath.Join(dir, "cache"))
	c.now = func() time.Time { return fixedNow }
	return c
}

func TestKey_Deterministic(t *testing.T) {
	in := KeyInputs{Tool: "Bash", Command: "git status", CWD: "/tmp"}
	a := Key(in)
	b := Key(in)
	if a != b {
		t.Errorf("Key not deterministic: %s vs %s", a, b)
	}
	if len(a) != 64 {
		t.Errorf("Key length = %d, want 64 hex chars", len(a))
	}
}

func TestKey_DifferentCommandsDifferentKeys(t *testing.T) {
	a := Key(KeyInputs{Command: "git status"})
	b := Key(KeyInputs{Command: "git log"})
	if a == b {
		t.Errorf("different commands should hash differently")
	}
}

func TestKey_CWDChangesKey(t *testing.T) {
	a := Key(KeyInputs{Command: "rm -rf node_modules", CWD: "/tmp/scoped"})
	b := Key(KeyInputs{Command: "rm -rf node_modules", CWD: "/Users/robin/code/prod"})
	if a == b {
		t.Errorf("same command in different cwd should hash differently")
	}
}

func TestKey_BranchChangesKey(t *testing.T) {
	a := Key(KeyInputs{Command: "git push origin main", GitBranch: "feature-x"})
	b := Key(KeyInputs{Command: "git push origin main", GitBranch: "main"})
	if a == b {
		t.Errorf("branch should change the key")
	}
}

func TestKey_PromptVersionChangesKey(t *testing.T) {
	a := Key(KeyInputs{Command: "ls", PromptVersion: "v1"})
	b := Key(KeyInputs{Command: "ls", PromptVersion: "v2"})
	if a == b {
		t.Errorf("prompt version should change the key")
	}
}

func TestPutGet(t *testing.T) {
	now := time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)
	c := newTestCache(t, now)

	key := Key(KeyInputs{Tool: "Bash", Command: "git status"})
	want := Entry{
		Verdict: VerdictAllow,
		Reason:  "git status is read-only",
		Tier:    "llm",
	}
	if err := c.Put(key, want, time.Hour); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, ok := c.Get(key)
	if !ok {
		t.Fatal("Get miss after Put")
	}
	if got.Verdict != VerdictAllow {
		t.Errorf("Verdict = %q", got.Verdict)
	}
	if got.Reason != want.Reason {
		t.Errorf("Reason = %q", got.Reason)
	}
	if got.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should be populated for ttl > 0")
	}
}

func TestGet_NeverExpires(t *testing.T) {
	now := time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)
	c := newTestCache(t, now)
	key := Key(KeyInputs{Command: "ls"})
	_ = c.Put(key, Entry{Verdict: VerdictAllow}, 0)

	c.now = func() time.Time { return now.Add(10 * 365 * 24 * time.Hour) }
	if _, ok := c.Get(key); !ok {
		t.Error("ttl=0 entries should never expire")
	}
}

func TestGet_ExpiredEvicted(t *testing.T) {
	now := time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)
	c := newTestCache(t, now)
	key := Key(KeyInputs{Command: "ls"})
	_ = c.Put(key, Entry{Verdict: VerdictAllow}, time.Minute)

	// Advance past expiry.
	c.now = func() time.Time { return now.Add(2 * time.Minute) }
	if _, ok := c.Get(key); ok {
		t.Error("expired entry should report miss")
	}
	// And the file should be gone.
	if _, err := os.Stat(c.path(key)); !os.IsNotExist(err) {
		t.Error("expired entry should be deleted on read")
	}
}

func TestGet_MissOnFreshCache(t *testing.T) {
	c := newTestCache(t, time.Now())
	if _, ok := c.Get("nope"); ok {
		t.Error("fresh cache should miss")
	}
}

func TestGet_CorruptFileEvicted(t *testing.T) {
	c := newTestCache(t, time.Now())
	key := "deadbeef"
	path := c.path(key)
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	_ = os.WriteFile(path, []byte("{not json"), 0o644)

	if _, ok := c.Get(key); ok {
		t.Error("corrupt entry should report miss")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("corrupt entry should be deleted")
	}
}

func TestPut_AtomicWrite(t *testing.T) {
	c := newTestCache(t, time.Now())
	key := Key(KeyInputs{Command: "ls"})
	if err := c.Put(key, Entry{Verdict: VerdictAllow}, time.Hour); err != nil {
		t.Fatal(err)
	}
	// No leftover .tmp file
	tmp := c.path(key) + ".tmp"
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Errorf("leftover tmp file: %s", tmp)
	}
}

func TestConcurrentPuts(t *testing.T) {
	c := newTestCache(t, time.Now())
	key := Key(KeyInputs{Command: "git status"})

	const writers = 10
	var wg sync.WaitGroup
	wg.Add(writers)
	for i := 0; i < writers; i++ {
		go func() {
			defer wg.Done()
			_ = c.Put(key, Entry{Verdict: VerdictAllow}, time.Hour)
		}()
	}
	wg.Wait()

	if _, ok := c.Get(key); !ok {
		t.Error("Get miss after concurrent Put")
	}
}

func TestSharding(t *testing.T) {
	c := newTestCache(t, time.Now())
	key := "ab1234567890abcdef"
	expected := filepath.Join(c.Dir, "ab", key+".json")
	if c.path(key) != expected {
		t.Errorf("path = %q, want %q", c.path(key), expected)
	}
}

func TestStats(t *testing.T) {
	now := time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)
	c := newTestCache(t, now)

	for i, cmd := range []string{"a", "b", "c", "d", "e"} {
		key := Key(KeyInputs{Command: cmd})
		ttl := time.Hour
		if i == 4 {
			ttl = 1 * time.Nanosecond // immediately expired by the time stats walks
		}
		_ = c.Put(key, Entry{Verdict: VerdictAllow}, ttl)
	}

	// Advance time slightly so the 1ns TTL entry is expired.
	c.now = func() time.Time { return now.Add(time.Second) }

	s, err := c.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if s.Entries != 5 {
		t.Errorf("Entries = %d, want 5", s.Entries)
	}
	if s.ExpiredHits < 1 {
		t.Errorf("ExpiredHits = %d, want >= 1", s.ExpiredHits)
	}
	if s.BytesOnDisk == 0 {
		t.Error("BytesOnDisk should be > 0")
	}
}

func TestSweep_RemovesExpired(t *testing.T) {
	now := time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)
	c := newTestCache(t, now)

	// 3 entries: 2 expired, 1 fresh
	keys := []string{Key(KeyInputs{Command: "a"}), Key(KeyInputs{Command: "b"}), Key(KeyInputs{Command: "c"})}
	for _, k := range keys[:2] {
		_ = c.Put(k, Entry{Verdict: VerdictAllow}, time.Nanosecond)
	}
	_ = c.Put(keys[2], Entry{Verdict: VerdictAllow}, time.Hour)

	c.now = func() time.Time { return now.Add(time.Second) }
	deleted, err := c.Sweep()
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 2 {
		t.Errorf("deleted = %d, want 2", deleted)
	}
	// Fresh entry survives
	if _, ok := c.Get(keys[2]); !ok {
		t.Error("fresh entry was wrongly deleted")
	}
}

func TestHashStrings_OrderIndependent(t *testing.T) {
	a := HashStrings([]string{"a", "b", "c"})
	b := HashStrings([]string{"c", "a", "b"})
	if a != b {
		t.Errorf("HashStrings should be order-independent")
	}
}

// --- Verifier ---

func TestVerify_AgreementMarksVerified(t *testing.T) {
	now := time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)
	c := newTestCache(t, now)
	key := Key(KeyInputs{Command: "git status"})
	_ = c.Put(key, Entry{Verdict: VerdictAllow, Reason: "fast: read-only"}, time.Hour)

	updated, err := c.Verify(key, VerifierResult{
		Provider: "anthropic",
		Model:    "claude-sonnet-4-5",
		Verdict:  VerdictAllow,
		Reason:   "verifier: confirmed read-only",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !updated {
		t.Fatal("Verify should report hit")
	}

	got, ok := c.Get(key)
	if !ok {
		t.Fatal("entry missing after verify")
	}
	if !got.Verified {
		t.Error("Verified should be true")
	}
	if got.Disagreement {
		t.Error("Disagreement should be false on agreement")
	}
	if got.VerifierProvider != "anthropic" {
		t.Errorf("VerifierProvider = %q", got.VerifierProvider)
	}
	if got.EffectiveVerdict() != VerdictAllow {
		t.Errorf("EffectiveVerdict = %q, want allow", got.EffectiveVerdict())
	}
}

func TestVerify_DisagreementFlipsEffectiveVerdict(t *testing.T) {
	now := time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)
	c := newTestCache(t, now)
	key := Key(KeyInputs{Command: "rm -rf node_modules"})
	_ = c.Put(key, Entry{Verdict: VerdictAllow, Reason: "fast: scoped to worktree"}, time.Hour)

	_, err := c.Verify(key, VerifierResult{
		Provider: "anthropic",
		Model:    "claude-sonnet-4-5",
		Verdict:  VerdictDeny,
		Reason:   "verifier: actually targets a system path",
	})
	if err != nil {
		t.Fatal(err)
	}

	got, _ := c.Get(key)
	if !got.Disagreement {
		t.Error("Disagreement should be true")
	}
	if got.EffectiveVerdict() != VerdictDeny {
		t.Errorf("EffectiveVerdict = %q, want deny (verifier's verdict wins)", got.EffectiveVerdict())
	}
	// Original verdict is preserved for audit
	if got.Verdict != VerdictAllow {
		t.Errorf("original Verdict should be preserved as allow; got %q", got.Verdict)
	}
}

func TestVerify_MissOnUnknownKey(t *testing.T) {
	c := newTestCache(t, time.Now())
	updated, err := c.Verify("nonexistent", VerifierResult{Verdict: VerdictAllow})
	if err != nil {
		t.Fatal(err)
	}
	if updated {
		t.Error("Verify should report miss on unknown key")
	}
}

func TestVerify_PreservesExpiry(t *testing.T) {
	now := time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)
	c := newTestCache(t, now)
	key := Key(KeyInputs{Command: "ls"})
	_ = c.Put(key, Entry{Verdict: VerdictAllow}, time.Hour)
	original, _ := c.Get(key)

	c.now = func() time.Time { return now.Add(10 * time.Minute) }
	_, _ = c.Verify(key, VerifierResult{Verdict: VerdictAllow})

	updated, _ := c.Get(key)
	if !updated.ExpiresAt.Equal(original.ExpiresAt) {
		t.Errorf("ExpiresAt changed: %v -> %v", original.ExpiresAt, updated.ExpiresAt)
	}
}

func TestEffectiveVerdict_NoDisagreement(t *testing.T) {
	e := &Entry{
		Verdict:         VerdictAllow,
		Verified:        true,
		VerifierVerdict: VerdictAllow,
		Disagreement:    false,
	}
	if e.EffectiveVerdict() != VerdictAllow {
		t.Errorf("EffectiveVerdict = %q", e.EffectiveVerdict())
	}
}

func TestEffectiveVerdict_UnverifiedReturnsOriginal(t *testing.T) {
	e := &Entry{Verdict: VerdictAllow, Verified: false}
	if e.EffectiveVerdict() != VerdictAllow {
		t.Errorf("EffectiveVerdict = %q", e.EffectiveVerdict())
	}
}

// --- Canonical lookup & MatchCount ---

func TestLookupCanonical_Hit(t *testing.T) {
	now := time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)
	c := newTestCache(t, now)
	canonKey := Key(KeyInputs{Command: "dig {DOMAIN} {DNS_TYPE}"})
	_ = c.Put(canonKey, Entry{
		Verdict:       VerdictAllow,
		Reason:        "llm: read-only DNS lookup",
		Tier:          "llm",
		Program:       "dig",
		CanonicalForm: "dig {DOMAIN} {DNS_TYPE}",
		MatchCount:    1,
	}, 90*24*time.Hour)

	matchFn := func(canonical, command string) bool {
		return canonical == "dig {DOMAIN} {DNS_TYPE}" && command == "dig example.com A"
	}
	entry, hitKey, hit := c.LookupCanonical("dig", "dig example.com A", matchFn)
	if !hit {
		t.Fatal("expected canonical hit")
	}
	if entry.CanonicalForm != "dig {DOMAIN} {DNS_TYPE}" {
		t.Errorf("CanonicalForm = %q", entry.CanonicalForm)
	}
	if hitKey == "" {
		t.Error("hitKey should be populated for MatchCount increment")
	}
}

// M3: When an exact-cache entry has expired, a subsequent lookup for
// the same command must still find the canonical sibling entry (which
// carries a longer TTL). Protects the behavior that the engine's Tier 3
// exact-miss path immediately falls through to canonical lookup.
func TestLookupCanonical_FindsEntry_WhenExactExpired(t *testing.T) {
	now := time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)
	c := newTestCache(t, now)

	exactKey := Key(KeyInputs{Command: "dig example.com A"})
	canonKey := Key(KeyInputs{Command: "dig {DOMAIN} {DNS_TYPE}"})

	// Exact: short TTL (simulates default safety horizon already passed).
	_ = c.Put(exactKey, Entry{
		Verdict: VerdictAllow,
		Reason:  "fast exact",
		Tier:    "llm",
		Command: "dig example.com A",
	}, time.Minute)

	// Canonical sibling: long TTL (90d is production default).
	_ = c.Put(canonKey, Entry{
		Verdict:       VerdictAllow,
		Reason:        "llm: read-only DNS lookup",
		Tier:          "llm",
		Program:       "dig",
		CanonicalForm: "dig {DOMAIN} {DNS_TYPE}",
		MatchCount:    1,
	}, 90*24*time.Hour)

	// Advance past the exact-TTL horizon.
	c.now = func() time.Time { return now.Add(2 * time.Minute) }

	// Exact is gone.
	if _, ok := c.Get(exactKey); ok {
		t.Fatal("expected exact entry to be evicted by TTL")
	}

	// Canonical still resolves — this is the fall-through that keeps
	// cache amplification working after the short exact TTL lapses.
	matchFn := func(canonical, command string) bool {
		return canonical == "dig {DOMAIN} {DNS_TYPE}" && command == "dig example.com A"
	}
	entry, hitKey, hit := c.LookupCanonical("dig", "dig example.com A", matchFn)
	if !hit {
		t.Fatal("canonical lookup must still succeed after exact TTL expiry")
	}
	if entry.CanonicalForm != "dig {DOMAIN} {DNS_TYPE}" {
		t.Errorf("CanonicalForm = %q", entry.CanonicalForm)
	}
	if hitKey == "" {
		t.Error("hitKey should be populated so the engine can bump MatchCount")
	}
}

// M3-companion: When BOTH exact and canonical have expired, the
// canonical lookup must miss. Otherwise a stale canonical could keep
// serving allow verdicts past its intended horizon.
func TestLookupCanonical_MissesWhenCanonicalExpired(t *testing.T) {
	now := time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)
	c := newTestCache(t, now)

	canonKey := Key(KeyInputs{Command: "dig {DOMAIN} {DNS_TYPE}"})
	_ = c.Put(canonKey, Entry{
		Verdict:       VerdictAllow,
		Program:       "dig",
		CanonicalForm: "dig {DOMAIN} {DNS_TYPE}",
	}, time.Minute)

	c.now = func() time.Time { return now.Add(2 * time.Minute) }

	matchFn := func(canonical, command string) bool { return true }
	if _, _, hit := c.LookupCanonical("dig", "dig example.com A", matchFn); hit {
		t.Error("expired canonical must not return a hit")
	}
}

func TestIncrementMatchCount_BumpsOnHit(t *testing.T) {
	now := time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)
	c := newTestCache(t, now)
	key := Key(KeyInputs{Command: "dig {DOMAIN} A"})
	_ = c.Put(key, Entry{
		Verdict:       VerdictAllow,
		Program:       "dig",
		CanonicalForm: "dig {DOMAIN} A",
		MatchCount:    3,
	}, time.Hour)

	originalExpiry := func() time.Time {
		e, _ := c.Get(key)
		return e.ExpiresAt
	}()

	updated, err := c.IncrementMatchCount(key)
	if err != nil {
		t.Fatal(err)
	}
	if !updated {
		t.Fatal("expected hit")
	}
	got, _ := c.Get(key)
	if got.MatchCount != 4 {
		t.Errorf("MatchCount = %d, want 4", got.MatchCount)
	}
	// TTL must be preserved — M1 telemetry must not extend entry life.
	if !got.ExpiresAt.Equal(originalExpiry) {
		t.Errorf("ExpiresAt changed: %v -> %v", originalExpiry, got.ExpiresAt)
	}
}

func TestIncrementMatchCount_MissOnUnknownKey(t *testing.T) {
	c := newTestCache(t, time.Now())
	updated, err := c.IncrementMatchCount("nope")
	if err != nil {
		t.Fatal(err)
	}
	if updated {
		t.Error("expected miss on unknown key")
	}
}
