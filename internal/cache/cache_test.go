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
