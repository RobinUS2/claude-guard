package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RobinUS2/claude-guard/internal/cache"
)

// seedTestCache writes N entries to a temp cache dir and returns the dir.
func seedTestCache(t *testing.T, entries []cache.Entry) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "verdicts")
	c := cache.New(dir)
	for i, e := range entries {
		key := cache.Key(cache.KeyInputs{
			Tool:    "Bash",
			Command: e.Command,
			CWD:     e.CWD,
		})
		ttl := 24 * time.Hour
		if !e.ExpiresAt.IsZero() {
			ttl = e.ExpiresAt.Sub(e.StoredAt)
		}
		if err := c.Put(key, e, ttl); err != nil {
			t.Fatalf("seed entry %d: %v", i, err)
		}
	}
	return dir
}

func TestCacheInspect_ShowsAllEntries(t *testing.T) {
	dir := seedTestCache(t, []cache.Entry{
		{
			Command:  "git status",
			Verdict:  cache.VerdictAllow,
			Tier:     "llm",
			Reason:   "read-only",
			Provider: "anthropic",
			Model:    "haiku",
			StoredAt: time.Now().Add(-1 * time.Hour),
		},
		{
			Command:  "curl -X PATCH https://api.example.com",
			Verdict:  cache.VerdictAllow,
			Tier:     "llm",
			Reason:   "external write",
			Provider: "anthropic",
			Model:    "haiku",
			StoredAt: time.Now().Add(-30 * time.Minute),
		},
	})

	// Override the cache dir.
	origFn := cacheDirFn
	cacheDirFn = func() string { return dir }
	defer func() { cacheDirFn = origFn }()

	code := cacheInspectCmd([]string{})
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
}

func TestCacheInspect_MatchFilter(t *testing.T) {
	dir := seedTestCache(t, []cache.Entry{
		{
			Command:  "git status",
			Verdict:  cache.VerdictAllow,
			Tier:     "llm",
			Provider: "anthropic",
			Model:    "haiku",
			StoredAt: time.Now().Add(-1 * time.Hour),
		},
		{
			Command:  "curl -X PATCH https://api.example.com",
			Verdict:  cache.VerdictAllow,
			Tier:     "llm",
			Provider: "anthropic",
			Model:    "haiku",
			StoredAt: time.Now().Add(-30 * time.Minute),
		},
	})

	origFn := cacheDirFn
	cacheDirFn = func() string { return dir }
	defer func() { cacheDirFn = origFn }()

	code := cacheInspectCmd([]string{"--match", "curl", "--json"})
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
}

func TestCacheInspect_DisagreementsFilter(t *testing.T) {
	dir := seedTestCache(t, []cache.Entry{
		{
			Command:         "git status",
			Verdict:         cache.VerdictAllow,
			Tier:            "llm",
			Provider:        "anthropic",
			Model:           "haiku",
			StoredAt:        time.Now().Add(-1 * time.Hour),
			Verified:        true,
			VerifiedAt:      time.Now().Add(-50 * time.Minute),
			VerifierVerdict: cache.VerdictAllow,
		},
		{
			Command:         "curl -X DELETE https://api.example.com/resource",
			Verdict:         cache.VerdictAllow,
			Tier:            "llm",
			Provider:        "anthropic",
			Model:           "haiku",
			StoredAt:        time.Now().Add(-30 * time.Minute),
			Verified:        true,
			VerifiedAt:      time.Now().Add(-20 * time.Minute),
			VerifierVerdict: cache.VerdictDeny,
			VerifierReason:  "destructive external API call",
			Disagreement:    true,
		},
	})

	origFn := cacheDirFn
	cacheDirFn = func() string { return dir }
	defer func() { cacheDirFn = origFn }()

	code := cacheInspectCmd([]string{"--disagreements"})
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
}

func TestCacheInspect_UnverifiedFilter(t *testing.T) {
	dir := seedTestCache(t, []cache.Entry{
		{
			Command:  "npm run build",
			Verdict:  cache.VerdictAllow,
			Tier:     "llm",
			Provider: "anthropic",
			Model:    "haiku",
			StoredAt: time.Now().Add(-1 * time.Hour),
			Verified: true,
		},
		{
			Command:  "make test",
			Verdict:  cache.VerdictAllow,
			Tier:     "llm",
			Provider: "anthropic",
			Model:    "haiku",
			StoredAt: time.Now().Add(-30 * time.Minute),
			Verified: false,
		},
	})

	origFn := cacheDirFn
	cacheDirFn = func() string { return dir }
	defer func() { cacheDirFn = origFn }()

	code := cacheInspectCmd([]string{"--unverified"})
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
}

func TestCacheInspect_JSONOutput(t *testing.T) {
	dir := seedTestCache(t, []cache.Entry{
		{
			Command:  "git log",
			Verdict:  cache.VerdictAllow,
			Tier:     "llm",
			Provider: "anthropic",
			Model:    "haiku",
			StoredAt: time.Now().Add(-1 * time.Hour),
		},
	})

	origFn := cacheDirFn
	cacheDirFn = func() string { return dir }
	defer func() { cacheDirFn = origFn }()

	// Capture stdout.
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	code := cacheInspectCmd([]string{"--json"})

	w.Close()
	os.Stdout = old

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	buf := make([]byte, 8192)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	// Should be valid JSON.
	var e cache.Entry
	if err := json.Unmarshal([]byte(output), &e); err != nil {
		t.Errorf("output is not valid JSON: %v\nraw: %s", err, output)
	}
	if e.Command != "git log" {
		t.Errorf("Command = %q, want %q", e.Command, "git log")
	}
}

func TestCacheInspect_EmptyCache(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "verdicts")
	os.MkdirAll(dir, 0o755)

	origFn := cacheDirFn
	cacheDirFn = func() string { return dir }
	defer func() { cacheDirFn = origFn }()

	code := cacheInspectCmd([]string{})
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
}

func TestCacheInspect_NonexistentDir(t *testing.T) {
	origFn := cacheDirFn
	cacheDirFn = func() string { return filepath.Join(t.TempDir(), "does-not-exist") }
	defer func() { cacheDirFn = origFn }()

	code := cacheInspectCmd([]string{})
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
}

func TestCacheInspect_LimitFlag(t *testing.T) {
	entries := make([]cache.Entry, 5)
	for i := range entries {
		entries[i] = cache.Entry{
			Command:  "cmd" + string(rune('A'+i)),
			Verdict:  cache.VerdictAllow,
			Tier:     "llm",
			Provider: "anthropic",
			Model:    "haiku",
			StoredAt: time.Now().Add(-time.Duration(i) * time.Hour),
		}
	}
	dir := seedTestCache(t, entries)

	origFn := cacheDirFn
	cacheDirFn = func() string { return dir }
	defer func() { cacheDirFn = origFn }()

	code := cacheInspectCmd([]string{"--limit", "2"})
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
}

func TestParseExtendedDuration(t *testing.T) {
	cases := []struct {
		input string
		want  time.Duration
		err   bool
	}{
		{"30m", 30 * time.Minute, false},
		{"2h", 2 * time.Hour, false},
		{"7d", 7 * 24 * time.Hour, false},
		{"1w", 7 * 24 * time.Hour, false},
		{"2W", 14 * 24 * time.Hour, false},
		{"", 0, true},
	}
	for _, tc := range cases {
		got, err := parseExtendedDuration(tc.input)
		if tc.err && err == nil {
			t.Errorf("parseExtendedDuration(%q): want error, got %v", tc.input, got)
			continue
		}
		if !tc.err && err != nil {
			t.Errorf("parseExtendedDuration(%q): unexpected error: %v", tc.input, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseExtendedDuration(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}
