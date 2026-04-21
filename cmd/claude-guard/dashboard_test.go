package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RobinUS2/claude-guard/internal/cache"
	"github.com/RobinUS2/claude-guard/internal/store"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// writeDecisionLog creates a minimal decisions.jsonl in a temp dir and
// returns a cleanup function that restores the original log dir.
func writeDecisionLog(t *testing.T, lines []string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "decisions.jsonl")
	var content string
	for _, l := range lines {
		content += l + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// makeDecisionLine returns a JSON line for a decision record.
func makeDecisionLine(verdict, tier, command string) string {
	rec := map[string]any{
		"time":       time.Now().Format(time.RFC3339Nano),
		"level":      "INFO",
		"msg":        "decision",
		"verdict":    verdict,
		"tier":       tier,
		"command":    command,
		"latency_us": 150,
	}
	data, _ := json.Marshal(rec)
	return string(data)
}

// makeStopHookLine returns a JSON line for a stop_hook record.
func makeStopHookLine(injected bool, firedRule string) string {
	rec := map[string]any{
		"time":            time.Now().Format(time.RFC3339Nano),
		"level":           "INFO",
		"msg":             "stop_hook",
		"stop_hook_active": true,
		"fired_rule":      firedRule,
		"injected":        injected,
		"continue_count":  1,
		"latency_us":      50,
	}
	data, _ := json.Marshal(rec)
	return string(data)
}

// setupTestCacheDir creates a temp cache directory with some entries and
// patches cacheDirFn to point at it.
func setupTestCacheDir(t *testing.T, entries []cache.Entry) (cleanup func()) {
	t.Helper()
	dir := t.TempDir()
	cch := cache.New(dir)
	for i, e := range entries {
		key := cache.Key(cache.KeyInputs{
			Tool:    "Bash",
			Command: e.Command,
			CWD:     "/tmp",
		})
		_ = i
		if err := cch.Put(key, e, 24*time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	old := cacheDirFn
	cacheDirFn = func() string { return dir }
	return func() { cacheDirFn = old }
}

// setupTestStore creates a temp SQLite store and patches defaultStorePath
// indirectly by setting XDG_CACHE_HOME.
func setupTestStore(t *testing.T) (*store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "guard.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	return db, dbPath
}

// ---------------------------------------------------------------------------
// API: /api/stats
// ---------------------------------------------------------------------------

func TestAPIStats_Empty(t *testing.T) {
	// No log file — should return valid JSON with zeros.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/stats?since=1h", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	handleAPIStats(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp statsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if resp.Total != 0 {
		t.Errorf("expected total=0, got %d", resp.Total)
	}
}

func TestAPIStats_WithData(t *testing.T) {
	lines := []string{
		makeDecisionLine("allow", "instant_allow", "git status"),
		makeDecisionLine("allow", "cache", "npm test"),
		makeDecisionLine("deny", "instant_block", "rm -rf /"),
		makeDecisionLine("continue", "llm", "curl http://example.com"),
		makeStopHookLine(true, "long_session"),
	}
	dir := writeDecisionLog(t, lines)

	// Point config to use our temp log dir by setting env.
	origHome := os.Getenv("HOME")
	tmpHome := t.TempDir()
	// Create the expected log path structure.
	logDir := filepath.Join(tmpHome, ".claude", "logs", "claude-guard")
	os.MkdirAll(logDir, 0o755)

	// Copy our test decisions file to the expected location.
	src := filepath.Join(dir, "decisions.jsonl")
	dst := filepath.Join(logDir, "decisions.jsonl")
	data, _ := os.ReadFile(src)
	os.WriteFile(dst, data, 0o644)

	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", origHome)

	cleanup := setupTestCacheDir(t, []cache.Entry{
		{Verdict: cache.VerdictAllow, Command: "git status", Tier: "cache"},
	})
	defer cleanup()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/stats?since=24h", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	handleAPIStats(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp statsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v\nbody: %s", err, rec.Body.String())
	}
	if resp.Total != 4 {
		t.Errorf("expected total=4, got %d", resp.Total)
	}
	if resp.ByVerdict["allow"] != 2 {
		t.Errorf("expected allow=2, got %d", resp.ByVerdict["allow"])
	}
	if resp.ByVerdict["deny"] != 1 {
		t.Errorf("expected deny=1, got %d", resp.ByVerdict["deny"])
	}
	if resp.StopHooks == nil || resp.StopHooks.Total != 1 {
		t.Errorf("expected 1 stop hook, got %+v", resp.StopHooks)
	}
}

// ---------------------------------------------------------------------------
// API: /api/decisions
// ---------------------------------------------------------------------------

func TestAPIDecisions_Empty(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/decisions?since=1h", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	handleAPIDecisions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var entries []decisionEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &entries); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestAPIDecisions_WithData(t *testing.T) {
	lines := []string{
		makeDecisionLine("allow", "cache", "echo hello"),
		makeDecisionLine("deny", "instant_block", "rm -rf /"),
	}
	dir := writeDecisionLog(t, lines)

	tmpHome := t.TempDir()
	logDir := filepath.Join(tmpHome, ".claude", "logs", "claude-guard")
	os.MkdirAll(logDir, 0o755)

	src := filepath.Join(dir, "decisions.jsonl")
	dst := filepath.Join(logDir, "decisions.jsonl")
	data, _ := os.ReadFile(src)
	os.WriteFile(dst, data, 0o644)

	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", origHome)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/decisions?since=1h&limit=10", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	handleAPIDecisions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var entries []decisionEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &entries); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
	// Newest first.
	if len(entries) == 2 && entries[0].Verdict != "deny" {
		t.Errorf("expected newest first (deny), got %s", entries[0].Verdict)
	}
}

// ---------------------------------------------------------------------------
// API: /api/stop-hooks
// ---------------------------------------------------------------------------

func TestAPIStopHooks_Empty(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/stop-hooks?since=1h", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	handleAPIStopHooks(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var entries []stopHookEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &entries); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

// ---------------------------------------------------------------------------
// API: /api/cache
// ---------------------------------------------------------------------------

func TestAPICache_Empty(t *testing.T) {
	cleanup := setupTestCacheDir(t, nil)
	defer cleanup()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/cache", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	handleAPICache(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var entries []cacheEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &entries); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestAPICache_WithEntries(t *testing.T) {
	cleanup := setupTestCacheDir(t, []cache.Entry{
		{Verdict: cache.VerdictAllow, Command: "git status", Tier: "cache", Program: "git"},
		{Verdict: cache.VerdictAllow, Command: "npm test", Tier: "llm", Program: "npm"},
		{Verdict: cache.VerdictDeny, Command: "rm -rf /", Tier: "instant_block", Program: "rm"},
	})
	defer cleanup()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/cache?limit=50", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	handleAPICache(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var entries []cacheEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &entries); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(entries))
	}
}

func TestAPICache_FilterByVerdict(t *testing.T) {
	cleanup := setupTestCacheDir(t, []cache.Entry{
		{Verdict: cache.VerdictAllow, Command: "git status", Tier: "cache"},
		{Verdict: cache.VerdictDeny, Command: "rm -rf /", Tier: "instant_block"},
	})
	defer cleanup()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/cache?verdict=deny", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	handleAPICache(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var entries []cacheEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &entries); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 deny entry, got %d", len(entries))
	}
}

func TestAPICache_FilterByMatch(t *testing.T) {
	cleanup := setupTestCacheDir(t, []cache.Entry{
		{Verdict: cache.VerdictAllow, Command: "git status", Tier: "cache"},
		{Verdict: cache.VerdictAllow, Command: "npm test", Tier: "llm"},
	})
	defer cleanup()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/cache?match=git", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	handleAPICache(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var entries []cacheEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &entries); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 entry matching 'git', got %d", len(entries))
	}
}

// ---------------------------------------------------------------------------
// API: /api/learned
// ---------------------------------------------------------------------------

func TestAPILearned_Empty(t *testing.T) {
	// Point to non-existent DB path.
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", t.TempDir())
	defer os.Setenv("HOME", origHome)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/learned", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	handleAPILearned(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var entries []learnedEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &entries); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestAPILearned_WithPatterns(t *testing.T) {
	db, dbPath := setupTestStore(t)

	// Insert a learned entry.
	entry := cache.Entry{
		Verdict:       cache.VerdictAllow,
		Tier:          "learned",
		Reason:        "user-approved",
		Provider:      "user",
		Model:         "human",
		Command:       "go test ./...",
		Program:       "go",
		CanonicalForm: "go test {PACKAGE}",
		MatchCount:    5,
	}
	key := cache.Key(cache.KeyInputs{Tool: "Bash", Command: "go test {PACKAGE}", CWD: "/tmp"})
	if err := db.PutVerdict(key, entry, 0); err != nil {
		t.Fatal(err)
	}
	db.Close()

	// Override the store path lookup so queryLearnedPatterns uses our test DB.
	// We do this by temporarily replacing the function — but since
	// queryLearnedPatterns takes a path directly, we override defaultStorePath.
	origHome := os.Getenv("HOME")
	origXDG := os.Getenv("XDG_CACHE_HOME")
	os.Setenv("XDG_CACHE_HOME", filepath.Dir(dbPath))
	defer func() {
		os.Setenv("HOME", origHome)
		os.Setenv("XDG_CACHE_HOME", origXDG)
	}()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/learned", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	handleAPILearned(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var entries []learnedEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &entries); err != nil {
		t.Fatalf("invalid JSON: %v\nbody: %s", err, rec.Body.String())
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 learned entry, got %d", len(entries))
	}
	if len(entries) == 1 {
		if entries[0].ApprovalCount != 5 {
			t.Errorf("expected approval_count=5, got %d", entries[0].ApprovalCount)
		}
		if entries[0].CanonicalForm != "go test {PACKAGE}" {
			t.Errorf("expected canonical form, got %q", entries[0].CanonicalForm)
		}
	}
}

// ---------------------------------------------------------------------------
// API: /api/metrics/history
// ---------------------------------------------------------------------------

func TestAPIMetricsHistory_Empty(t *testing.T) {
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", t.TempDir())
	defer os.Setenv("HOME", origHome)

	origXDG := os.Getenv("XDG_CACHE_HOME")
	os.Setenv("XDG_CACHE_HOME", t.TempDir())
	defer os.Setenv("XDG_CACHE_HOME", origXDG)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/metrics/history?days=7", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	handleAPIMetricsHistory(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	// Should be a valid JSON array.
	body := rec.Body.Bytes()
	var arr []any
	if err := json.Unmarshal(body, &arr); err != nil {
		t.Fatalf("invalid JSON: %v\nbody: %s", err, string(body))
	}
}

func TestAPIMetricsHistory_WithData(t *testing.T) {
	db, dbPath := setupTestStore(t)

	// Insert a metrics snapshot.
	snap := store.MetricsSnapshot{
		RecordedAt:     time.Now().Add(-1 * time.Hour),
		PeriodHours:    24,
		TotalDecisions: 100,
		AllowCount:     80,
		ContinueCount:  15,
		DenyCount:      5,
	}
	if err := db.RecordMetrics(snap); err != nil {
		t.Fatal(err)
	}
	db.Close()

	origXDG := os.Getenv("XDG_CACHE_HOME")
	os.Setenv("XDG_CACHE_HOME", filepath.Dir(dbPath))
	defer os.Setenv("XDG_CACHE_HOME", origXDG)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/metrics/history?days=7", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	handleAPIMetricsHistory(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var snapshots []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &snapshots); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(snapshots) != 1 {
		t.Errorf("expected 1 snapshot, got %d", len(snapshots))
	}
}

// ---------------------------------------------------------------------------
// Localhost-only middleware
// ---------------------------------------------------------------------------

func TestLocalhostOnly_Allows127(t *testing.T) {
	handler := localhostOnly(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "ok")
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for localhost, got %d", rec.Code)
	}
}

func TestLocalhostOnly_AllowsIPv6Loopback(t *testing.T) {
	handler := localhostOnly(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "[::1]:12345"
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for ::1, got %d", rec.Code)
	}
}

func TestLocalhostOnly_RejectsExternal(t *testing.T) {
	handler := localhostOnly(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	handler(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for external IP, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Embedded filesystem
// ---------------------------------------------------------------------------

func TestDashboardFS_IndexHTML(t *testing.T) {
	sub, err := newDashboardFS()
	if err != nil {
		t.Fatal(err)
	}
	f, err := sub.Open("index.html")
	if err != nil {
		t.Fatal("expected index.html in embedded FS:", err)
	}
	f.Close()
}

func TestDashboardFS_CSS(t *testing.T) {
	sub, err := newDashboardFS()
	if err != nil {
		t.Fatal(err)
	}
	f, err := sub.Open("style.css")
	if err != nil {
		t.Fatal("expected style.css in embedded FS:", err)
	}
	f.Close()
}

func TestDashboardFS_JS(t *testing.T) {
	sub, err := newDashboardFS()
	if err != nil {
		t.Fatal(err)
	}
	f, err := sub.Open("app.js")
	if err != nil {
		t.Fatal("expected app.js in embedded FS:", err)
	}
	f.Close()
}

// ---------------------------------------------------------------------------
// parseSince
// ---------------------------------------------------------------------------

func TestParseSince(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
	}{
		{"1h", 1 * time.Hour},
		{"24h", 24 * time.Hour},
		{"7d", 7 * 24 * time.Hour},
		{"30d", 30 * 24 * time.Hour},
		{"", 24 * time.Hour}, // fallback
		{"invalid", 24 * time.Hour},
	}
	for _, tt := range tests {
		got := parseSince(tt.input, 24*time.Hour)
		if got != tt.expected {
			t.Errorf("parseSince(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}
