package main

import (
	"bufio"
	"database/sql"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/RobinUS2/claude-guard/internal/cache"
	"github.com/RobinUS2/claude-guard/internal/config"
	clog "github.com/RobinUS2/claude-guard/internal/log"
	"github.com/RobinUS2/claude-guard/internal/store"

	_ "modernc.org/sqlite"
)

//go:embed dashboard/*
var dashboardFS embed.FS

// cmdDashboard starts a localhost-only HTTP server serving the web dashboard.
func cmdDashboard(args []string) int {
	fs := flag.NewFlagSet("dashboard", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var port int
	var noBrowser bool
	fs.IntVar(&port, "port", 9384, "port to bind to (localhost only)")
	fs.BoolVar(&noBrowser, "no-browser", false, "don't auto-open browser")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	mux := http.NewServeMux()

	// API endpoints.
	mux.HandleFunc("/api/stats", localhostOnly(handleAPIStats))
	mux.HandleFunc("/api/decisions", localhostOnly(handleAPIDecisions))
	mux.HandleFunc("/api/stop-hooks", localhostOnly(handleAPIStopHooks))
	mux.HandleFunc("/api/cache", localhostOnly(handleAPICache))
	mux.HandleFunc("/api/learned", localhostOnly(handleAPILearned))
	mux.HandleFunc("/api/metrics/history", localhostOnly(handleAPIMetricsHistory))

	// Static files — serve embedded dashboard/ directory at /.
	staticFS, err := newDashboardFS()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dashboard: embed fs: %v\n", err)
		return 1
	}
	mux.Handle("/", http.FileServer(http.FS(staticFS)))

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dashboard: listen %s: %v\n", addr, err)
		return 1
	}

	url := fmt.Sprintf("http://%s", addr)
	fmt.Printf("claude-guard dashboard: %s\n", url)

	if !noBrowser {
		openBrowser(url)
	}

	server := &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "dashboard: serve: %v\n", err)
		return 1
	}
	return 0
}

// newDashboardFS returns a sub-filesystem rooted at "dashboard/" from the
// embedded FS, so files are served without the "dashboard/" prefix.
func newDashboardFS() (fs.FS, error) {
	return fs.Sub(dashboardFS, "dashboard")
}

// localhostOnly wraps a handler and rejects requests that don't come from
// loopback addresses.
func localhostOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			http.Error(w, "forbidden: dashboard is localhost-only", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func openBrowser(url string) {
	var cmd string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
	case "linux":
		cmd = "xdg-open"
	case "windows":
		cmd = "start"
	default:
		return
	}
	_ = exec.Command(cmd, url).Start()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// parseSince parses a "since" query parameter like "24h", "1h", "7d".
func parseSince(s string, fallback time.Duration) time.Duration {
	if s == "" {
		return fallback
	}
	// Support day suffix.
	s = strings.TrimSpace(s)
	if len(s) > 0 && (s[len(s)-1] == 'd' || s[len(s)-1] == 'D') {
		n, err := strconv.Atoi(s[:len(s)-1])
		if err == nil {
			return time.Duration(n) * 24 * time.Hour
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return fallback
	}
	return d
}

// ---------------------------------------------------------------------------
// API: /api/stats
// ---------------------------------------------------------------------------

type statsResponse struct {
	Since       string         `json:"since"`
	Total       int            `json:"total"`
	ByVerdict   map[string]int `json:"by_verdict"`
	ByTier      map[string]int `json:"by_tier"`
	LatencyP50  float64        `json:"latency_p50_ms"`
	LatencyP95  float64        `json:"latency_p95_ms"`
	LatencyP99  float64        `json:"latency_p99_ms"`
	LatencyMax  float64        `json:"latency_max_ms"`
	CacheStats  *cacheInfo     `json:"cache,omitempty"`
	StopHooks   *stopHookInfo  `json:"stop_hooks,omitempty"`
	TimeSaved   *timeSavedInfo `json:"time_saved,omitempty"`
}

type cacheInfo struct {
	Entries     int   `json:"entries"`
	BytesOnDisk int64 `json:"bytes_on_disk"`
	Verified    int   `json:"verified"`
	Disagree    int   `json:"disagree"`
}

type stopHookInfo struct {
	Total    int `json:"total"`
	Injected int `json:"injected"`
	Capped   int `json:"capped"`
}

type timeSavedInfo struct {
	InterruptsAvoided int `json:"interrupts_avoided"`
	MinutesSaved      int `json:"minutes_saved"`
}

func handleAPIStats(w http.ResponseWriter, r *http.Request) {
	since := parseSince(r.URL.Query().Get("since"), 24*time.Hour)
	cutoff := time.Now().Add(-since)

	cfg := config.Default()
	paths := clog.DefaultPaths(cfg.Log.Dir)

	f, err := os.Open(paths.Decisions)
	if err != nil {
		writeJSON(w, http.StatusOK, statsResponse{
			Since:     since.String(),
			ByVerdict: map[string]int{},
			ByTier:    map[string]int{},
		})
		return
	}
	defer f.Close()

	agg := newAggregation()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<16), 1<<20)
	for scanner.Scan() {
		var rec clog.ReadRecord
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			continue
		}
		if rec.Msg == clog.MsgStopHook {
			var sr clog.StopHookRecord
			if err := json.Unmarshal(scanner.Bytes(), &sr); err == nil {
				agg.addStopHook(&sr)
			}
			continue
		}
		if rec.Msg != clog.MsgDecision {
			continue
		}
		if ts, err := time.Parse(time.RFC3339Nano, rec.Time); err == nil {
			if ts.Before(cutoff) {
				continue
			}
		}
		agg.add(&rec)
	}

	resp := statsResponse{
		Since:      since.String(),
		Total:      agg.total,
		ByVerdict:  agg.byVerdict,
		ByTier:     agg.byTier,
		LatencyP50: percentileMs(agg.latencies, 0.50),
		LatencyP95: percentileMs(agg.latencies, 0.95),
		LatencyP99: percentileMs(agg.latencies, 0.99),
		LatencyMax: percentileMs(agg.latencies, 1.00),
	}

	// Cache stats.
	dir := cacheDirForOps()
	cch := cache.New(dir)
	if cs, err := cch.Stats(); err == nil && cs.Entries > 0 {
		resp.CacheStats = &cacheInfo{
			Entries:     cs.Entries,
			BytesOnDisk: cs.BytesOnDisk,
			Verified:    cs.Verified,
			Disagree:    cs.Disagree,
		}
	}

	// Stop hook info.
	if agg.stopTotal > 0 {
		resp.StopHooks = &stopHookInfo{
			Total:    agg.stopTotal,
			Injected: agg.stopInjected,
			Capped:   agg.stopCapped,
		}
	}

	// Time saved.
	avoided, savedMin := computeTimeSaved(agg)
	if avoided > 0 {
		resp.TimeSaved = &timeSavedInfo{
			InterruptsAvoided: avoided,
			MinutesSaved:      savedMin,
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// API: /api/decisions
// ---------------------------------------------------------------------------

type decisionEntry struct {
	Time      string `json:"time"`
	Command   string `json:"command"`
	Verdict   string `json:"verdict"`
	Tier      string `json:"tier"`
	Reason    string `json:"reason,omitempty"`
	LatencyUS int64  `json:"latency_us"`
	SessionID string `json:"session_id,omitempty"`
	CWD       string `json:"cwd,omitempty"`
}

func handleAPIDecisions(w http.ResponseWriter, r *http.Request) {
	since := parseSince(r.URL.Query().Get("since"), 1*time.Hour)
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if n, err := strconv.Atoi(limitStr); err == nil && n > 0 && n <= 1000 {
		limit = n
	}

	cutoff := time.Now().Add(-since)
	cfg := config.Default()
	paths := clog.DefaultPaths(cfg.Log.Dir)

	f, err := os.Open(paths.Decisions)
	if err != nil {
		writeJSON(w, http.StatusOK, []decisionEntry{})
		return
	}
	defer f.Close()

	var entries []decisionEntry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<16), 1<<20)
	for scanner.Scan() {
		var rec clog.ReadRecord
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			continue
		}
		if rec.Msg != clog.MsgDecision {
			continue
		}
		if ts, err := time.Parse(time.RFC3339Nano, rec.Time); err == nil {
			if ts.Before(cutoff) {
				continue
			}
		}
		entries = append(entries, decisionEntry{
			Time:      rec.Time,
			Command:   rec.Command,
			Verdict:   rec.Verdict,
			Tier:      rec.Tier,
			Reason:    rec.Reason,
			LatencyUS: rec.LatencyUS,
			SessionID: rec.SessionID,
			CWD:       rec.CWD,
		})
	}

	// Return newest first, capped at limit.
	if len(entries) > limit {
		entries = entries[len(entries)-limit:]
	}
	// Reverse for newest-first.
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}

	writeJSON(w, http.StatusOK, entries)
}

// ---------------------------------------------------------------------------
// API: /api/stop-hooks
// ---------------------------------------------------------------------------

type stopHookEntry struct {
	Time          string `json:"time"`
	SessionID     string `json:"session_id,omitempty"`
	FiredRule     string `json:"fired_rule,omitempty"`
	Injected      bool   `json:"injected"`
	Suppressed    string `json:"suppressed,omitempty"`
	ContinueCount int   `json:"continue_count"`
}

func handleAPIStopHooks(w http.ResponseWriter, r *http.Request) {
	since := parseSince(r.URL.Query().Get("since"), 24*time.Hour)
	cutoff := time.Now().Add(-since)

	cfg := config.Default()
	paths := clog.DefaultPaths(cfg.Log.Dir)

	f, err := os.Open(paths.Decisions)
	if err != nil {
		writeJSON(w, http.StatusOK, []stopHookEntry{})
		return
	}
	defer f.Close()

	var entries []stopHookEntry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<16), 1<<20)
	for scanner.Scan() {
		var rec clog.StopHookRecord
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			continue
		}
		if rec.Msg != clog.MsgStopHook {
			continue
		}
		if ts, err := time.Parse(time.RFC3339Nano, rec.Time); err == nil {
			if ts.Before(cutoff) {
				continue
			}
		}
		entries = append(entries, stopHookEntry{
			Time:          rec.Time,
			SessionID:     rec.SessionID,
			FiredRule:     rec.FiredRule,
			Injected:      rec.Injected,
			Suppressed:    rec.Suppressed,
			ContinueCount: rec.ContinueCount,
		})
	}

	// Newest first.
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}

	writeJSON(w, http.StatusOK, entries)
}

// ---------------------------------------------------------------------------
// API: /api/cache
// ---------------------------------------------------------------------------

type cacheEntry struct {
	Command          string `json:"command"`
	Verdict          string `json:"verdict"`
	EffectiveVerdict string `json:"effective_verdict"`
	Tier             string `json:"tier"`
	Reason           string `json:"reason,omitempty"`
	Provider         string `json:"provider,omitempty"`
	Model            string `json:"model,omitempty"`
	StoredAt         string `json:"stored_at"`
	ExpiresAt        string `json:"expires_at,omitempty"`
	CWD              string `json:"cwd,omitempty"`
	Program          string `json:"program,omitempty"`
	CanonicalForm    string `json:"canonical_form,omitempty"`
	MatchCount       int    `json:"match_count"`
	Verified         bool   `json:"verified"`
	Disagreement     bool   `json:"disagreement"`
}

func handleAPICache(w http.ResponseWriter, r *http.Request) {
	matchSub := r.URL.Query().Get("match")
	verdictFilter := r.URL.Query().Get("verdict")
	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if n, err := strconv.Atoi(limitStr); err == nil && n > 0 && n <= 500 {
		limit = n
	}

	dir := cacheDirForOps()
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		writeJSON(w, http.StatusOK, []cacheEntry{})
		return
	}

	now := time.Now()
	var entries []cacheEntry

	_ = walkCacheForAPI(dir, now, matchSub, verdictFilter, limit, func(e *cache.Entry) {
		ce := cacheEntry{
			Command:          e.Command,
			Verdict:          string(e.Verdict),
			EffectiveVerdict: string(e.EffectiveVerdict()),
			Tier:             e.Tier,
			Reason:           e.Reason,
			Provider:         e.Provider,
			Model:            e.Model,
			CWD:              e.CWD,
			Program:          e.Program,
			CanonicalForm:    e.CanonicalForm,
			MatchCount:       e.MatchCount,
			Verified:         e.Verified,
			Disagreement:     e.Disagreement,
		}
		if !e.StoredAt.IsZero() {
			ce.StoredAt = e.StoredAt.Format(time.RFC3339)
		}
		if !e.ExpiresAt.IsZero() {
			ce.ExpiresAt = e.ExpiresAt.Format(time.RFC3339)
		}
		entries = append(entries, ce)
	})

	if entries == nil {
		entries = []cacheEntry{}
	}
	writeJSON(w, http.StatusOK, entries)
}

// walkCacheForAPI walks the file cache directory with filter support.
func walkCacheForAPI(dir string, now time.Time, matchSub, verdictFilter string, limit int, fn func(*cache.Entry)) error {
	shown := 0
	return walkCacheDir(dir, func(e *cache.Entry) bool {
		if shown >= limit {
			return false
		}
		if e.Expired(now) {
			return true
		}
		if matchSub != "" && !strings.Contains(e.Command, matchSub) {
			return true
		}
		if verdictFilter != "" && string(e.EffectiveVerdict()) != verdictFilter {
			return true
		}
		fn(e)
		shown++
		return true
	})
}

// walkCacheDir walks cache JSON files and calls fn for each parsed entry.
// fn returns false to stop walking.
func walkCacheDir(dir string, fn func(*cache.Entry) bool) error {
	return walkCacheDirFunc(dir, fn)
}

// walkCacheDirFunc is the implementation, overridable in tests.
var walkCacheDirFunc = defaultWalkCacheDir

func defaultWalkCacheDir(dir string, fn func(*cache.Entry) bool) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, de := range entries {
		if de.IsDir() {
			// Shard directory — recurse.
			subpath := dir + "/" + de.Name()
			if err := defaultWalkCacheDir(subpath, fn); err != nil {
				return err
			}
			continue
		}
		if !strings.HasSuffix(de.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(dir + "/" + de.Name())
		if err != nil {
			continue
		}
		var e cache.Entry
		if json.Unmarshal(data, &e) != nil {
			continue
		}
		if !fn(&e) {
			return nil
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// API: /api/learned
// ---------------------------------------------------------------------------

type learnedEntry struct {
	Command       string `json:"command"`
	CanonicalForm string `json:"canonical_form,omitempty"`
	Program       string `json:"program,omitempty"`
	CWD           string `json:"cwd,omitempty"`
	ApprovalCount int    `json:"approval_count"`
	StoredAt      string `json:"stored_at"`
}

func handleAPILearned(w http.ResponseWriter, r *http.Request) {
	dbPath := defaultStorePath()
	entries, err := queryLearnedPatterns(dbPath)
	if err != nil {
		// Fall back to empty list — DB may not exist yet.
		writeJSON(w, http.StatusOK, []learnedEntry{})
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

// queryLearnedPatterns opens a read-only connection to the SQLite DB
// and queries learned entries. We open a separate connection to avoid
// modifying the store package.
func queryLearnedPatterns(dbPath string) ([]learnedEntry, error) {
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return nil, err
	}
	db, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query(`
		SELECT command, canonical_form, program, cwd, match_count, stored_at
		FROM verdicts
		WHERE tier = 'learned'
		ORDER BY match_count DESC, stored_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []learnedEntry
	for rows.Next() {
		var e learnedEntry
		var canonical, program, cwd sql.NullString
		var storedStr string
		if err := rows.Scan(&e.Command, &canonical, &program, &cwd, &e.ApprovalCount, &storedStr); err != nil {
			continue
		}
		if canonical.Valid {
			e.CanonicalForm = canonical.String
		}
		if program.Valid {
			e.Program = program.String
		}
		if cwd.Valid {
			e.CWD = cwd.String
		}
		e.StoredAt = storedStr
		out = append(out, e)
	}
	if out == nil {
		out = []learnedEntry{}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// API: /api/metrics/history
// ---------------------------------------------------------------------------

func handleAPIMetricsHistory(w http.ResponseWriter, r *http.Request) {
	daysStr := r.URL.Query().Get("days")
	days := 30
	if n, err := strconv.Atoi(daysStr); err == nil && n > 0 && n <= 365 {
		days = n
	}

	dbPath := defaultStorePath()
	db, err := store.Open(dbPath)
	if err != nil {
		writeJSON(w, http.StatusOK, []store.MetricsSnapshot{})
		return
	}
	defer db.Close()

	history, err := db.GetMetricsHistory(days)
	if err != nil || history == nil {
		writeJSON(w, http.StatusOK, []store.MetricsSnapshot{})
		return
	}

	writeJSON(w, http.StatusOK, history)
}
