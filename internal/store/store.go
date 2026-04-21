// Package store implements a SQLite-backed storage layer for claude-guard.
// It replaces the file-per-key verdict cache with a single database file,
// adds pending approval tracking (for the learn subcommand), and provides
// persistent metrics history.
//
// The database lives at ~/.cache/claude-guard/guard.db and uses WAL mode
// for concurrent read access during hook invocations.
package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/RobinUS2/claude-guard/internal/cache"

	// Pure-Go SQLite driver — no CGO required.
	_ "modernc.org/sqlite"
)

// schemaVersion is stored in PRAGMA user_version. Bump when the schema
// changes in a way that requires migration.
const schemaVersion = 1

// PendingApproval represents a command awaiting user approval. Written
// by PreToolUse when the verdict is Continue, read by the learn
// subcommand after PostToolUse confirms the user approved.
type PendingApproval struct {
	ToolUseID     string
	Command       string
	CanonicalForm string
	CWD           string
	SessionID     string
	PromptedAt    time.Time
	Reason        string
}

// MetricsSnapshot is a point-in-time capture of guard activity over
// a given lookback period. Stored in the metrics_snapshots table for
// trend analysis.
type MetricsSnapshot struct {
	ID                  int64
	RecordedAt          time.Time
	PeriodHours         int
	TotalDecisions      int
	AllowCount          int
	ContinueCount       int
	DenyCount           int
	LearnedAllows       int
	StopHookEvals       int
	StopHookFires       int
	Interrupts          int
	UserApproved        int
	MedianUninterrupted float64
	P95Uninterrupted    float64
	CacheEntries        int
	LearnedPatterns     int
}

// Store wraps a SQLite database for all claude-guard persistent state.
type Store struct {
	db *sql.DB
}

// Open creates or opens the SQLite database at path, creates tables if
// they don't exist, and configures WAL mode with a 5-second busy
// timeout. The parent directory is created if needed.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("store: mkdir %s: %w", filepath.Dir(path), err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}

	// WAL mode for concurrent readers + single writer.
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: set WAL mode: %w", err)
	}
	// 5-second busy timeout so concurrent hook invocations don't fail
	// immediately when one is writing.
	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: set busy_timeout: %w", err)
	}

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: migrate: %w", err)
	}

	return s, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// migrate creates tables if they don't exist and updates
// PRAGMA user_version.
func (s *Store) migrate() error {
	var ver int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&ver); err != nil {
		return fmt.Errorf("read user_version: %w", err)
	}
	if ver >= schemaVersion {
		return nil // already at current schema
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// --- verdicts ---
	if _, err := tx.Exec(`
		CREATE TABLE IF NOT EXISTS verdicts (
			key TEXT PRIMARY KEY,
			command TEXT,
			canonical_form TEXT,
			program TEXT,
			cwd TEXT,
			verdict TEXT NOT NULL,
			tier TEXT,
			reason TEXT,
			provider TEXT,
			model TEXT,
			stored_at TEXT NOT NULL,
			expires_at TEXT,
			verified INTEGER DEFAULT 0,
			verified_at TEXT,
			verifier_provider TEXT,
			verifier_model TEXT,
			verifier_verdict TEXT,
			verifier_reason TEXT,
			disagreement INTEGER DEFAULT 0,
			trusted_at TEXT,
			trusted_reason TEXT,
			match_count INTEGER DEFAULT 0,
			approval_count INTEGER DEFAULT 0
		)`); err != nil {
		return fmt.Errorf("create verdicts: %w", err)
	}
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_verdicts_program ON verdicts(program)`); err != nil {
		return fmt.Errorf("create idx_verdicts_program: %w", err)
	}
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_verdicts_expires ON verdicts(expires_at)`); err != nil {
		return fmt.Errorf("create idx_verdicts_expires: %w", err)
	}
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_verdicts_canonical ON verdicts(canonical_form) WHERE canonical_form != ''`); err != nil {
		return fmt.Errorf("create idx_verdicts_canonical: %w", err)
	}

	// --- pending_approvals ---
	if _, err := tx.Exec(`
		CREATE TABLE IF NOT EXISTS pending_approvals (
			tool_use_id TEXT PRIMARY KEY,
			command TEXT NOT NULL,
			canonical_form TEXT,
			cwd TEXT,
			session_id TEXT,
			prompted_at TEXT NOT NULL,
			reason TEXT
		)`); err != nil {
		return fmt.Errorf("create pending_approvals: %w", err)
	}
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_pending_age ON pending_approvals(prompted_at)`); err != nil {
		return fmt.Errorf("create idx_pending_age: %w", err)
	}

	// --- metrics_snapshots ---
	if _, err := tx.Exec(`
		CREATE TABLE IF NOT EXISTS metrics_snapshots (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			recorded_at TEXT NOT NULL,
			period_hours INTEGER NOT NULL,
			total_decisions INTEGER,
			allow_count INTEGER,
			continue_count INTEGER,
			deny_count INTEGER,
			learned_allows INTEGER,
			stop_hook_evals INTEGER,
			stop_hook_fires INTEGER,
			interrupts INTEGER,
			user_approved INTEGER,
			median_uninterrupted_s REAL,
			p95_uninterrupted_s REAL,
			cache_entries INTEGER,
			learned_patterns INTEGER
		)`); err != nil {
		return fmt.Errorf("create metrics_snapshots: %w", err)
	}
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_metrics_time ON metrics_snapshots(recorded_at)`); err != nil {
		return fmt.Errorf("create idx_metrics_time: %w", err)
	}

	// Stamp the schema version.
	if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", schemaVersion)); err != nil {
		return fmt.Errorf("set user_version: %w", err)
	}

	return tx.Commit()
}

// ---------------------------------------------------------------------------
// Verdict cache
// ---------------------------------------------------------------------------

// GetVerdict retrieves a cached verdict by key. Expired entries are
// deleted on access and reported as misses, matching the behaviour of
// the file-per-key cache.
func (s *Store) GetVerdict(key string) (*cache.Entry, bool) {
	row := s.db.QueryRow(`
		SELECT command, canonical_form, program, cwd,
		       verdict, tier, reason, provider, model,
		       stored_at, expires_at,
		       verified, verified_at,
		       verifier_provider, verifier_model, verifier_verdict, verifier_reason,
		       disagreement,
		       trusted_at, trusted_reason,
		       match_count, approval_count
		FROM verdicts WHERE key = ?`, key)

	e, err := scanEntry(row)
	if err != nil {
		return nil, false
	}

	// Evict expired entries on read.
	if e.Expired(time.Now()) {
		_, _ = s.db.Exec("DELETE FROM verdicts WHERE key = ?", key)
		return nil, false
	}

	return e, true
}

// PutVerdict inserts or replaces a verdict cache entry. If ttl > 0 the
// entry will expire after that duration; ttl <= 0 means no expiry.
// Commands longer than cache.MaxCommandInEntry are truncated.
func (s *Store) PutVerdict(key string, e cache.Entry, ttl time.Duration) error {
	if e.StoredAt.IsZero() {
		e.StoredAt = time.Now()
	}
	if ttl > 0 {
		e.ExpiresAt = e.StoredAt.Add(ttl)
	}
	if len(e.Command) > cache.MaxCommandInEntry {
		e.Command = e.Command[:cache.MaxCommandInEntry-3] + "..."
	}

	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO verdicts (
			key, command, canonical_form, program, cwd,
			verdict, tier, reason, provider, model,
			stored_at, expires_at,
			verified, verified_at,
			verifier_provider, verifier_model, verifier_verdict, verifier_reason,
			disagreement,
			trusted_at, trusted_reason,
			match_count, approval_count
		) VALUES (?,?,?,?,?, ?,?,?,?,?, ?,?, ?,?, ?,?,?,?, ?, ?,?, ?,?)`,
		key, e.Command, e.CanonicalForm, e.Program, e.CWD,
		string(e.Verdict), e.Tier, e.Reason, e.Provider, e.Model,
		timeToText(e.StoredAt), timeToText(e.ExpiresAt),
		boolToInt(e.Verified), timeToText(e.VerifiedAt),
		e.VerifierProvider, e.VerifierModel, string(e.VerifierVerdict), e.VerifierReason,
		boolToInt(e.Disagreement),
		timeToText(e.TrustedAt), e.TrustedReason,
		e.MatchCount, 0, // approval_count left at 0 unless explicitly set
	)
	return err
}

// DeleteVerdict removes a verdict by key. Idempotent.
func (s *Store) DeleteVerdict(key string) error {
	_, err := s.db.Exec("DELETE FROM verdicts WHERE key = ?", key)
	return err
}

// VerifyVerdict updates an existing entry with the verifier's review.
// Returns (true, nil) if found and updated, (false, nil) on miss.
// Sets Disagreement when the verifier's verdict differs from the
// original.
func (s *Store) VerifyVerdict(key string, result cache.VerifierResult) (bool, error) {
	entry, ok := s.GetVerdict(key)
	if !ok {
		return false, nil
	}

	entry.Verified = true
	entry.VerifiedAt = time.Now()
	entry.VerifierProvider = result.Provider
	entry.VerifierModel = result.Model
	entry.VerifierVerdict = result.Verdict
	entry.VerifierReason = result.Reason
	entry.Disagreement = result.Verdict != entry.Verdict

	// Preserve the original TTL.
	ttl := time.Duration(0)
	if !entry.ExpiresAt.IsZero() {
		ttl = entry.ExpiresAt.Sub(entry.StoredAt)
	}

	if err := s.PutVerdict(key, *entry, ttl); err != nil {
		return false, err
	}
	return true, nil
}

// VerdictStats returns aggregate statistics over all cached verdicts.
func (s *Store) VerdictStats() (cache.Stats, error) {
	var st cache.Stats
	now := time.Now()

	rows, err := s.db.Query(`
		SELECT stored_at, expires_at, verified, disagreement
		FROM verdicts`)
	if err != nil {
		return st, err
	}
	defer rows.Close()

	for rows.Next() {
		var storedStr, expiresStr string
		var verified, disagree int
		if err := rows.Scan(&storedStr, &expiresStr, &verified, &disagree); err != nil {
			return st, err
		}
		storedAt := textToTime(storedStr)
		expiresAt := textToTime(expiresStr)

		st.Entries++
		if verified != 0 {
			st.Verified++
		}
		if disagree != 0 {
			st.Disagree++
		}
		if !expiresAt.IsZero() && now.After(expiresAt) {
			st.ExpiredHits++
		}
		if st.Newest.IsZero() || storedAt.After(st.Newest) {
			st.Newest = storedAt
		}
		if st.Oldest.IsZero() || storedAt.Before(st.Oldest) {
			st.Oldest = storedAt
		}
	}
	return st, rows.Err()
}

// LookupCanonical scans canonical entries whose Program matches the
// given program, returning the first entry whose CanonicalForm matches
// the incoming command via matchFn. Returns (entry, key, true) on hit.
func (s *Store) LookupCanonical(program, command string, matchFn cache.MatchFunc) (*cache.Entry, string, bool) {
	if program == "" || command == "" || matchFn == nil {
		return nil, "", false
	}

	rows, err := s.db.Query(`
		SELECT key, command, canonical_form, program, cwd,
		       verdict, tier, reason, provider, model,
		       stored_at, expires_at,
		       verified, verified_at,
		       verifier_provider, verifier_model, verifier_verdict, verifier_reason,
		       disagreement,
		       trusted_at, trusted_reason,
		       match_count, approval_count
		FROM verdicts
		WHERE canonical_form != '' AND program = ?`, program)
	if err != nil {
		return nil, "", false
	}
	defer rows.Close()

	now := time.Now()
	for rows.Next() {
		var k string
		var cmdStr, canonical, prog, cwd sql.NullString
		var verdict, tier, reason, provider, model sql.NullString
		var storedStr, expiresStr string
		var verified, disagree int
		var verifiedAtStr sql.NullString
		var vfProvider, vfModel, vfVerdict, vfReason sql.NullString
		var trustedAtStr, trustedReason sql.NullString
		var matchCount, approvalCount int

		if err := rows.Scan(
			&k, &cmdStr, &canonical, &prog, &cwd,
			&verdict, &tier, &reason, &provider, &model,
			&storedStr, &expiresStr,
			&verified, &verifiedAtStr,
			&vfProvider, &vfModel, &vfVerdict, &vfReason,
			&disagree,
			&trustedAtStr, &trustedReason,
			&matchCount, &approvalCount,
		); err != nil {
			continue
		}

		e := &cache.Entry{
			Command:          nullStr(cmdStr),
			CanonicalForm:    nullStr(canonical),
			Program:          nullStr(prog),
			CWD:              nullStr(cwd),
			Verdict:          cache.Verdict(nullStr(verdict)),
			Tier:             nullStr(tier),
			Reason:           nullStr(reason),
			Provider:         nullStr(provider),
			Model:            nullStr(model),
			StoredAt:         textToTime(storedStr),
			ExpiresAt:        textToTime(expiresStr),
			Verified:         verified != 0,
			VerifiedAt:       textToTime(nullStr(verifiedAtStr)),
			VerifierProvider: nullStr(vfProvider),
			VerifierModel:    nullStr(vfModel),
			VerifierVerdict:  cache.Verdict(nullStr(vfVerdict)),
			VerifierReason:   nullStr(vfReason),
			Disagreement:     disagree != 0,
			TrustedAt:        textToTime(nullStr(trustedAtStr)),
			TrustedReason:    nullStr(trustedReason),
			MatchCount:       matchCount,
		}

		if e.Expired(now) {
			continue
		}
		if matchFn(e.CanonicalForm, command) {
			return e, k, true
		}
	}
	return nil, "", false
}

// IncrementMatchCount atomically bumps MatchCount for a verdict entry.
// Returns (true, nil) if found, (false, nil) on miss.
func (s *Store) IncrementMatchCount(key string) (bool, error) {
	res, err := s.db.Exec(
		"UPDATE verdicts SET match_count = match_count + 1 WHERE key = ?", key)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// ---------------------------------------------------------------------------
// Pending approvals
// ---------------------------------------------------------------------------

// WritePending records a pending approval for the learn subcommand.
func (s *Store) WritePending(toolUseID, command, canonical, cwd, sessionID, reason string) error {
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO pending_approvals
			(tool_use_id, command, canonical_form, cwd, session_id, prompted_at, reason)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		toolUseID, command, canonical, cwd, sessionID,
		time.Now().UTC().Format(time.RFC3339), reason)
	return err
}

// ReadPending retrieves a pending approval by tool_use_id.
// Returns nil if not found.
func (s *Store) ReadPending(toolUseID string) (*PendingApproval, error) {
	row := s.db.QueryRow(`
		SELECT tool_use_id, command, canonical_form, cwd, session_id, prompted_at, reason
		FROM pending_approvals WHERE tool_use_id = ?`, toolUseID)

	var p PendingApproval
	var canonical, cwd, sessionID, reason sql.NullString
	var promptedStr string
	if err := row.Scan(&p.ToolUseID, &p.Command, &canonical, &cwd, &sessionID, &promptedStr, &reason); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	p.CanonicalForm = nullStr(canonical)
	p.CWD = nullStr(cwd)
	p.SessionID = nullStr(sessionID)
	p.PromptedAt = textToTime(promptedStr)
	p.Reason = nullStr(reason)
	return &p, nil
}

// DeletePending removes a pending approval by tool_use_id. Idempotent.
func (s *Store) DeletePending(toolUseID string) error {
	_, err := s.db.Exec("DELETE FROM pending_approvals WHERE tool_use_id = ?", toolUseID)
	return err
}

// CleanStalePending deletes pending approvals older than maxAge.
// Returns the number of deleted rows.
func (s *Store) CleanStalePending(maxAge time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-maxAge).Format(time.RFC3339)
	res, err := s.db.Exec("DELETE FROM pending_approvals WHERE prompted_at < ?", cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ---------------------------------------------------------------------------
// Metrics snapshots
// ---------------------------------------------------------------------------

// RecordMetrics inserts a metrics snapshot.
func (s *Store) RecordMetrics(snap MetricsSnapshot) error {
	if snap.RecordedAt.IsZero() {
		snap.RecordedAt = time.Now()
	}
	_, err := s.db.Exec(`
		INSERT INTO metrics_snapshots (
			recorded_at, period_hours,
			total_decisions, allow_count, continue_count, deny_count,
			learned_allows, stop_hook_evals, stop_hook_fires,
			interrupts, user_approved,
			median_uninterrupted_s, p95_uninterrupted_s,
			cache_entries, learned_patterns
		) VALUES (?,?, ?,?,?,?, ?,?,?, ?,?, ?,?, ?,?)`,
		snap.RecordedAt.UTC().Format(time.RFC3339), snap.PeriodHours,
		snap.TotalDecisions, snap.AllowCount, snap.ContinueCount, snap.DenyCount,
		snap.LearnedAllows, snap.StopHookEvals, snap.StopHookFires,
		snap.Interrupts, snap.UserApproved,
		snap.MedianUninterrupted, snap.P95Uninterrupted,
		snap.CacheEntries, snap.LearnedPatterns)
	return err
}

// GetMetricsHistory returns snapshots from the last N days, ordered
// oldest first.
func (s *Store) GetMetricsHistory(days int) ([]MetricsSnapshot, error) {
	cutoff := time.Now().UTC().AddDate(0, 0, -days).Format(time.RFC3339)
	rows, err := s.db.Query(`
		SELECT id, recorded_at, period_hours,
		       total_decisions, allow_count, continue_count, deny_count,
		       learned_allows, stop_hook_evals, stop_hook_fires,
		       interrupts, user_approved,
		       median_uninterrupted_s, p95_uninterrupted_s,
		       cache_entries, learned_patterns
		FROM metrics_snapshots
		WHERE recorded_at >= ?
		ORDER BY recorded_at ASC`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []MetricsSnapshot
	for rows.Next() {
		var m MetricsSnapshot
		var recordedStr string
		if err := rows.Scan(
			&m.ID, &recordedStr, &m.PeriodHours,
			&m.TotalDecisions, &m.AllowCount, &m.ContinueCount, &m.DenyCount,
			&m.LearnedAllows, &m.StopHookEvals, &m.StopHookFires,
			&m.Interrupts, &m.UserApproved,
			&m.MedianUninterrupted, &m.P95Uninterrupted,
			&m.CacheEntries, &m.LearnedPatterns,
		); err != nil {
			return nil, err
		}
		m.RecordedAt = textToTime(recordedStr)
		out = append(out, m)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Helpers: row scanning & time conversion
// ---------------------------------------------------------------------------

// scanner abstracts *sql.Row and *sql.Rows for scanEntry.
type scanner interface {
	Scan(dest ...any) error
}

// scanEntry reads a verdict row into a cache.Entry. Column order must
// match the SELECT in GetVerdict.
func scanEntry(row scanner) (*cache.Entry, error) {
	var e cache.Entry
	var cmdStr, canonical, prog, cwd sql.NullString
	var verdict, tier, reason, provider, model sql.NullString
	var storedStr, expiresStr string
	var verified, disagree int
	var verifiedAtStr sql.NullString
	var vfProvider, vfModel, vfVerdict, vfReason sql.NullString
	var trustedAtStr, trustedReason sql.NullString
	var matchCount, approvalCount int

	if err := row.Scan(
		&cmdStr, &canonical, &prog, &cwd,
		&verdict, &tier, &reason, &provider, &model,
		&storedStr, &expiresStr,
		&verified, &verifiedAtStr,
		&vfProvider, &vfModel, &vfVerdict, &vfReason,
		&disagree,
		&trustedAtStr, &trustedReason,
		&matchCount, &approvalCount,
	); err != nil {
		return nil, err
	}

	e.Command = nullStr(cmdStr)
	e.CanonicalForm = nullStr(canonical)
	e.Program = nullStr(prog)
	e.CWD = nullStr(cwd)
	e.Verdict = cache.Verdict(nullStr(verdict))
	e.Tier = nullStr(tier)
	e.Reason = nullStr(reason)
	e.Provider = nullStr(provider)
	e.Model = nullStr(model)
	e.StoredAt = textToTime(storedStr)
	e.ExpiresAt = textToTime(expiresStr)
	e.Verified = verified != 0
	e.VerifiedAt = textToTime(nullStr(verifiedAtStr))
	e.VerifierProvider = nullStr(vfProvider)
	e.VerifierModel = nullStr(vfModel)
	e.VerifierVerdict = cache.Verdict(nullStr(vfVerdict))
	e.VerifierReason = nullStr(vfReason)
	e.Disagreement = disagree != 0
	e.TrustedAt = textToTime(nullStr(trustedAtStr))
	e.TrustedReason = nullStr(trustedReason)
	e.MatchCount = matchCount
	_ = approvalCount // reserved for future use

	return &e, nil
}

// timeToText formats a time.Time as RFC3339 for storage. Returns empty
// string for zero times (used for nullable columns).
func timeToText(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// textToTime parses an RFC3339 string back to time.Time. Returns zero
// time for empty strings.
func textToTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// boolToInt converts a Go bool to SQLite integer (0/1).
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// nullStr extracts a string from a sql.NullString, returning "" if null.
func nullStr(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return ""
}

// CountPending returns the number of pending approval rows.
func (s *Store) CountPending() (int, error) {
	var n int
	err := s.db.QueryRow("SELECT COUNT(*) FROM pending_approvals").Scan(&n)
	return n, err
}

// CountLearned returns the number of verdict entries with tier='learned'.
func (s *Store) CountLearned() (int, error) {
	var n int
	err := s.db.QueryRow("SELECT COUNT(*) FROM verdicts WHERE tier = 'learned'").Scan(&n)
	return n, err
}

// CountMetrics returns the number of metrics snapshot rows.
func (s *Store) CountMetrics() (int, error) {
	var n int
	err := s.db.QueryRow("SELECT COUNT(*) FROM metrics_snapshots").Scan(&n)
	return n, err
}

// LearnedStats returns the count of learned patterns and the total
// cumulative match_count across all learned entries (auto-allows).
func (s *Store) LearnedStats() (patterns int, autoAllows int, err error) {
	err = s.db.QueryRow(
		"SELECT COUNT(*), COALESCE(SUM(match_count), 0) FROM verdicts WHERE tier = 'learned'",
	).Scan(&patterns, &autoAllows)
	return
}
