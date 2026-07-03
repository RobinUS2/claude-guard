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
	"strings"
	"time"

	"github.com/RobinUS2/claude-guard/internal/cache"

	// Pure-Go SQLite driver — no CGO required.
	_ "modernc.org/sqlite"
)

// schemaVersion is stored in PRAGMA user_version. Bump when the schema
// changes in a way that requires migration.
const schemaVersion = 3

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
	// Flow quality: auto-approves between interrupts (tool-call count, not time).
	// Higher = better flow. Stored since schemaVersion 3.
	MedianAutoApprovesPerInterrupt float64
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

	// Restrict DB files to owner-only. WAL and SHM siblings are created
	// by SQLite on first write; chmod them if they already exist, and rely
	// on the directory mode (0700) to protect them until they are created.
	for _, ext := range []string{"", "-wal", "-shm"} {
		_ = os.Chmod(path+ext, 0o600)
	}
	_ = os.Chmod(filepath.Dir(path), 0o700)

	return s, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// migrate creates tables if they don't exist and updates
// PRAGMA user_version. Additive: each version block runs only when the
// current DB version is below that version, so existing DBs upgrade
// without data loss.
func (s *Store) migrate() error {
	var ver int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&ver); err != nil {
		return fmt.Errorf("read user_version: %w", err)
	}
	if ver >= schemaVersion {
		return nil // already at current schema
	}

	if ver < 1 {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback() //nolint:errcheck — idempotent after Commit; protects against panics
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
			tx.Rollback()
			return fmt.Errorf("create verdicts: %w", err)
		}
		for _, idx := range []string{
			`CREATE INDEX IF NOT EXISTS idx_verdicts_program ON verdicts(program)`,
			`CREATE INDEX IF NOT EXISTS idx_verdicts_expires ON verdicts(expires_at)`,
			`CREATE INDEX IF NOT EXISTS idx_verdicts_canonical ON verdicts(canonical_form) WHERE canonical_form != ''`,
		} {
			if _, err := tx.Exec(idx); err != nil {
				tx.Rollback()
				return fmt.Errorf("create verdict index: %w", err)
			}
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
			tx.Rollback()
			return fmt.Errorf("create pending_approvals: %w", err)
		}
		if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_pending_age ON pending_approvals(prompted_at)`); err != nil {
			tx.Rollback()
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
			tx.Rollback()
			return fmt.Errorf("create metrics_snapshots: %w", err)
		}
		if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_metrics_time ON metrics_snapshots(recorded_at)`); err != nil {
			tx.Rollback()
			return fmt.Errorf("create idx_metrics_time: %w", err)
		}
		if _, err := tx.Exec("PRAGMA user_version = 1"); err != nil {
			tx.Rollback()
			return fmt.Errorf("set user_version=1: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}

	if ver < 2 {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback() //nolint:errcheck — idempotent after Commit; protects against panics
		// --- session_approvals ---
		// Stores commands approved (or explicitly denied) within a session.
		// Key = (session_id, agent_id, canonical_key) — agent_id is empty
		// for the main agent, non-empty for subagents (isolated by default).
		// source: "llm" | "user" | "sequence"
		// verdict: "allow" | "deny"  (deny wins over allow, blocks rest-of-session)
		// expires_at: 8-hour TTL from approved_at (covers a full workday)
		// max 500 rows per (session_id, agent_id) — enforced at write time.
		if _, err := tx.Exec(`
			CREATE TABLE IF NOT EXISTS session_approvals (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				session_id TEXT NOT NULL,
				agent_id TEXT NOT NULL DEFAULT '',
				canonical_key TEXT NOT NULL,
				canonical_form TEXT,
				command TEXT,
				source TEXT NOT NULL,
				verdict TEXT NOT NULL DEFAULT 'allow',
				approved_at TEXT NOT NULL,
				expires_at TEXT NOT NULL,
				UNIQUE(session_id, agent_id, canonical_key)
			)`); err != nil {
			tx.Rollback()
			return fmt.Errorf("create session_approvals: %w", err)
		}
		for _, idx := range []string{
			`CREATE INDEX IF NOT EXISTS idx_sa_lookup ON session_approvals(session_id, agent_id, canonical_key)`,
			`CREATE INDEX IF NOT EXISTS idx_sa_expiry ON session_approvals(expires_at)`,
			`CREATE INDEX IF NOT EXISTS idx_sa_context ON session_approvals(session_id, agent_id, verdict, approved_at)`,
		} {
			if _, err := tx.Exec(idx); err != nil {
				tx.Rollback()
				return fmt.Errorf("create session_approvals index: %w", err)
			}
		}
		// --- session_sequence_progress ---
		// Tracks position within known workflow sequences per session/agent.
		// sequence_idx: index into the compiled workflow sequence table.
		// step_idx: last approved step within that sequence (0-based).
		// last_updated: used for the 10-minute inactivity timeout.
		if _, err := tx.Exec(`
			CREATE TABLE IF NOT EXISTS session_sequence_progress (
				session_id TEXT NOT NULL,
				agent_id TEXT NOT NULL DEFAULT '',
				sequence_idx INTEGER NOT NULL,
				step_idx INTEGER NOT NULL,
				last_updated TEXT NOT NULL,
				PRIMARY KEY (session_id, agent_id, sequence_idx)
			)`); err != nil {
			tx.Rollback()
			return fmt.Errorf("create session_sequence_progress: %w", err)
		}
		if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_ssp_lookup ON session_sequence_progress(session_id, agent_id)`); err != nil {
			tx.Rollback()
			return fmt.Errorf("create idx_ssp_lookup: %w", err)
		}
		if _, err := tx.Exec("PRAGMA user_version = 2"); err != nil {
			tx.Rollback()
			return fmt.Errorf("set user_version=2: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}

	if ver < 3 {
		// Additive: add median_auto_approves_per_interrupt column to metrics_snapshots.
		// ALTER TABLE in SQLite requires DEFAULT for existing rows; NULL is fine here.
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback() //nolint:errcheck — idempotent after Commit
		if _, err := tx.Exec(
			`ALTER TABLE metrics_snapshots ADD COLUMN median_auto_approves_per_interrupt REAL DEFAULT 0`,
		); err != nil {
			// Column may already exist (idempotent re-run) — ignore "duplicate column" errors.
			if !isDuplicateColumnError(err) {
				tx.Rollback()
				return fmt.Errorf("add median_auto_approves_per_interrupt: %w", err)
			}
		}
		if _, err := tx.Exec("PRAGMA user_version = 3"); err != nil {
			tx.Rollback()
			return fmt.Errorf("set user_version=3: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}

	return nil
}

// isDuplicateColumnError returns true when the SQLite error indicates
// the column being added already exists. Used for idempotent ALTER TABLE.
func isDuplicateColumnError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "duplicate column name")
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
			cache_entries, learned_patterns,
			median_auto_approves_per_interrupt
		) VALUES (?,?, ?,?,?,?, ?,?,?, ?,?, ?,?, ?,?, ?)`,
		snap.RecordedAt.UTC().Format(time.RFC3339), snap.PeriodHours,
		snap.TotalDecisions, snap.AllowCount, snap.ContinueCount, snap.DenyCount,
		snap.LearnedAllows, snap.StopHookEvals, snap.StopHookFires,
		snap.Interrupts, snap.UserApproved,
		snap.MedianUninterrupted, snap.P95Uninterrupted,
		snap.CacheEntries, snap.LearnedPatterns,
		snap.MedianAutoApprovesPerInterrupt)
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
		       cache_entries, learned_patterns,
		       COALESCE(median_auto_approves_per_interrupt, 0)
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
			&m.MedianAutoApprovesPerInterrupt,
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

// ---------------------------------------------------------------------------
// Session approvals
// ---------------------------------------------------------------------------

const sessionApprovalTTL = 8 * time.Hour
const sessionApprovalCap = 500 // max rows per (session_id, agent_id)

// WriteSessionApproval upserts an allow entry into session_approvals.
// If the table already holds a deny entry for this key, the deny wins and
// the write is silently ignored. The check-then-update is performed
// atomically via ON CONFLICT … WHERE to eliminate the TOCTOU window that
// existed in the previous SELECT-then-INSERT-OR-REPLACE implementation.
func (s *Store) WriteSessionApproval(sessionID, agentID, canonicalKey, canonicalForm, command, source string) error {
	if sessionID == "" || canonicalKey == "" {
		return nil
	}
	now := time.Now().UTC()
	expires := now.Add(sessionApprovalTTL)
	// The WHERE clause on DO UPDATE prevents overwriting a deny verdict.
	// If the row is a deny, the UPDATE is skipped and the row is unchanged.
	_, err := s.db.Exec(`
		INSERT INTO session_approvals
			(session_id, agent_id, canonical_key, canonical_form, command, source, verdict, approved_at, expires_at)
		VALUES (?,?,?,?,?,?,'allow',?,?)
		ON CONFLICT(session_id, agent_id, canonical_key)
		DO UPDATE SET
			canonical_form = excluded.canonical_form,
			command        = excluded.command,
			source         = excluded.source,
			approved_at    = excluded.approved_at,
			expires_at     = excluded.expires_at
		WHERE session_approvals.verdict != 'deny'`,
		sessionID, agentID, canonicalKey, canonicalForm, command, source,
		now.Format(time.RFC3339), expires.Format(time.RFC3339))
	if err != nil {
		return err
	}
	s.enforceSessionCap(sessionID, agentID)
	return nil
}

// WriteSessionDeny records an explicit deny for a canonical key, preventing
// session-cache from auto-approving that pattern for the rest of the session.
// A deny entry overrides any existing allow entry.
func (s *Store) WriteSessionDeny(sessionID, agentID, canonicalKey string) error {
	if sessionID == "" || canonicalKey == "" {
		return nil
	}
	now := time.Now().UTC()
	expires := now.Add(sessionApprovalTTL)
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO session_approvals
			(session_id, agent_id, canonical_key, canonical_form, command, source, verdict, approved_at, expires_at)
		VALUES (?,?,?,'','','user-deny','deny',?,?)`,
		sessionID, agentID, canonicalKey,
		now.Format(time.RFC3339), expires.Format(time.RFC3339))
	return err
}

// ReadSessionApproval checks whether a canonical key is approved for this
// session/agent. Returns "allow", "deny", or "" (miss / expired).
func (s *Store) ReadSessionApproval(sessionID, agentID, canonicalKey string) string {
	if sessionID == "" || canonicalKey == "" {
		return ""
	}
	var verdict, expiresStr string
	err := s.db.QueryRow(`
		SELECT verdict, expires_at FROM session_approvals
		WHERE session_id=? AND agent_id=? AND canonical_key=?`,
		sessionID, agentID, canonicalKey,
	).Scan(&verdict, &expiresStr)
	if err != nil {
		return ""
	}
	if exp := textToTime(expiresStr); !exp.IsZero() && time.Now().After(exp) {
		// Expired — delete on read.
		_, _ = s.db.Exec(
			`DELETE FROM session_approvals WHERE session_id=? AND agent_id=? AND canonical_key=?`,
			sessionID, agentID, canonicalKey)
		return ""
	}
	return verdict
}

// GetSessionContext returns up to limit recently-approved canonical forms for
// the session/agent, ordered newest-first. Used by the LLM tier for context
// injection. Only returns "allow" entries; deny entries are excluded.
func (s *Store) GetSessionContext(sessionID, agentID string, limit int) []string {
	if sessionID == "" || limit <= 0 {
		return nil
	}
	rows, err := s.db.Query(`
		SELECT canonical_form FROM session_approvals
		WHERE session_id=? AND agent_id=? AND verdict='allow'
		  AND (expires_at='' OR expires_at > ?)
		ORDER BY approved_at DESC LIMIT ?`,
		sessionID, agentID, time.Now().UTC().Format(time.RFC3339), limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var form string
		if err := rows.Scan(&form); err == nil && form != "" {
			out = append(out, form)
		}
	}
	return out
}

// CleanStaleSessionApprovals deletes expired session_approvals rows.
// Call periodically (e.g. at process start) to prevent unbounded growth.
func (s *Store) CleanStaleSessionApprovals() error {
	_, err := s.db.Exec(
		`DELETE FROM session_approvals WHERE expires_at != '' AND expires_at < ?`,
		time.Now().UTC().Format(time.RFC3339))
	return err
}

// enforceSessionCap evicts the oldest allow rows when the allow-only count
// for a (session_id, agent_id) pair exceeds sessionApprovalCap. Deny rows
// are never evicted — an attacker must not be able to push a deny out of
// the cache by flooding the approval table with allows. Best-effort.
func (s *Store) enforceSessionCap(sessionID, agentID string) {
	var count int
	if err := s.db.QueryRow(
		`SELECT COUNT(*) FROM session_approvals WHERE session_id=? AND agent_id=? AND verdict='allow'`,
		sessionID, agentID,
	).Scan(&count); err != nil || count <= sessionApprovalCap {
		return
	}
	excess := count - sessionApprovalCap
	_, _ = s.db.Exec(`
		DELETE FROM session_approvals WHERE id IN (
			SELECT id FROM session_approvals
			WHERE session_id=? AND agent_id=? AND verdict='allow'
			ORDER BY approved_at ASC LIMIT ?
		)`, sessionID, agentID, excess)
}

// ---------------------------------------------------------------------------
// Session sequence progress
// ---------------------------------------------------------------------------

// WriteSequenceProgress upserts progress for a workflow sequence within a session.
func (s *Store) WriteSequenceProgress(sessionID, agentID string, sequenceIdx, stepIdx int) error {
	if sessionID == "" {
		return nil
	}
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO session_sequence_progress
			(session_id, agent_id, sequence_idx, step_idx, last_updated)
		VALUES (?,?,?,?,?)`,
		sessionID, agentID, sequenceIdx, stepIdx,
		time.Now().UTC().Format(time.RFC3339))
	return err
}

// ReadSequenceProgress returns (stepIdx, lastUpdated, found) for a sequence.
func (s *Store) ReadSequenceProgress(sessionID, agentID string, sequenceIdx int) (stepIdx int, lastUpdated time.Time, found bool) {
	var updStr string
	err := s.db.QueryRow(`
		SELECT step_idx, last_updated FROM session_sequence_progress
		WHERE session_id=? AND agent_id=? AND sequence_idx=?`,
		sessionID, agentID, sequenceIdx,
	).Scan(&stepIdx, &updStr)
	if err != nil {
		return 0, time.Time{}, false
	}
	return stepIdx, textToTime(updStr), true
}

// DeleteSequenceProgress removes progress for a sequence (e.g. after timeout).
func (s *Store) DeleteSequenceProgress(sessionID, agentID string, sequenceIdx int) error {
	_, err := s.db.Exec(`
		DELETE FROM session_sequence_progress
		WHERE session_id=? AND agent_id=? AND sequence_idx=?`,
		sessionID, agentID, sequenceIdx)
	return err
}

// CleanStaleSequences removes sequence progress records older than maxAge.
func (s *Store) CleanStaleSequences(maxAge time.Duration) error {
	cutoff := time.Now().UTC().Add(-maxAge).Format(time.RFC3339)
	_, err := s.db.Exec(
		`DELETE FROM session_sequence_progress WHERE last_updated < ?`, cutoff)
	return err
}
