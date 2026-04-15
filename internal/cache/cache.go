// Package cache implements tier 3 — a file-per-key verdict cache for
// the LLM tier. Tier 1 and tier 2 are already <100µs deterministic
// matchers, so they don't benefit from caching. Tier 4 (LLM) is the
// only tier slow enough to be worth caching, and it's also the only
// tier whose verdict can legitimately change over time (model drift,
// prompt updates, config rule changes).
//
// Layout: <root>/<first2chars>/<full-sha256>.json. Sharding by the
// first two hex characters keeps any single directory under ~1k files
// even with tens of thousands of cached commands.
//
// Concurrency: writes are atomic (tmp + rename). Reads use os.ReadFile
// and tolerate the file disappearing mid-read. Two concurrent guards
// can race on the same key — the loser's write is harmlessly
// overwritten by the next successful classify call.
//
// Expiry: an entry's TTL is encoded in the file content (ExpiresAt).
// On read, expired entries are evicted (deleted) so the directory
// doesn't grow unbounded.
//
// Cache key composition is left to the caller because it depends on
// engine state (config rules hash, prompt version) the cache package
// does not know about. KeyInputs is the recommended starting point.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Verdict is what the cache stores. We deliberately don't reuse
// engine.Verdict / llm.Verdict types to keep the cache package free of
// cross-package coupling — callers translate at the boundary.
type Verdict string

const (
	// VerdictAllow means the engine should auto-approve.
	VerdictAllow Verdict = "allow"
	// VerdictDeny is reserved for future use; the LLM tier currently
	// never produces deny entries (approve-only), but deterministic
	// rules might cache here later.
	VerdictDeny Verdict = "deny"
)

// Entry is the on-disk shape of a cached verdict.
type Entry struct {
	// Original verdict from the fast classifier.
	Verdict   Verdict   `json:"verdict"`
	Reason    string    `json:"reason,omitempty"`
	Tier      string    `json:"tier"`
	Provider  string    `json:"provider,omitempty"`
	Model     string    `json:"model,omitempty"`
	StoredAt  time.Time `json:"stored_at"`
	ExpiresAt time.Time `json:"expires_at"`

	// Verification fields — populated asynchronously by a slower model
	// (typically the cross-provider one). Verified means "another model
	// has reviewed this entry"; Disagreement means "the verifier said
	// the fast verdict was wrong".
	//
	// When Disagreement is true, EffectiveVerdict() returns the verifier's
	// verdict, which means the next cache hit on this entry will return
	// the verifier's stronger judgment instead of the fast one.
	Verified         bool      `json:"verified,omitempty"`
	VerifiedAt       time.Time `json:"verified_at,omitempty"`
	VerifierProvider string    `json:"verifier_provider,omitempty"`
	VerifierModel    string    `json:"verifier_model,omitempty"`
	VerifierVerdict  Verdict   `json:"verifier_verdict,omitempty"`
	VerifierReason   string    `json:"verifier_reason,omitempty"`
	Disagreement     bool      `json:"disagreement,omitempty"`
}

// EffectiveVerdict returns the verdict that should be applied to a
// cache hit. If a verifier disagreed with the fast classifier, the
// verifier's verdict wins — that's the whole point of cross-provider
// verification: the second opinion is a stronger signal.
func (e *Entry) EffectiveVerdict() Verdict {
	if e.Disagreement && e.VerifierVerdict != "" {
		return e.VerifierVerdict
	}
	return e.Verdict
}

// Expired reports whether the entry has passed its expiry deadline.
func (e *Entry) Expired(now time.Time) bool {
	return !e.ExpiresAt.IsZero() && now.After(e.ExpiresAt)
}

// KeyInputs is what the engine passes when computing a cache key.
// All fields participate in the hash. Adding a field in the future
// must invalidate existing entries — bump SchemaVersion.
type KeyInputs struct {
	Tool          string
	Command       string
	CWD           string
	GitBranch     string
	PromptVersion string // sha256 of the classifier prompt
	RulesHash     string // sha256 of the active rule set
}

// SchemaVersion is part of every cache key. Bump it when the KeyInputs
// shape changes in a way that should invalidate existing entries.
//
// v2: added scope-aware keys (global key strips cwd + branch).
const SchemaVersion = "2"

// Key returns the deterministic project-scoped cache key for these
// inputs. Project keys include cwd + git_branch — they apply only to
// the same project.
func Key(in KeyInputs) string {
	return keyWithDimensions(in, true)
}

// GlobalKey returns the deterministic global-scoped cache key. Global
// keys strip cwd + git_branch — they apply to a command anywhere on
// disk. Used for commands the LLM judged as universally safe (`git
// status`, `ls`, `cat /etc/hosts`).
func GlobalKey(in KeyInputs) string {
	return keyWithDimensions(in, false)
}

func keyWithDimensions(in KeyInputs, includeProject bool) string {
	var b strings.Builder
	b.WriteString(SchemaVersion)
	b.WriteByte('\x00')
	if includeProject {
		b.WriteString("p\x00")
	} else {
		b.WriteString("g\x00")
	}
	b.WriteString(in.Tool)
	b.WriteByte('\x00')
	b.WriteString(in.Command)
	b.WriteByte('\x00')
	if includeProject {
		b.WriteString(in.CWD)
		b.WriteByte('\x00')
		b.WriteString(in.GitBranch)
		b.WriteByte('\x00')
	}
	b.WriteString(in.PromptVersion)
	b.WriteByte('\x00')
	b.WriteString(in.RulesHash)

	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// Cache is a file-per-key verdict store rooted at Dir.
type Cache struct {
	Dir string
	// now is injectable for testing.
	now func() time.Time
}

// New returns a Cache rooted at dir. The directory is created on first
// write; nothing is created on construction.
func New(dir string) *Cache {
	return &Cache{Dir: dir, now: time.Now}
}

// Get fetches a non-expired entry by key. Returns (nil, false) on
// miss, expired entry, or any read error. Expired entries are evicted.
func (c *Cache) Get(key string) (*Entry, bool) {
	path := c.path(key)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false
	}
	if err != nil {
		return nil, false
	}
	var e Entry
	if err := json.Unmarshal(data, &e); err != nil {
		// Corrupt entry — best-effort delete and report miss.
		_ = os.Remove(path)
		return nil, false
	}
	if e.Expired(c.now()) {
		_ = os.Remove(path)
		return nil, false
	}
	return &e, true
}

// Put writes an entry atomically. ttl <= 0 means "never expire", which
// translates to ExpiresAt being zero on disk.
func (c *Cache) Put(key string, e Entry, ttl time.Duration) error {
	if e.StoredAt.IsZero() {
		e.StoredAt = c.now()
	}
	if ttl > 0 {
		e.ExpiresAt = e.StoredAt.Add(ttl)
	}

	data, err := json.MarshalIndent(&e, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal entry: %w", err)
	}
	path := c.path(key)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir cache shard: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename tmp: %w", err)
	}
	return nil
}

// Delete removes an entry. Idempotent — non-existent keys are not an error.
func (c *Cache) Delete(key string) error {
	if err := os.Remove(c.path(key)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// VerifierResult carries a verifier's review of an existing cache entry.
type VerifierResult struct {
	Provider string
	Model    string
	Verdict  Verdict // safe / unsafe / unsure
	Reason   string
}

// Verify updates an existing cache entry with the verifier's review.
// If the verifier disagrees with the original verdict (e.g. fast said
// allow, verifier said deny), the entry is marked Disagreement=true so
// future cache hits return the verifier's verdict instead. Returns
// (true, nil) if the entry was found and updated, (false, nil) if it
// was a miss, and (false, err) on I/O failure.
func (c *Cache) Verify(key string, result VerifierResult) (bool, error) {
	entry, hit := c.Get(key)
	if !hit {
		return false, nil
	}
	entry.Verified = true
	entry.VerifiedAt = c.now()
	entry.VerifierProvider = result.Provider
	entry.VerifierModel = result.Model
	entry.VerifierVerdict = result.Verdict
	entry.VerifierReason = result.Reason
	entry.Disagreement = result.Verdict != entry.Verdict

	// Preserve the original ExpiresAt — verification doesn't change the
	// TTL of the entry. If the user wants disagreed entries to expire
	// faster, that's a future config knob.
	ttl := time.Duration(0)
	if !entry.ExpiresAt.IsZero() {
		ttl = entry.ExpiresAt.Sub(entry.StoredAt)
	}
	if err := c.Put(key, *entry, ttl); err != nil {
		return false, err
	}
	return true, nil
}

// Stats describes the on-disk state of the cache.
type Stats struct {
	Entries     int
	Verified    int // entries reviewed by a verifier (any verdict)
	Disagree    int // entries where verifier disagreed with original
	ExpiredHits int
	BytesOnDisk int64
	Shards      int
	Newest      time.Time
	Oldest      time.Time
}

// Stats walks the cache directory once and returns a snapshot. Used
// by doctor / stats subcommands. Cheap enough to call interactively
// (a few thousand small files).
func (c *Cache) Stats() (Stats, error) {
	var s Stats
	if _, err := os.Stat(c.Dir); errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	now := c.now()
	shardSet := map[string]struct{}{}
	err := filepath.Walk(c.Dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if info.IsDir() {
			if path != c.Dir {
				shardSet[path] = struct{}{}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".json") {
			return nil
		}
		s.Entries++
		s.BytesOnDisk += info.Size()
		mt := info.ModTime()
		if s.Newest.IsZero() || mt.After(s.Newest) {
			s.Newest = mt
		}
		if s.Oldest.IsZero() || mt.Before(s.Oldest) {
			s.Oldest = mt
		}
		// Open the file to count verified / disagree / expired.
		if data, err := os.ReadFile(path); err == nil {
			var e Entry
			if json.Unmarshal(data, &e) == nil {
				if e.Expired(now) {
					s.ExpiredHits++
				}
				if e.Verified {
					s.Verified++
				}
				if e.Disagreement {
					s.Disagree++
				}
			}
		}
		return nil
	})
	if err != nil {
		return s, err
	}
	s.Shards = len(shardSet)
	return s, nil
}

// Sweep deletes all expired entries. Called by `claude-guard cache prune`
// or as a periodic maintenance operation.
func (c *Cache) Sweep() (deleted int, err error) {
	if _, err := os.Stat(c.Dir); errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	now := c.now()
	walkErr := filepath.Walk(c.Dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var e Entry
		if json.Unmarshal(data, &e) != nil {
			// corrupt → delete
			if os.Remove(path) == nil {
				deleted++
			}
			return nil
		}
		if e.Expired(now) {
			if os.Remove(path) == nil {
				deleted++
			}
		}
		return nil
	})
	return deleted, walkErr
}

// path builds the on-disk path for a given key. Files are sharded by
// the first two hex characters to keep any one directory bounded.
func (c *Cache) path(key string) string {
	if len(key) < 2 {
		return filepath.Join(c.Dir, key+".json")
	}
	return filepath.Join(c.Dir, key[:2], key+".json")
}

// HashString returns the hex SHA-256 of a string. Useful for callers
// computing PromptVersion / RulesHash.
func HashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// HashStrings returns the hex SHA-256 of a sorted list of strings.
// Order-independent — useful for hashing a rule set without depending
// on the iteration order of the underlying slice.
func HashStrings(items []string) string {
	sorted := append([]string(nil), items...)
	sort.Strings(sorted)
	var b strings.Builder
	for _, s := range sorted {
		b.WriteString(s)
		b.WriteByte('\n')
	}
	return HashString(b.String())
}
