// Package freeze implements an operator-toggled release freeze for
// claude-guard. When a freeze is active, deploy/release commands (the
// catalog) are blocked (high confidence) or routed to a user prompt
// (ambiguous) in Tier 1 — the one tier the approve-only LLM cannot override.
//
// Three orthogonal concepts live here:
//
//   - State   (this file) — is a freeze on, for which envs, which projects,
//     why, until when. Persisted as a single YAML file a human can read,
//     edit, and delete to unfreeze.
//   - Catalog (catalog.go) — which command shapes count as a release, each
//     tagged with the env(s) it touches and a confidence (deny vs ask).
//   - Evaluate (evaluate.go) — given a parsed command, the current repo, and
//     the active state(s), decide Pass / Deny / Ask.
//
// The engine loads State once per hook process (each Bash call spawns a fresh
// `claude-guard decide`) and injects it; tests inject a State directly. Nothing
// in this package reads a hardcoded path during evaluation, and nothing calls
// time.Now() — callers pass `now` so expiry math is deterministic under test.
package freeze

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/RobinUS2/claude-guard/internal/reporisk"
)

// SchemaVersion is written into every freeze.yaml. Bump on breaking changes.
const SchemaVersion = 1

// EnvAll is the wildcard env — a freeze that lists it matches every catalog
// entry regardless of the entry's own env tag.
const EnvAll = "all"

// KnownEnvs are the environments the CLI validates --env against. `all` is
// accepted too but is not a real deploy target — it's the wildcard.
var KnownEnvs = []string{"prod", "staging", "dev"}

// IncludeRule is an ad-hoc extra command armed for a single freeze (the
// `--include program:subcommand` flag). It only ever ADDS a deny, so it cannot
// be a security regression — the worst case is over-blocking one command.
type IncludeRule struct {
	Program    string   `yaml:"program"`
	Subcommand string   `yaml:"subcommand"`
	Envs       []string `yaml:"envs,omitempty"` // empty → prod
}

// State is the persisted freeze. A nil *State means "not frozen".
type State struct {
	Version    int           `yaml:"version"`
	FrozenEnvs []string      `yaml:"frozen_envs"`
	Projects   []string      `yaml:"projects,omitempty"` // remote-URL substrings; empty = ALL repos (global)
	Reason     string        `yaml:"reason,omitempty"`
	SetBy      string        `yaml:"set_by,omitempty"`
	SetAt      time.Time     `yaml:"set_at,omitempty"`
	ExpiresAt  *time.Time    `yaml:"expires_at,omitempty"`
	Include    []IncludeRule `yaml:"include,omitempty"`
	Exclude    []string      `yaml:"exclude,omitempty"` // catalog rule names carved out
}

// DefaultPath returns ~/.config/claude-guard/freeze.yaml (honoring
// XDG_CONFIG_HOME to match the rest of claude-guard's config resolution).
func DefaultPath() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "claude-guard", "freeze.yaml")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".claude-guard-freeze.yaml"
	}
	return filepath.Join(home, ".config", "claude-guard", "freeze.yaml")
}

// Load reads the freeze file. A missing file returns (nil, nil) — not frozen,
// not an error. A malformed file returns (nil, err) so the caller can WARN;
// callers MUST treat a load error as "not frozen" (fail-open), never as a
// broken guard.
func Load(path string) (*State, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read freeze file: %w", err)
	}
	var s State
	if err := yaml.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("parse freeze file: %w", err)
	}
	if len(s.FrozenEnvs) == 0 {
		// A file with no envs is a no-op freeze; treat as not frozen.
		return nil, nil
	}
	return &s, nil
}

// Save atomically writes the state to path (temp file + rename), creating the
// parent directory if needed. Atomicity means a concurrent reader sees either
// the old file or the new one, never a partial write.
func (s *State) Save(path string) error {
	if s.Version == 0 {
		s.Version = SchemaVersion
	}
	b, err := yaml.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshal freeze: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".freeze-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}
	return nil
}

// EnvState builds a synthetic global freeze from the CLAUDE_GUARD_FREEZE env
// var (comma-separated env list), or nil if unset/empty. Scoped to no
// project (global) — it's meant to freeze a single shell's agents. Returns nil
// when the var is unset so callers can cheaply skip it.
func EnvState(getenv func(string) string) *State {
	raw := strings.TrimSpace(getenv("CLAUDE_GUARD_FREEZE"))
	if raw == "" {
		return nil
	}
	envs := splitList(raw)
	if len(envs) == 0 {
		return nil
	}
	return &State{
		Version:    SchemaVersion,
		FrozenEnvs: envs,
		Reason:     "CLAUDE_GUARD_FREEZE env var (session-scoped)",
		SetBy:      "env",
	}
}

// Sources returns the active (non-expired, non-empty) freeze states from the
// file and the env var, in priority order. Load errors on the file are
// swallowed here (fail-open) — use Load directly if you need to surface them.
func Sources(path string, getenv func(string) string, now time.Time) []*State {
	var out []*State
	if fs, err := Load(path); err == nil && fs.active(now) {
		out = append(out, fs)
	}
	if es := EnvState(getenv); es.active(now) {
		out = append(out, es)
	}
	return out
}

// Expired reports whether the freeze has an expiry that has passed.
func (s *State) Expired(now time.Time) bool {
	return s != nil && s.ExpiresAt != nil && now.After(*s.ExpiresAt)
}

// active reports whether the freeze is on right now (has envs, not expired).
func (s *State) active(now time.Time) bool {
	return s != nil && len(s.FrozenEnvs) > 0 && !s.Expired(now)
}

// Active is the exported form of active.
func (s *State) Active(now time.Time) bool { return s.active(now) }

// FreezesEnv reports whether env is frozen by this state (accounting for the
// `all` wildcard). Does not consider expiry — callers filter via Sources/active.
func (s *State) FreezesEnv(env string) bool {
	if s == nil {
		return false
	}
	for _, e := range s.FrozenEnvs {
		if e == EnvAll || strings.EqualFold(e, env) {
			return true
		}
	}
	return false
}

// ScopeAll reports whether the freeze covers every repo (no project scoping).
func (s *State) ScopeAll() bool { return s == nil || len(s.Projects) == 0 }

// MatchesProject reports whether a command whose repo has the given origin
// remote URL is within this freeze's project scope. A global freeze (no
// projects) matches everything. A project-scoped freeze fails open when the
// repo can't be identified (empty remoteURL) — we can't prove it's the frozen
// project, so we don't block it.
func (s *State) MatchesProject(remoteURL string) bool {
	if s.ScopeAll() {
		return true
	}
	if remoteURL == "" {
		return false
	}
	norm := strings.ToLower(reporisk.NormalizeRemoteURL(remoteURL))
	for _, pat := range s.Projects {
		pat = strings.ToLower(strings.TrimSpace(pat))
		if pat != "" && strings.Contains(norm, pat) {
			return true
		}
	}
	return false
}

// IsExcluded reports whether a catalog rule name is carved out of this freeze.
func (s *State) IsExcluded(ruleName string) bool {
	for _, e := range s.Exclude {
		if strings.EqualFold(e, ruleName) {
			return true
		}
	}
	return false
}

// ScopeLabel is a short human description of the project scope for status/logs.
func (s *State) ScopeLabel() string {
	if s.ScopeAll() {
		return "all repos"
	}
	return strings.Join(s.Projects, ",")
}

// splitList splits a comma/space separated list into trimmed, deduped tokens.
func splitList(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' })
	seen := map[string]bool{}
	var out []string
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}
