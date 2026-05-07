// Package config loads claude-guard configuration and exposes the
// compiled-in default rule set.
//
// Fail-closed design: if the YAML file is missing, malformed, or contains
// unknown fields, Load returns an error AND a safe default config so the
// caller can decide whether to start up (shadow mode) or abort. The
// default rule set is hand-written in Go code, so it is compile-time
// guaranteed to exist. This ensures the deny rules are NEVER silently
// disabled by a typo in YAML.
//
// For v1 (Phase 1), user YAML controls a small set of knobs:
//   - shadow_mode (true/false) — in shadow mode, engine logs verdicts but
//     does not enforce them.
//   - log paths, rotation
//   - LLM toggle + model (disabled by default in Phase 1)
//
// User-defined rules in YAML are a Phase 2 feature and intentionally not
// supported yet.
package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/RobinUS2/claude-guard/internal/rules"
	"gopkg.in/yaml.v3"
)

const SchemaVersion = 1

// Config is the loaded configuration.
type Config struct {
	Version    int    `yaml:"version"`
	ShadowMode bool   `yaml:"shadow_mode"`
	Log        Log    `yaml:"log"`
	LLM        LLM    `yaml:"llm"`
	Cache       Cache       `yaml:"cache"`
	Legacy      Legacy      `yaml:"legacy"`
	DailyBudget DailyBudget `yaml:"daily_budget"`

	// Rules are populated from the compiled-in default set; YAML overrides
	// are intentionally not supported in v1.
	InstantBlock []rules.Rule `yaml:"-"`
	InstantAllow []rules.Rule `yaml:"-"`
}

// Log configures the decision log paths and rotation.
// Dir is the base directory; the three files (decisions, denies, app)
// live inside it as decisions.jsonl, denies.jsonl, app.jsonl.
// Path is the legacy single-file path, kept as a compatibility alias
// for anyone migrating from v0.
type Log struct {
	Dir       string `yaml:"dir"`
	Path      string `yaml:"path"` // legacy alias
	MaxSizeMB int    `yaml:"max_size_mb"`
	KeepFiles int    `yaml:"keep_files"`
}

// LLM toggles the Haiku classifier tier.
type LLM struct {
	Enabled    bool   `yaml:"enabled"`
	Model      string `yaml:"model"`
	APIKeyEnv  string `yaml:"api_key_env"`
	TimeoutMS  int    `yaml:"timeout_ms"`
	MaxTokens  int    `yaml:"max_tokens"`
	RatePerMin int    `yaml:"rate_per_minute"`
}

// Cache configures the file-per-key verdict cache.
type Cache struct {
	Path        string `yaml:"path"`
	TTLApproveD int    `yaml:"ttl_approve_days"`
	TTLBlockD   int    `yaml:"ttl_block_days"`
}

// Legacy points at the migrated allow-list file.
type Legacy struct {
	Path string `yaml:"path"`
}

// DailyBudget caps daily LLM calls to control cost.
type DailyBudget struct {
	LLMCalls          int `yaml:"llm_calls"`
	FileAnalysisCalls int `yaml:"file_analysis_calls"`
}

// Default returns the compiled-in default Config. This is the fallback
// used when the YAML file is missing or unparseable. It contains the
// full deterministic rule set so tier 1/2 are always enforceable.
// DefaultLogDir is the directory where claude-guard writes its logs.
// Using ~/.claude/logs/claude-guard/ keeps the logs next to the Claude Code
// configuration they relate to, so users can find them without hunting
// through XDG paths.
func DefaultLogDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".claude", "logs", "claude-guard")
}

func Default() *Config {
	home, _ := os.UserHomeDir()

	logDir := DefaultLogDir()
	cachePath := filepath.Join(home, ".cache/claude-guard")
	legacyPath := filepath.Join(home, ".config/claude-guard/legacy-patterns.yaml")

	return &Config{
		Version: SchemaVersion,
		// Enforce mode by default. The guard has been built and tested
		// with a 275-case golden corpus, the cache + verifier have been
		// running cleanly in shadow mode, and zero verifier disagreements
		// have been observed on real traffic. Flip back to true via
		// config.yaml for any user who wants to start in shadow mode.
		ShadowMode: false,
		Log: Log{
			Dir:       logDir,
			MaxSizeMB: 50,
			KeepFiles: 3,
		},
		LLM: LLM{
			Enabled:    false, // disabled in Phase 1
			Model:      "claude-haiku-4-5",
			APIKeyEnv:  "ANTHROPIC_API_KEY",
			TimeoutMS:  3000,
			MaxTokens:  200,
			RatePerMin: 30,
		},
		Cache: Cache{
			Path:        cachePath,
			TTLApproveD: 90,
			TTLBlockD:   7,
		},
		Legacy: Legacy{
			Path: legacyPath,
		},
		DailyBudget: DailyBudget{
			LLMCalls:          2000,
			FileAnalysisCalls: 50,
		},
		InstantBlock: DefaultBlockRules(),
		InstantAllow: DefaultAllowRules(),
	}
}

// DefaultConfigPath returns the XDG-style default config file location.
func DefaultConfigPath() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "claude-guard", "config.yaml")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "claude-guard", "config.yaml")
}

// LoadResult carries both the loaded Config and a warning state. When
// the caller gets a non-nil Warning, they should log it and proceed with
// Config — which is always populated (defaults on any failure). The
// binary should continue to run so the user is never blocked by a
// config bug.
type LoadResult struct {
	Config  *Config
	Warning error  // non-nil if defaults were used or the file was malformed
	Source  string // "default", "yaml", or "yaml-with-warnings"
}

// Load reads config from path. If path is empty, the XDG default is used.
// On any failure, Load returns the compiled-in defaults with a non-nil
// Warning so the caller can surface the issue to the user.
//
// Load NEVER returns a nil Config — the invariant is: you always get a
// config to run with.
func Load(path string) LoadResult {
	if path == "" {
		path = DefaultConfigPath()
	}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return LoadResult{
			Config:  Default(),
			Warning: fmt.Errorf("config file not found at %s; using defaults", path),
			Source:  "default",
		}
	}
	if err != nil {
		return LoadResult{
			Config:  Default(),
			Warning: fmt.Errorf("read config %s: %w; using defaults", path, err),
			Source:  "default",
		}
	}

	cfg := Default() // start with defaults so any missing fields are pre-filled
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		// Any decode error — unknown field, type mismatch, malformed YAML —
		// means the user's file is broken. Fall back to compiled defaults.
		return LoadResult{
			Config:  Default(),
			Warning: fmt.Errorf("parse config %s: %w; using defaults", path, err),
			Source:  "default",
		}
	}

	// Re-apply compiled-in rules — they're authoritative, not YAML-driven in v1.
	cfg.InstantBlock = DefaultBlockRules()
	cfg.InstantAllow = DefaultAllowRules()

	if cfg.Version != SchemaVersion {
		return LoadResult{
			Config:  cfg,
			Warning: fmt.Errorf("config %s has version %d, expected %d (partial load, continuing)", path, cfg.Version, SchemaVersion),
			Source:  "yaml-with-warnings",
		}
	}

	return LoadResult{Config: cfg, Source: "yaml"}
}
