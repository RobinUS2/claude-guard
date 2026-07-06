// Package reporisk loads a user-defined repo risk registry and provides
// per-repo risk level lookups for the smart git push scorer.
//
// Registry file: ~/.config/claude-guard/repo-risk.yaml
// If missing, all repos default to LevelMedium (heuristic scoring only).
package reporisk

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Level is the risk classification for a repository.
type Level string

const (
	LevelHigh   Level = "high"
	LevelMedium Level = "medium"
	LevelLow    Level = "low"
)

// RepoEntry is one entry in the registry YAML.
type RepoEntry struct {
	// RemotePattern is a substring matched against the git remote URL.
	// Case-insensitive. Examples: "github.com/RobinUS2/ai-site-gen",
	// "Brendan-MacKenzie/Mr-Einstein".
	RemotePattern string `yaml:"remote_pattern"`
	Risk          Level  `yaml:"risk"`
	Reason        string `yaml:"reason"`
}

// Registry holds the loaded repo risk entries.
type Registry struct {
	Repos []RepoEntry `yaml:"repos"`
}

// DefaultRegistryPath returns the XDG-style location for the registry file.
func DefaultRegistryPath() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "claude-guard", "repo-risk.yaml")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "claude-guard", "repo-risk.yaml")
}

// Load reads the registry YAML from path. Returns an empty Registry (no
// entries) on missing file so the caller can fall back to heuristic scoring.
func Load(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Registry{}, nil
	}
	if err != nil {
		return nil, err
	}
	var r Registry
	if err := yaml.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Score returns the risk level for a given remote URL.
// Returns LevelMedium when no entry matches (neutral / heuristic scoring).
// Matching is case-insensitive substring on RemotePattern.
//
// Both SSH (git@github.com:org/repo.git) and HTTPS (https://github.com/org/repo)
// URLs are handled — SSH URLs are normalized to HTTPS format before matching.
func (r *Registry) Score(remoteURL string) Level {
	if r == nil || remoteURL == "" {
		return LevelMedium
	}
	urlLower := strings.ToLower(normalizeRemoteURL(remoteURL))
	for _, entry := range r.Repos {
		if strings.Contains(urlLower, strings.ToLower(entry.RemotePattern)) {
			return entry.Risk
		}
	}
	return LevelMedium
}

// NormalizeRemoteURL converts SSH remote URLs to HTTPS form so substring
// matching works consistently regardless of how the user's git remotes are
// configured. Exported so the freeze package can scope a release freeze to a
// project by the same remote-URL matching this registry uses.
// git@github.com:org/repo.git → github.com/org/repo
// https://github.com/org/repo.git → github.com/org/repo
func NormalizeRemoteURL(u string) string { return normalizeRemoteURL(u) }

func normalizeRemoteURL(u string) string {
	u = strings.TrimSuffix(u, ".git")
	// SSH: git@host:org/repo
	if strings.HasPrefix(u, "git@") {
		u = strings.TrimPrefix(u, "git@")
		u = strings.Replace(u, ":", "/", 1)
	}
	// HTTPS: https://host/org/repo or http://host/org/repo
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	return u
}
