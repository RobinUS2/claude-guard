package reporisk

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_MissingFile(t *testing.T) {
	r, err := Load(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	if err != nil {
		t.Fatalf("Load missing file: %v", err)
	}
	if len(r.Repos) != 0 {
		t.Errorf("expected empty registry, got %d entries", len(r.Repos))
	}
}

func TestLoad_ValidYAML(t *testing.T) {
	yaml := `repos:
  - remote_pattern: "github.com/example/production"
    risk: high
    reason: "customer-facing"
  - remote_pattern: "github.com/example/scripts"
    risk: low
    reason: "personal tooling"
`
	path := filepath.Join(t.TempDir(), "repo-risk.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(r.Repos) != 2 {
		t.Errorf("expected 2 entries, got %d", len(r.Repos))
	}
}

func TestScore_ExactMatch(t *testing.T) {
	r := &Registry{Repos: []RepoEntry{
		{RemotePattern: "github.com/RobinUS2/ai-site-gen", Risk: LevelHigh},
		{RemotePattern: "github.com/RobinUS2/cto-as-a-service", Risk: LevelLow},
	}}

	if got := r.Score("git@github.com:RobinUS2/ai-site-gen.git"); got != LevelHigh {
		t.Errorf("ai-site-gen: got %q, want high", got)
	}
	if got := r.Score("https://github.com/RobinUS2/cto-as-a-service"); got != LevelLow {
		t.Errorf("cto-as-a-service: got %q, want low", got)
	}
}

func TestScore_CaseInsensitive(t *testing.T) {
	r := &Registry{Repos: []RepoEntry{
		{RemotePattern: "Github.Com/Robin/Prod", Risk: LevelHigh},
	}}
	if got := r.Score("https://github.com/robin/prod"); got != LevelHigh {
		t.Errorf("case-insensitive match failed: got %q", got)
	}
}

func TestScore_NoMatch_DefaultsMedium(t *testing.T) {
	r := &Registry{Repos: []RepoEntry{
		{RemotePattern: "github.com/someone/specific", Risk: LevelHigh},
	}}
	if got := r.Score("https://github.com/other/repo"); got != LevelMedium {
		t.Errorf("no-match: got %q, want medium", got)
	}
}

func TestScore_NilRegistry(t *testing.T) {
	var r *Registry
	if got := r.Score("anything"); got != LevelMedium {
		t.Errorf("nil registry: got %q, want medium", got)
	}
}

func TestScore_EmptyURL(t *testing.T) {
	r := &Registry{}
	if got := r.Score(""); got != LevelMedium {
		t.Errorf("empty URL: got %q, want medium", got)
	}
}
