package freeze

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/RobinUS2/claude-guard/internal/shellparse"
)

var now = time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)

func mustParse(t *testing.T, cmd string) *shellparse.Parsed {
	t.Helper()
	p, err := shellparse.Parse(cmd)
	if err != nil {
		t.Fatalf("parse %q: %v", cmd, err)
	}
	return p
}

// prodState returns a plain prod freeze covering all repos.
func prodState() *State {
	return &State{Version: 1, FrozenEnvs: []string{"prod"}, Reason: "test freeze", SetBy: "robin", SetAt: now}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "freeze.yaml")
	exp := now.Add(48 * time.Hour)
	in := &State{
		FrozenEnvs: []string{"prod"},
		Projects:   []string{"ai-site-gen"},
		Reason:     "launch prep",
		SetBy:      "robin",
		SetAt:      now,
		ExpiresAt:  &exp,
		Exclude:    []string{"terraform-apply"},
	}
	if err := in.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got == nil {
		t.Fatal("loaded nil")
	}
	if got.Version != SchemaVersion {
		t.Errorf("version = %d, want %d", got.Version, SchemaVersion)
	}
	if got.Reason != "launch prep" || got.SetBy != "robin" {
		t.Errorf("meta not round-tripped: %+v", got)
	}
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(exp) {
		t.Errorf("expires_at = %v, want %v", got.ExpiresAt, exp)
	}
	if len(got.Projects) != 1 || got.Projects[0] != "ai-site-gen" {
		t.Errorf("projects = %v", got.Projects)
	}
	if !got.IsExcluded("terraform-apply") {
		t.Error("exclude not round-tripped")
	}
}

func TestLoadMissingIsNotFrozen(t *testing.T) {
	got, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil || got != nil {
		t.Fatalf("missing file: got (%v, %v), want (nil, nil)", got, err)
	}
}

func TestExpiry(t *testing.T) {
	past := now.Add(-time.Hour)
	s := &State{FrozenEnvs: []string{"prod"}, ExpiresAt: &past}
	if s.active(now) {
		t.Error("expired freeze should be inactive")
	}
	future := now.Add(time.Hour)
	s.ExpiresAt = &future
	if !s.active(now) {
		t.Error("unexpired freeze should be active")
	}
	s.ExpiresAt = nil
	if !s.active(now) {
		t.Error("no-expiry freeze should be active")
	}
}

func TestEnvStateFromVar(t *testing.T) {
	env := func(k string) string {
		if k == "CLAUDE_GUARD_FREEZE" {
			return "prod, staging"
		}
		return ""
	}
	s := EnvState(env)
	if s == nil || !s.FreezesEnv("prod") || !s.FreezesEnv("staging") {
		t.Fatalf("env state = %+v", s)
	}
	if !s.ScopeAll() {
		t.Error("env freeze should be global scope")
	}
	if EnvState(func(string) string { return "" }) != nil {
		t.Error("unset var should yield nil")
	}
}

func TestFreezesEnvWildcard(t *testing.T) {
	s := &State{FrozenEnvs: []string{"all"}}
	for _, e := range []string{"prod", "staging", "dev"} {
		if !s.FreezesEnv(e) {
			t.Errorf("all-freeze should cover %s", e)
		}
	}
}

func TestProjectScoping(t *testing.T) {
	cases := []struct {
		name      string
		projects  []string
		remoteURL string
		want      bool
	}{
		{"global matches anything", nil, "git@github.com:taufinity/felix.git", true},
		{"global matches empty remote", nil, "", true},
		{"scoped matches substring", []string{"ai-site-gen"}, "git@github.com:taufinity/ai-site-gen.git", true},
		{"scoped rejects other repo", []string{"ai-site-gen"}, "git@github.com:taufinity/felix.git", false},
		{"scoped fails open on unknown repo", []string{"ai-site-gen"}, "", false},
		{"scoped case-insensitive", []string{"AI-Site-Gen"}, "https://github.com/taufinity/ai-site-gen", true},
		{"multi-token related repo", []string{"ai-site-gen", "voorpositiviteit"}, "git@github.com:taufinity/voorpositiviteit-templates.git", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &State{FrozenEnvs: []string{"prod"}, Projects: tc.projects}
			if got := s.MatchesProject(tc.remoteURL); got != tc.want {
				t.Errorf("MatchesProject(%q) = %v, want %v", tc.remoteURL, got, tc.want)
			}
		})
	}
}
