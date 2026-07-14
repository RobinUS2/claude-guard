package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/RobinUS2/claude-guard/internal/freeze"
)

func TestParseFlags(t *testing.T) {
	f := parseFlags([]string{"--env", "prod,staging", "--reason=launch prep", "--project", "ai-site-gen"})
	if f["env"] != "prod,staging" {
		t.Errorf("env = %q", f["env"])
	}
	if f["reason"] != "launch prep" {
		t.Errorf("reason = %q", f["reason"])
	}
	if f["project"] != "ai-site-gen" {
		t.Errorf("project = %q", f["project"])
	}
}

func TestValidateEnvs(t *testing.T) {
	if bad := validateEnvs([]string{"prod", "staging", "all"}); bad != "" {
		t.Errorf("valid envs rejected: %q", bad)
	}
	if bad := validateEnvs([]string{"prod", "banana"}); bad != "banana" {
		t.Errorf("bad env = %q, want banana", bad)
	}
}

func TestParseUntil(t *testing.T) {
	if _, err := parseUntil("2026-07-14T18:00"); err != nil {
		t.Errorf("bare local timestamp: %v", err)
	}
	if _, err := parseUntil("2026-07-14T18:00:00+02:00"); err != nil {
		t.Errorf("RFC3339: %v", err)
	}
	if _, err := parseUntil("not-a-date"); err == nil {
		t.Error("expected error for garbage timestamp")
	}
}

func TestParseInclude(t *testing.T) {
	ir, err := parseInclude("make:publish-content", []string{"prod"})
	if err != nil || ir.Program != "make" || ir.Subcommand != "publish-content" {
		t.Fatalf("parseInclude = %+v, %v", ir, err)
	}
	ir2, _ := parseInclude("deployer", []string{"prod"})
	if ir2.Program != "deployer" || ir2.Subcommand != "" {
		t.Errorf("bare program = %+v", ir2)
	}
}

// TestFreezeCLIRoundTrip exercises on → status → off through the real command
// handlers against a temp config dir.
func TestFreezeCLIRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	path := filepath.Join(dir, "claude-guard", "freeze.yaml")

	if code := freezeOn([]string{"--env", "prod", "--project", "ai-site-gen", "--reason", "test"}); code != 0 {
		t.Fatalf("freeze on exit = %d", code)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("freeze file not written: %v", err)
	}
	s, err := freeze.Load(path)
	if err != nil || s == nil || !s.FreezesEnv("prod") {
		t.Fatalf("loaded state = %+v, %v", s, err)
	}
	if len(s.Projects) != 1 || s.Projects[0] != "ai-site-gen" {
		t.Errorf("projects = %v", s.Projects)
	}

	// Lift one env from a two-env freeze.
	_ = freezeOn([]string{"--env", "prod,staging"})
	if code := freezeOff([]string{"--env", "staging"}); code != 0 {
		t.Fatalf("freeze off --env exit = %d", code)
	}
	s, _ = freeze.Load(path)
	if s == nil || s.FreezesEnv("staging") || !s.FreezesEnv("prod") {
		t.Errorf("after lifting staging: %+v", s)
	}

	// Full off removes the file.
	if code := freezeOff(nil); code != 0 {
		t.Fatalf("freeze off exit = %d", code)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("freeze file should be gone, stat err = %v", err)
	}
}

func TestFreezeRejectsBadEnv(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if code := freezeOn([]string{"--env", "banana"}); code == 0 {
		t.Error("freeze on with bad env should fail")
	}
}
