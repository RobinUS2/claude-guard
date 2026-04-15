package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefault(t *testing.T) {
	cfg := Default()
	if cfg == nil {
		t.Fatal("Default returned nil")
	}
	if !cfg.ShadowMode {
		t.Error("default should have shadow_mode=true")
	}
	if cfg.LLM.Enabled {
		t.Error("default should have LLM disabled in Phase 1")
	}
	if len(cfg.InstantBlock) == 0 {
		t.Error("default should have block rules")
	}
	if len(cfg.InstantAllow) == 0 {
		t.Error("default should have allow rules")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	result := Load("/nonexistent/path/config.yaml")
	if result.Config == nil {
		t.Fatal("Config should never be nil")
	}
	if result.Warning == nil {
		t.Error("missing file should produce a warning")
	}
	if result.Source != "default" {
		t.Errorf("Source = %q, want default", result.Source)
	}
	// Must still have compiled-in rules.
	if len(result.Config.InstantBlock) == 0 {
		t.Error("fallback should still have block rules")
	}
}

func TestLoad_ValidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yamlContent := `version: 1
shadow_mode: false
log:
  path: /tmp/test-guard.log
  max_size_bytes: 1048576
  keep_files: 2
llm:
  enabled: true
  model: claude-haiku-4-5
  timeout_ms: 2000
`
	if err := os.WriteFile(path, []byte(yamlContent), 0o644); err != nil {
		t.Fatal(err)
	}

	result := Load(path)
	if result.Warning != nil {
		t.Errorf("unexpected warning: %v", result.Warning)
	}
	if result.Source != "yaml" {
		t.Errorf("Source = %q, want yaml", result.Source)
	}
	if result.Config.ShadowMode {
		t.Error("shadow_mode should be overridden to false")
	}
	if !result.Config.LLM.Enabled {
		t.Error("LLM should be enabled")
	}
	if result.Config.Log.Path != "/tmp/test-guard.log" {
		t.Errorf("Log.Path = %q", result.Config.Log.Path)
	}
	// Compiled-in rules must still be present.
	if len(result.Config.InstantBlock) == 0 {
		t.Error("block rules should still be present after YAML merge")
	}
}

func TestLoad_UnknownFieldRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	// "shadow_mod" is a typo — with KnownFields(true) the decoder rejects it.
	yamlContent := `version: 1
shadow_mod: false
`
	if err := os.WriteFile(path, []byte(yamlContent), 0o644); err != nil {
		t.Fatal(err)
	}

	result := Load(path)
	if result.Warning == nil {
		t.Error("unknown field should produce a warning")
	}
	// Crucially, we still get a Config with default rules — fail-closed on rules.
	if len(result.Config.InstantBlock) == 0 {
		t.Error("default block rules must remain after a config error")
	}
	// Shadow mode should be the default (true) since the YAML failed to parse.
	if !result.Config.ShadowMode {
		t.Error("after YAML parse failure, ShadowMode should be the safe default (true)")
	}
}

func TestLoad_MalformedYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("this: is: not valid: yaml {{{"), 0o644); err != nil {
		t.Fatal(err)
	}

	result := Load(path)
	if result.Warning == nil {
		t.Error("malformed YAML should produce a warning")
	}
	if len(result.Config.InstantBlock) == 0 {
		t.Error("default rules must remain after parse failure")
	}
}

func TestDefaultConfigPath(t *testing.T) {
	// Save+restore env to avoid polluting other tests.
	oldXDG := os.Getenv("XDG_CONFIG_HOME")
	defer os.Setenv("XDG_CONFIG_HOME", oldXDG)

	os.Setenv("XDG_CONFIG_HOME", "/tmp/xdg-home")
	if got := DefaultConfigPath(); got != "/tmp/xdg-home/claude-guard/config.yaml" {
		t.Errorf("DefaultConfigPath() = %q", got)
	}

	os.Unsetenv("XDG_CONFIG_HOME")
	got := DefaultConfigPath()
	if got == "" || got == "claude-guard/config.yaml" {
		t.Errorf("DefaultConfigPath() = %q (should fall back to ~/.config/...)", got)
	}
}

func TestDefaultBlockRules_Sanity(t *testing.T) {
	rules := DefaultBlockRules()
	// Must include the load-bearing rules.
	wantNames := []string{
		"sudo-anything",
		"rm-rf-system",
		"curl-pipe-sh",
		"procsub-to-shell",
		"git-force-push-protected",
		"ssh-private-key",
	}
	names := map[string]bool{}
	for _, r := range rules {
		names[r.Name()] = true
	}
	for _, want := range wantNames {
		if !names[want] {
			t.Errorf("missing default block rule %q", want)
		}
	}
}

func TestDefaultAllowRules_Sanity(t *testing.T) {
	rules := DefaultAllowRules()
	wantNames := []string{
		"posix-readonly",
		"git-readonly",
		"terraform-readonly",
		"kubectl-readonly",
	}
	names := map[string]bool{}
	for _, r := range rules {
		names[r.Name()] = true
	}
	for _, want := range wantNames {
		if !names[want] {
			t.Errorf("missing default allow rule %q", want)
		}
	}
}
