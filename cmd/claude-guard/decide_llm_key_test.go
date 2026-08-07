package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeTokenVaultHome creates a fake ~/bin/token-vault so llm.TokenVaultInstalled()
// resolves true via the real HOME-based lookup, without touching Robin's actual vault.
func fakeTokenVaultHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	binDir := filepath.Join(home, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "token-vault"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatalf("write fake token-vault: %v", err)
	}
	t.Setenv("HOME", home)
	return home
}

func TestWarnNoLLMKey_FirstCallReturnsMessage(t *testing.T) {
	fakeTokenVaultHome(t)

	msg := warnNoLLMKey(nil)
	if msg == "" {
		t.Fatal("expected a non-empty nudge on first call with token-vault installed and no key")
	}
	if _, err := os.Stat(noLLMKeyMarkerPath()); err != nil {
		t.Errorf("expected marker file to be written: %v", err)
	}
}

func TestWarnNoLLMKey_ThrottledWithinTTL(t *testing.T) {
	fakeTokenVaultHome(t)

	first := warnNoLLMKey(nil)
	if first == "" {
		t.Fatal("expected first call to return a message")
	}
	second := warnNoLLMKey(nil)
	if second != "" {
		t.Errorf("expected second call within TTL to be silent (not block, not nag), got: %q", second)
	}
}

func TestWarnNoLLMKey_RewarnsAfterTTLExpires(t *testing.T) {
	fakeTokenVaultHome(t)

	if msg := warnNoLLMKey(nil); msg == "" {
		t.Fatal("expected first call to return a message")
	}
	// Backdate the marker past the TTL to simulate "a day later".
	old := time.Now().Add(-noLLMKeyWarnTTL - time.Minute)
	if err := os.Chtimes(noLLMKeyMarkerPath(), old, old); err != nil {
		t.Fatalf("backdate marker: %v", err)
	}
	if msg := warnNoLLMKey(nil); msg == "" {
		t.Error("expected a fresh nudge once the TTL has elapsed")
	}
}

func TestWarnNoLLMKey_NoTokenVaultInstalled(t *testing.T) {
	// HOME with no ~/bin/token-vault and an empty PATH — TokenVaultInstalled() is false.
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", "")

	if msg := warnNoLLMKey(nil); msg != "" {
		t.Errorf("expected no nudge when token-vault isn't installed at all, got: %q", msg)
	}
}
