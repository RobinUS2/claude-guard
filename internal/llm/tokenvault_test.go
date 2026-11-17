package llm

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeFakeTokenVault writes a shell script standing in for the real
// token-vault binary. Content is irrelevant to TokenVaultInstalled,
// which only checks resolvability, but this mirrors how other tests in
// this package stub tokenVaultBinary with a real, executable file.
func writeFakeTokenVault(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "token-vault")
	if err := os.WriteFile(path, []byte("#!/bin/bash\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTokenVaultInstalled_False(t *testing.T) {
	old := tokenVaultBinary
	tokenVaultBinary = "/nonexistent-token-vault-stub"
	t.Cleanup(func() { tokenVaultBinary = old })

	if TokenVaultInstalled() {
		t.Fatal("expected false when token-vault binary doesn't exist")
	}
}

func TestTokenVaultInstalled_True(t *testing.T) {
	old := tokenVaultBinary
	tokenVaultBinary = writeFakeTokenVault(t)
	t.Cleanup(func() { tokenVaultBinary = old })

	if !TokenVaultInstalled() {
		t.Fatal("expected true when token-vault binary resolves to a real file")
	}
}

// setupVaultLookup stubs the binary, isolates the cache dir, resets the
// in-process cache and restores timeouts afterwards.
func setupVaultLookup(t *testing.T, script string) (marker string) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "token-vault")
	if err := os.WriteFile(bin, []byte("#!/bin/bash\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	oldBin, oldT, oldTot := tokenVaultBinary, tokenVaultTimeout, tokenVaultTotalTimeout
	tokenVaultBinary = bin
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	inProcessCache.Lock()
	inProcessCache.value, inProcessCache.checked = "", false
	inProcessCache.Unlock()
	t.Cleanup(func() {
		tokenVaultBinary, tokenVaultTimeout, tokenVaultTotalTimeout = oldBin, oldT, oldTot
		inProcessCache.Lock()
		inProcessCache.value, inProcessCache.checked = "", false
		inProcessCache.Unlock()
	})
	return tokenVaultNegativeCachePath()
}

func TestTokenVaultCandidates_TaufinityFirst(t *testing.T) {
	c := TokenVaultAnthropicCandidates[0]
	if c.Vault != "taufinity" || c.Secret != "anthropic_api_key" {
		t.Fatalf("first candidate = %v, want taufinity/anthropic_api_key", c)
	}
}

func TestLookupTokenVault_SlowCandidateStillResolves(t *testing.T) {
	// Slow (400ms, above the old 300ms limit) but successful.
	setupVaultLookup(t, `if [ "$2" = taufinity ] && [ "$3" = anthropic_api_key ]; then sleep 0.4; echo test-value; exit 0; fi
exit 1
`)
	if got := LookupTokenVaultAnthropic(); got != "test-value" {
		t.Fatalf("got %q, want resolved value", got)
	}
}

func TestLookupTokenVault_TimeoutWritesNoMarker(t *testing.T) {
	marker := setupVaultLookup(t, "sleep 5\n")
	tokenVaultTimeout = 100 * time.Millisecond
	tokenVaultTotalTimeout = 300 * time.Millisecond
	start := time.Now()
	if got := LookupTokenVaultAnthropic(); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("sweep took %v, total cap not honoured", d)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("miss marker written after a timeout")
	}
}

func TestLookupTokenVault_CleanMissWritesMarker(t *testing.T) {
	marker := setupVaultLookup(t, "exit 1\n")
	if got := LookupTokenVaultAnthropic(); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("miss marker not written after clean miss: %v", err)
	}
}
