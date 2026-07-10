package llm

import (
	"os"
	"path/filepath"
	"testing"
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
