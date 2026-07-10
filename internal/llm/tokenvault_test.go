package llm

import (
	"os"
	"path/filepath"
	"testing"
)

// writeFakeTokenVault writes a shell script standing in for the real
// token-vault binary, printing statusOutput to stderr on `status` and
// exiting 0. Mirrors the real CLI's behavior of writing status to stderr.
func writeFakeTokenVault(t *testing.T, statusOutput string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "token-vault")
	script := "#!/bin/bash\ncat 1>&2 <<'STATUS'\n" + statusOutput + "\nSTATUS\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLookupVaultLockState_NotInstalled(t *testing.T) {
	old := tokenVaultBinary
	tokenVaultBinary = "/nonexistent-token-vault-stub"
	t.Cleanup(func() { tokenVaultBinary = old })

	got := LookupVaultLockState()
	if got.Installed {
		t.Fatal("expected Installed=false when token-vault binary doesn't exist")
	}
	if got.Unlocked {
		t.Fatal("expected Unlocked=false when not installed")
	}
}

func TestLookupVaultLockState_InstalledAndLocked(t *testing.T) {
	old := tokenVaultBinary
	tokenVaultBinary = writeFakeTokenVault(t, "[vault] Token Vaults\n\n  demo  1 secret(s)  [locked]")
	t.Cleanup(func() { tokenVaultBinary = old })

	got := LookupVaultLockState()
	if !got.Installed {
		t.Fatal("expected Installed=true")
	}
	if got.Unlocked {
		t.Fatal("expected Unlocked=false for a status report with only [locked] vaults")
	}
}

func TestLookupVaultLockState_InstalledAndUnlocked(t *testing.T) {
	old := tokenVaultBinary
	tokenVaultBinary = writeFakeTokenVault(t, "[vault] Token Vaults\n\n  demo  1 secret(s)  [unlocked, expires in 47m]")
	t.Cleanup(func() { tokenVaultBinary = old })

	got := LookupVaultLockState()
	if !got.Installed {
		t.Fatal("expected Installed=true")
	}
	if !got.Unlocked {
		t.Fatal("expected Unlocked=true when status reports an [unlocked ...] vault")
	}
}

func TestLookupVaultLockState_MixedLockedAndUnlocked(t *testing.T) {
	old := tokenVaultBinary
	tokenVaultBinary = writeFakeTokenVault(t, "[vault] Token Vaults\n\n  a  [locked]\n  b  [unlocked, expires in 5m]")
	t.Cleanup(func() { tokenVaultBinary = old })

	got := LookupVaultLockState()
	if !got.Unlocked {
		t.Fatal("expected Unlocked=true when at least one vault is unlocked, even if others are locked")
	}
}
