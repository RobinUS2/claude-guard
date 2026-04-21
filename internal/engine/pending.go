package engine

import (
	"os"
	"path/filepath"

	"github.com/RobinUS2/claude-guard/internal/store"
)

// writePendingApproval records that a command was forwarded to the user
// (Continue verdict) so the PostToolUse learn hook can pick it up if
// the user approves. Opens SQLite, writes, closes — stateless per call.
//
// Errors are swallowed: pending approval is best-effort. If it fails,
// the learn hook simply won't find a pending entry and skips learning.
func writePendingApproval(toolUseID, command, canonical, cwd, sessionID, reason string) {
	if toolUseID == "" || command == "" {
		return
	}
	dbPath := defaultDBPath()
	db, err := store.Open(dbPath)
	if err != nil {
		return
	}
	defer db.Close()
	db.WritePending(toolUseID, command, canonical, cwd, sessionID, reason) //nolint:errcheck
}

func defaultDBPath() string {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".cache", "claude-guard")
	if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
		dir = filepath.Join(xdg, "claude-guard")
	}
	return filepath.Join(dir, "guard.db")
}
