package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/RobinUS2/claude-guard/internal/cache"
	"github.com/RobinUS2/claude-guard/internal/normalize"
	"github.com/RobinUS2/claude-guard/internal/store"
)

// postToolUseInput is the JSON schema Claude Code sends to PostToolUse hooks.
type postToolUseInput struct {
	SessionID  string          `json:"session_id"`
	ToolName   string          `json:"tool_name"`
	ToolInput  json.RawMessage `json:"tool_input"`
	ToolUseID  string          `json:"tool_use_id"`
	CWD        string          `json:"cwd"`
}

type bashToolInput struct {
	Command string `json:"command"`
}

// learnResponse is the JSON output — must be valid JSON for the hook protocol.
type learnResponse struct {
	Learned bool   `json:"learned,omitempty"`
	Pattern string `json:"pattern,omitempty"`
}

// promoteAfter is the number of approvals before a learned pattern
// is promoted from project-scoped to global-scoped auto-allow.
const promoteAfter = 3

func cmdLearn(args []string) int {
	return cmdLearnWithIO(os.Stdin, os.Stdout)
}

func cmdLearnWithIO(r io.Reader, w io.Writer) int {
	data, err := io.ReadAll(r)
	if err != nil {
		writeLearnResp(w, false, "")
		return 0
	}

	var in postToolUseInput
	if err := json.Unmarshal(data, &in); err != nil {
		writeLearnResp(w, false, "")
		return 0
	}

	// Only learn from Bash commands.
	if in.ToolName != "Bash" {
		writeLearnResp(w, false, "")
		return 0
	}

	var bash bashToolInput
	if err := json.Unmarshal(in.ToolInput, &bash); err != nil || bash.Command == "" {
		writeLearnResp(w, false, "")
		return 0
	}

	// Open the store.
	dbPath := defaultStorePath()
	db, err := store.Open(dbPath)
	if err != nil {
		// Can't learn — fail silently, don't block Claude.
		writeLearnResp(w, false, "")
		return 0
	}
	defer db.Close()

	// Clean stale pending approvals (>1h).
	db.CleanStalePending(1 * time.Hour) //nolint:errcheck

	// Look up the pending approval by tool_use_id.
	pending, err := db.ReadPending(in.ToolUseID)
	if err != nil || pending == nil {
		// No pending approval — command was auto-allowed, nothing to learn.
		writeLearnResp(w, false, "")
		return 0
	}

	// User approved this command. Cache it as a learned entry.
	canonical := pending.CanonicalForm
	if canonical == "" {
		canonical, _, _ = normalize.Normalize(bash.Command, nil)
	}

	// Check if we already have a learned entry for this canonical.
	// If so, increment approval_count.
	program := firstToken(bash.Command)

	entry := cache.Entry{
		Verdict:       cache.VerdictAllow,
		Tier:          "learned",
		Reason:        "user-approved",
		Provider:      "user",
		Model:         "human",
		StoredAt:      time.Now(),
		Command:       bash.Command,
		CWD:           in.CWD,
		CanonicalForm: canonical,
		Program:       program,
	}

	// Build cache key — project-scoped by default.
	cacheKey := cache.Key(cache.KeyInputs{
		Tool:    "Bash",
		Command: canonical, // key on canonical form so similar commands share entry
		CWD:     in.CWD,
	})

	// Check existing entry — merge approval count.
	existing, hit := db.GetVerdict(cacheKey)
	approvalCount := 1
	if hit && existing.Tier == "learned" {
		approvalCount = existing.MatchCount + 1 // reuse MatchCount as approval counter
	}
	entry.MatchCount = approvalCount

	// No expiry for learned entries — they persist until manually forgotten.
	if err := db.PutVerdict(cacheKey, entry, 0); err != nil {
		writeLearnResp(w, false, "")
		return 0
	}

	// Promote to global scope after N approvals.
	if approvalCount >= promoteAfter {
		globalKey := cache.GlobalKey(cache.KeyInputs{
			Tool:    "Bash",
			Command: canonical,
		})
		entry.Reason = fmt.Sprintf("user-approved (%d approvals, promoted to global)", approvalCount)
		db.PutVerdict(globalKey, entry, 0) //nolint:errcheck
	}

	// Delete the pending approval.
	db.DeletePending(in.ToolUseID) //nolint:errcheck

	writeLearnResp(w, true, canonical)
	return 0
}

func writeLearnResp(w io.Writer, learned bool, pattern string) {
	resp := learnResponse{Learned: learned, Pattern: pattern}
	data, _ := json.Marshal(resp)
	fmt.Fprintln(w, string(data))
}

func defaultStorePath() string {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".cache", "claude-guard")
	if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
		dir = filepath.Join(xdg, "claude-guard")
	}
	return filepath.Join(dir, "guard.db")
}

func firstToken(s string) string {
	for i, ch := range s {
		if ch == ' ' || ch == '\t' {
			return s[:i]
		}
	}
	return s
}
