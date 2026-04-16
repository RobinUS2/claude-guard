package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/RobinUS2/claude-guard/internal/cache"
	"github.com/RobinUS2/claude-guard/internal/engine"
	"github.com/RobinUS2/claude-guard/internal/llm"
)

// cmdTrust clears the Disagreement flag on a cache entry so the
// verifier's "this should be denied" verdict is overridden by the
// user. Used when the verifier is being over-conservative and the
// user has manually inspected and approved the command.
//
//	claude-guard trust "<command>"              # trust in the current cwd
//	claude-guard trust --cwd /path "<command>"  # trust in a specific cwd
//	claude-guard trust --global "<command>"     # trust everywhere (global scope)
//	claude-guard trust --list                   # list all disagreements
//	claude-guard trust --clear-all              # clear every disagreement
//
// SECURITY: this is a user-initiated override. The verifier's
// reasoning is left in place on the cache entry for audit — trust
// only flips Disagreement=false, preserving VerifierVerdict,
// VerifierReason, and VerifierModel. An auditor can still see the
// verifier thought this was risky and that the user chose to trust
// it anyway.
func cmdTrust(args []string) int {
	fs := flag.NewFlagSet("trust", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		cwd      string
		reason   string
		global   bool
		list     bool
		clearAll bool
		yes      bool
	)
	fs.StringVar(&cwd, "cwd", "", "override the cwd for project-scoped lookup (default: current)")
	fs.StringVar(&reason, "reason", "", "optional note explaining why the command is trusted (stored for audit)")
	fs.BoolVar(&global, "global", false, "trust this command in any cwd (global-scope cache entry)")
	fs.BoolVar(&list, "list", false, "list all cache entries currently flagged as disagreements")
	fs.BoolVar(&clearAll, "clear-all", false, "clear Disagreement on every flagged entry")
	fs.BoolVar(&yes, "yes", false, "skip confirmation prompt (required for non-interactive --clear-all)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	home, _ := os.UserHomeDir()
	cacheDir := filepath.Join(home, ".cache", "claude-guard", "verdicts")
	if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
		cacheDir = filepath.Join(xdg, "claude-guard", "verdicts")
	}
	cch := cache.New(cacheDir)

	if list {
		return listDisagreements(cacheDir)
	}
	if clearAll {
		return clearAllDisagreements(cacheDir, yes)
	}

	if fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: claude-guard trust [--global|--cwd DIR] \"<command>\"")
		fmt.Fprintln(os.Stderr, "       claude-guard trust --list")
		fmt.Fprintln(os.Stderr, "       claude-guard trust --clear-all")
		return 2
	}
	command := fs.Arg(0)

	if cwd == "" && !global {
		cwd, _ = os.Getwd()
	}

	// Build the same key the engine would use.
	keyInputs := cache.KeyInputs{
		Tool:          "Bash",
		Command:       command,
		CWD:           cwd,
		GitBranch:     engine.GitBranchOf(cwd),
		PromptVersion: cache.HashString(llm.DefaultSystemPrompt()),
		// RulesHash is engine-internal — we don't have it here without
		// instantiating the full engine, so the user's key won't match
		// project entries if rules have changed since the cache was
		// built. In practice this is fine: after a rule change, the
		// cache is invalidated anyway. We only need to match entries
		// written with the current rule set.
		RulesHash: "",
	}

	var key string
	if global {
		key = cache.GlobalKey(keyInputs)
	} else {
		key = cache.Key(keyInputs)
	}

	entry, hit := cch.Get(key)
	if !hit {
		// The rules-hash mismatch problem: we can't build the same key
		// without access to the engine's computed hash. Fall back to
		// scanning the cache directory for an entry whose stored command
		// matches the user's input. Slower but always works.
		match := findEntryByCommand(cacheDir, command, cwd, global)
		if match == nil {
			fmt.Fprintf(os.Stderr, "trust: no cache entry found for that command\n")
			fmt.Fprintln(os.Stderr, "       (run `claude-guard trust --list` to see what IS cached)")
			return 1
		}
		key = match.key
		entry = &match.entry
	}

	if !entry.Disagreement {
		fmt.Printf("no-op: entry was not flagged as a disagreement\n")
		fmt.Printf("  command:        %s\n", command)
		fmt.Printf("  current verdict: %s (%s)\n", entry.Verdict, entry.Tier)
		return 0
	}

	// Flip the disagreement flag and record the trust action.
	// All audit fields (verifier verdict, reason, model) are preserved
	// so an auditor can still see that the user explicitly overrode the
	// verifier's warning.
	entry.Disagreement = false
	entry.TrustedAt = time.Now().UTC()
	entry.TrustedReason = reason
	// Preserve ExpiresAt so trusting doesn't extend the entry's lifetime.
	ttl := int64(0)
	if !entry.ExpiresAt.IsZero() {
		ttl = entry.ExpiresAt.UnixNano() - entry.StoredAt.UnixNano()
	}
	if err := cch.Put(key, *entry, ttlDurationFromNano(ttl)); err != nil {
		fmt.Fprintf(os.Stderr, "trust: failed to write cache: %v\n", err)
		return 1
	}

	fmt.Printf("trusted: %s\n", command)
	fmt.Printf("  verifier said: %s (%s)\n", entry.VerifierVerdict, entry.VerifierProvider)
	fmt.Printf("  reason:        %s\n", entry.VerifierReason)
	fmt.Println("  you have overridden this — future cache hits will ALLOW.")
	fmt.Println("  (audit trail preserved: verifier fields are intact.)")
	return 0
}

// matchedEntry carries a cache entry with its on-disk key.
type matchedEntry struct {
	key   string
	entry cache.Entry
}

// findEntryByCommand walks the cache directory and returns the first
// entry whose stored Command matches. Used as a fallback when the
// caller can't reconstruct the exact cache key (because RulesHash is
// engine-internal and not available to subcommand code).
//
// Match rules:
//   - Command is compared exactly (including whitespace). We do NOT
//     normalize — if the user wants to trust `ls -la` they must pass
//     the exact command text that was cached.
//   - When global=true, only entries with CWD="" are considered.
//   - When global=false, entries must have CWD==cwd (best-effort; if
//     the caller passes cwd="" we accept any).
//
// Returns the first match; callers can iterate or disambiguate via
// `trust --list` if multiple entries tie.
func findEntryByCommand(cacheDir, command, cwd string, global bool) *matchedEntry {
	var out *matchedEntry
	_ = filepath.Walk(cacheDir, func(path string, info os.FileInfo, err error) error {
		if out != nil {
			return filepath.SkipDir
		}
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var entry cache.Entry
		if err := json.Unmarshal(data, &entry); err != nil {
			return nil
		}
		if entry.Command != command {
			return nil
		}
		switch {
		case global && entry.CWD != "":
			return nil
		case !global && cwd != "" && entry.CWD != cwd:
			return nil
		}
		base := filepath.Base(path)
		key := strings.TrimSuffix(base, ".json")
		out = &matchedEntry{key: key, entry: entry}
		return nil
	})
	return out
}

// listDisagreements walks the cache dir and prints every entry marked
// as a disagreement. Prints enough info for the user to decide whether
// to trust it (verifier reason, model) and the exact cache key they
// can pass to `trust` to flip the flag.
func listDisagreements(cacheDir string) int {
	found := 0
	_ = filepath.Walk(cacheDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var entry cache.Entry
		if err := json.Unmarshal(data, &entry); err != nil {
			return nil
		}
		if !entry.Disagreement {
			return nil
		}
		found++
		base := filepath.Base(path)
		key := strings.TrimSuffix(base, ".json")
		fmt.Printf("=== %s ===\n", key)
		fmt.Printf("  stored:      %s\n", entry.StoredAt.Format(time.RFC3339))
		fmt.Printf("  verifier:    %s / %s\n", entry.VerifierProvider, entry.VerifierModel)
		fmt.Printf("  verifier verdict: %s\n", entry.VerifierVerdict)
		fmt.Printf("  reason:      %s\n", truncLong(entry.VerifierReason, 240))
		fmt.Printf("  path:        %s\n", path)
		fmt.Println()
		return nil
	})
	if found == 0 {
		fmt.Println("no cache entries are currently flagged as disagreements.")
	} else {
		fmt.Printf("%d disagreement(s). To trust a specific entry:\n", found)
		fmt.Println("  claude-guard trust \"<original command>\"")
		fmt.Println("or edit the JSON file directly and set \"disagreement\": false.")
	}
	return 0
}

// clearAllDisagreements flips Disagreement=false on every flagged
// cache entry. Bulk override of verifier warnings — requires explicit
// confirmation. Exit codes:
//
//	0 — some entries cleared (or none were flagged)
//	1 — write error during walk
//	2 — user aborted or refused to prompt (non-interactive without --yes)
func clearAllDisagreements(cacheDir string, yes bool) int {
	if !yes {
		if !isTerminal(os.Stdin) {
			fmt.Fprintln(os.Stderr, "refusing to prompt: stdin is not a terminal")
			fmt.Fprintln(os.Stderr, "re-run with --yes to confirm non-interactively")
			return 2
		}
		fmt.Print("This will clear the Disagreement flag on every flagged cache entry.\n")
		fmt.Print("Audit fields (verifier verdict, reason, model) and the new\n")
		fmt.Print("TrustedAt timestamp are preserved.\n")
		fmt.Print("Continue? [y/N] ")
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer != "y" && answer != "yes" {
			fmt.Println("aborted.")
			return 2
		}
	}

	cleared := 0
	now := time.Now().UTC()
	walkErr := filepath.Walk(cacheDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var entry cache.Entry
		if err := json.Unmarshal(data, &entry); err != nil {
			return nil
		}
		if !entry.Disagreement {
			return nil
		}
		entry.Disagreement = false
		entry.TrustedAt = now
		entry.TrustedReason = "cleared via trust --clear-all"
		newData, err := json.MarshalIndent(&entry, "", "  ")
		if err != nil {
			return nil
		}
		tmp := path + ".tmp"
		// Defer cleanup: if rename fails, the .tmp file is removed.
		writeOK := false
		defer func() {
			if !writeOK {
				_ = os.Remove(tmp)
			}
		}()
		if err := os.WriteFile(tmp, newData, 0o640); err != nil {
			return nil
		}
		if err := os.Rename(tmp, path); err != nil {
			return nil
		}
		writeOK = true
		cleared++
		return nil
	})
	if walkErr != nil {
		fmt.Fprintf(os.Stderr, "clear-all: %v\n", walkErr)
		return 1
	}
	fmt.Printf("cleared %d disagreement(s).\n", cleared)
	return 0
}

// isTerminal returns true if f is connected to a terminal. Used by
// --clear-all to decide whether to prompt or require --yes.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// ttlDurationFromNano converts a nanosecond span to a time.Duration.
// Wrapper for readability at the call site.
func ttlDurationFromNano(nanos int64) time.Duration {
	return time.Duration(nanos)
}

