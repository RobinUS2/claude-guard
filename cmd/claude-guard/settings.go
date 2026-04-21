package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/RobinUS2/claude-guard/internal/cache"
	"github.com/RobinUS2/claude-guard/internal/config"
	"github.com/RobinUS2/claude-guard/internal/rules"
	"github.com/RobinUS2/claude-guard/internal/store"
)

const settingsUsage = `claude-guard settings — audit and migrate settings.json permissions

Usage:
  claude-guard settings <subcommand> [flags]

Subcommands:
  audit                         cross-reference settings.json with guard rules
  migrate [--dry-run|--apply]   move Bash entries to guard's learned store

Audit shows which settings.json entries are redundant (tier 2 handles them),
which contain credentials, and which are non-Bash (guard doesn't handle).

Migrate moves Bash entries out of settings.json into claude-guard's SQLite
store as learned patterns, removing redundant ones that tier 2 already covers.
`

// settingsPathFn resolves the settings.json path. Overridable in tests.
var settingsPathFn = defaultSettingsPath

func defaultSettingsPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".claude", "settings.json")
}

// storePathFn resolves the SQLite store path. Overridable in tests.
// Reuses defaultStorePath from learn.go for production.
var storePathFn = defaultStorePath

func cmdSettings(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, settingsUsage)
		return 2
	}
	switch args[0] {
	case "audit":
		return settingsAuditCmd(args[1:])
	case "migrate":
		return settingsMigrateCmd(args[1:])
	case "help", "-h", "--help":
		fmt.Print(settingsUsage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "settings: unknown subcommand %q\n\n", args[0])
		fmt.Fprint(os.Stderr, settingsUsage)
		return 2
	}
}

// settingsJSON is the minimal structure we need from settings.json.
type settingsJSON struct {
	Permissions struct {
		Allow []string `json:"allow"`
		Deny  []string `json:"deny"`
	} `json:"permissions"`
	// Preserve the rest for round-trip writes.
	raw map[string]json.RawMessage
}

// readSettings reads and parses settings.json at the given path.
func readSettings(path string) (*settingsJSON, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s settingsJSON
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	// Also parse raw for round-trip.
	if err := json.Unmarshal(data, &s.raw); err != nil {
		return nil, err
	}
	return &s, nil
}

// writeSettings writes back the settings.json, replacing permissions.allow
// with the given entries while preserving all other keys.
func writeSettings(path string, s *settingsJSON, newAllow []string) error {
	// Re-marshal the permissions block with the updated allow list.
	permData, ok := s.raw["permissions"]
	var permMap map[string]json.RawMessage
	if ok {
		if err := json.Unmarshal(permData, &permMap); err != nil {
			permMap = make(map[string]json.RawMessage)
		}
	} else {
		permMap = make(map[string]json.RawMessage)
	}

	allowData, err := json.Marshal(newAllow)
	if err != nil {
		return err
	}
	permMap["allow"] = allowData

	newPermData, err := json.Marshal(permMap)
	if err != nil {
		return err
	}
	s.raw["permissions"] = newPermData

	out, err := json.MarshalIndent(s.raw, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return os.WriteFile(path, out, 0o644)
}

// entryCategory classifies a settings.json entry.
type entryCategory int

const (
	catBash       entryCategory = iota // Bash(...) entry
	catNonBash                         // Read, WebFetch, mcp__*, etc.
	catCredential                      // Bash entry with credential patterns
)

// classifyEntry determines the category of a settings.json permission entry.
func classifyEntry(entry string) (entryCategory, string) {
	// Non-Bash entries.
	if !strings.HasPrefix(entry, "Bash(") {
		return catNonBash, ""
	}

	// Check for credential patterns.
	if hasCredentialPattern(entry) {
		return catCredential, extractBashProgram(entry)
	}

	return catBash, extractBashProgram(entry)
}

// hasCredentialPattern checks if an entry contains known credential patterns.
func hasCredentialPattern(entry string) bool {
	patterns := []string{
		"ATATT3x", "Bearer ", "token=", "password=", "secret=",
		"api_key=", "apikey=", "Authorization:", "ghp_", "gho_",
		"sk-",
	}
	for _, p := range patterns {
		if strings.Contains(entry, p) {
			return true
		}
	}
	return false
}

// extractBashProgram extracts the program name from a Bash(cmd:*) entry.
// Returns the first word of the command part. For entries like
// "Bash(git status:*)" returns "git".
func extractBashProgram(entry string) string {
	// Strip "Bash(" prefix and trailing ")".
	if !strings.HasPrefix(entry, "Bash(") {
		return ""
	}
	inner := strings.TrimPrefix(entry, "Bash(")
	if idx := strings.LastIndex(inner, ")"); idx >= 0 {
		inner = inner[:idx]
	}
	// The format is "command:scope" — strip the scope.
	if idx := strings.LastIndex(inner, ":"); idx >= 0 {
		inner = inner[:idx]
	}
	inner = strings.TrimSpace(inner)
	// First token is the program.
	for i, ch := range inner {
		if ch == ' ' || ch == '\t' {
			return inner[:i]
		}
	}
	return inner
}

// extractBashCommand extracts the full command from a Bash(cmd:scope) entry.
func extractBashCommand(entry string) string {
	if !strings.HasPrefix(entry, "Bash(") {
		return ""
	}
	inner := strings.TrimPrefix(entry, "Bash(")
	if idx := strings.LastIndex(inner, ")"); idx >= 0 {
		inner = inner[:idx]
	}
	if idx := strings.LastIndex(inner, ":"); idx >= 0 {
		inner = inner[:idx]
	}
	return strings.TrimSpace(inner)
}

// tier2Programs builds a set of program names that tier 2 rules handle.
// Uses reflection-free type assertions on the known rule types.
func tier2Programs() map[string]string {
	progs := make(map[string]string) // program -> rule name
	for _, r := range config.DefaultAllowRules() {
		var programs []string
		switch v := r.(type) {
		case *rules.AnchoredCommand:
			programs = v.Programs
		case *rules.NestedSubcommandAllow:
			programs = v.Programs
		}
		for _, p := range programs {
			progs[p] = r.Name()
		}
	}
	return progs
}

// auditResult holds the categorized entries.
type auditResult struct {
	total       int
	redundant   []auditEntry // Bash entries covered by tier 2
	credentials []auditEntry // Bash entries with credential patterns
	nonBash     []string     // non-Bash entries (keep)
	remaining   []string     // Bash entries guard doesn't cover
}

type auditEntry struct {
	entry    string
	reason   string
	program  string
}

func auditSettings(entries []string) auditResult {
	t2 := tier2Programs()
	var res auditResult
	res.total = len(entries)

	for _, e := range entries {
		cat, prog := classifyEntry(e)
		switch cat {
		case catNonBash:
			res.nonBash = append(res.nonBash, e)
		case catCredential:
			res.credentials = append(res.credentials, auditEntry{
				entry:   e,
				reason:  "contains credential pattern",
				program: prog,
			})
		case catBash:
			if ruleName, ok := t2[prog]; ok {
				res.redundant = append(res.redundant, auditEntry{
					entry:   e,
					reason:  fmt.Sprintf("covered by %s", ruleName),
					program: prog,
				})
			} else {
				res.remaining = append(res.remaining, e)
			}
		}
	}

	return res
}

func settingsAuditCmd(args []string) int {
	fs := flag.NewFlagSet("settings audit", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	path := settingsPathFn()
	s, err := readSettings(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "settings audit: %v\n", err)
		return 1
	}

	res := auditSettings(s.Permissions.Allow)

	fmt.Printf("settings.json audit (%d entries)\n\n", res.total)

	// Redundant with tier 2.
	if len(res.redundant) > 0 {
		fmt.Printf("redundant with tier 2 (guard already auto-allows these):\n")
		for _, e := range res.redundant {
			cmd := extractBashCommand(e.entry)
			if len(cmd) > 60 {
				cmd = cmd[:57] + "..."
			}
			fmt.Printf("  %-40s -> %s\n", cmd, e.reason)
		}
	} else {
		fmt.Printf("redundant with tier 2 (guard already auto-allows these):\n  (none)\n")
	}
	fmt.Println()

	// Credential risk.
	if len(res.credentials) > 0 {
		fmt.Printf("credential risk (should never be in settings.json):\n")
		for _, e := range res.credentials {
			cmd := extractBashCommand(e.entry)
			if len(cmd) > 60 {
				cmd = cmd[:57] + "..."
			}
			fmt.Printf("  %s\n", cmd)
		}
	} else {
		fmt.Printf("credential risk (should never be in settings.json):\n  (none found)\n")
	}
	fmt.Println()

	// Non-Bash entries.
	if len(res.nonBash) > 0 {
		fmt.Printf("non-Bash entries (not handled by guard, keep):\n")
		// Group by type prefix for readability.
		types := map[string]int{}
		for _, e := range res.nonBash {
			prefix := e
			if idx := strings.Index(e, "("); idx >= 0 {
				prefix = e[:idx]
			}
			types[prefix]++
		}
		keys := make([]string, 0, len(types))
		for k := range types {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("  %s (%d)\n", k, types[k])
		}
	} else {
		fmt.Printf("non-Bash entries (not handled by guard, keep):\n  (none)\n")
	}
	fmt.Println()

	// Summary.
	fmt.Printf("summary:\n")
	fmt.Printf("  total:       %d\n", res.total)
	fmt.Printf("  redundant:   %-5d (safe to remove — guard handles these)\n", len(res.redundant))
	fmt.Printf("  credentials: %d\n", len(res.credentials))
	fmt.Printf("  non-Bash:    %-5d (keep — guard doesn't handle these yet)\n", len(res.nonBash))
	fmt.Printf("  remaining:   %-5d (Bash entries guard doesn't cover, keep in settings.json)\n", len(res.remaining))

	return 0
}

func settingsMigrateCmd(args []string) int {
	fs := flag.NewFlagSet("settings migrate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var dryRun, apply bool
	fs.BoolVar(&dryRun, "dry-run", false, "show what would change without modifying anything")
	fs.BoolVar(&apply, "apply", false, "actually modify settings.json and SQLite")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if !dryRun && !apply {
		fmt.Fprintln(os.Stderr, "settings migrate: must specify --dry-run or --apply")
		return 2
	}
	if dryRun && apply {
		fmt.Fprintln(os.Stderr, "settings migrate: --dry-run and --apply are mutually exclusive")
		return 2
	}

	path := settingsPathFn()
	s, err := readSettings(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "settings migrate: %v\n", err)
		return 1
	}

	res := auditSettings(s.Permissions.Allow)

	label := "settings migrate --dry-run"
	if apply {
		label = "settings migrate --apply"
	}
	fmt.Println(label)
	fmt.Println()

	wouldRemove := len(res.redundant)
	wouldMigrate := len(res.remaining)
	wouldSkipNonBash := len(res.nonBash)
	wouldSkipCreds := len(res.credentials)

	if dryRun {
		fmt.Printf("would remove (tier 2 handles):     %d entries\n", wouldRemove)
		fmt.Printf("would migrate to learned:          %d entries\n", wouldMigrate)
		fmt.Printf("would skip (non-Bash, keep):       %d entries\n", wouldSkipNonBash)
		fmt.Printf("would skip (credentials, manual):  %d entries\n", wouldSkipCreds)
		fmt.Println()
		fmt.Println("run with --apply to execute")
		return 0
	}

	// --apply: open the SQLite store.
	dbPath := storePathFn()
	db, err := store.Open(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "settings migrate: open store: %v\n", err)
		return 1
	}
	defer db.Close()

	// Migrate remaining Bash entries to learned store.
	migrated := 0
	for _, entry := range res.remaining {
		cmd := extractBashCommand(entry)
		if cmd == "" {
			continue
		}
		prog := extractBashProgram(entry)

		cacheEntry := cache.Entry{
			Verdict:  cache.VerdictAllow,
			Tier:     "learned",
			Reason:   "migrated from settings.json",
			Provider: "settings-migrate",
			Model:    "user",
			StoredAt: time.Now(),
			Command:  cmd,
			Program:  prog,
		}

		// Use global key — these are user-approved patterns that should
		// apply everywhere (matching the original settings.json semantics).
		key := cache.GlobalKey(cache.KeyInputs{
			Tool:    "Bash",
			Command: cmd,
		})
		if err := db.PutVerdict(key, cacheEntry, 0); err != nil {
			fmt.Fprintf(os.Stderr, "  error migrating %q: %v\n", cmd, err)
			continue
		}
		migrated++
	}

	// Build the new allow list: keep only non-Bash + credential entries.
	var newAllow []string
	newAllow = append(newAllow, res.nonBash...)
	for _, e := range res.credentials {
		newAllow = append(newAllow, e.entry)
	}

	if err := writeSettings(path, s, newAllow); err != nil {
		fmt.Fprintf(os.Stderr, "settings migrate: write settings.json: %v\n", err)
		return 1
	}

	fmt.Printf("removed (tier 2 handles):          %d entries\n", wouldRemove)
	fmt.Printf("migrated to learned:               %d entries\n", migrated)
	fmt.Printf("kept (non-Bash):                   %d entries\n", wouldSkipNonBash)
	fmt.Printf("kept (credentials, manual review): %d entries\n", wouldSkipCreds)
	fmt.Println()
	fmt.Printf("settings.json: %s\n", path)
	fmt.Printf("store:         %s\n", dbPath)

	return 0
}
