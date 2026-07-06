package main

import (
	"fmt"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/RobinUS2/claude-guard/internal/freeze"
)

const freezeUsage = `claude-guard freeze — operator-toggled release freeze (all agents, all sessions)

Usage:
  claude-guard freeze status                 show the current freeze (if any)
  claude-guard freeze on   [flags]           turn a freeze ON
  claude-guard freeze off  [--env E]         lift the freeze (or one env)
  claude-guard freeze validate               lint the freeze file

freeze on flags:
  --env prod[,staging,dev,all]   environment(s) to freeze         (default: prod)
  --project a[,b]                repo scope: origin-remote substrings; omit = ALL repos
  --reason "..."                 why (shown in the block message)
  --until 2026-07-14T18:00       auto-expiry (RFC3339 or local YYYY-MM-DDTHH:MM)
  --include make:target          arm an extra command for this freeze
  --exclude rule-name            carve a catalog rule out of this freeze

Examples:
  claude-guard freeze on --project ai-site-gen --reason "v2 launch prep"
  claude-guard freeze on --env prod,staging --until 2026-07-14T18:00
  claude-guard freeze off --env staging
  claude-guard freeze off
`

func cmdFreeze(args []string) int {
	if len(args) == 0 {
		fmt.Print(freezeUsage)
		return 0
	}
	switch args[0] {
	case "status", "":
		return freezeStatus()
	case "on":
		return freezeOn(args[1:])
	case "off":
		return freezeOff(args[1:])
	case "validate", "lint":
		return freezeValidate()
	case "help", "--help", "-h":
		fmt.Print(freezeUsage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown freeze subcommand: %q\n\n", args[0])
		fmt.Fprint(os.Stderr, freezeUsage)
		return 2
	}
}

func freezeStatus() int {
	path := freeze.DefaultPath()
	now := time.Now()
	s, err := freeze.Load(path)
	if err != nil {
		fmt.Printf("⚠️  freeze file is malformed (%v)\n    %s\n    Treated as NOT frozen. Fix or delete it.\n", err, path)
		return 1
	}
	if envS := freeze.EnvState(os.Getenv); envS != nil {
		fmt.Printf("🧊 CLAUDE_GUARD_FREEZE env var active (this shell): envs=%s\n", strings.Join(envS.FrozenEnvs, ","))
	}
	if s == nil {
		fmt.Println("✅ No release freeze active.")
		fmt.Printf("   (file: %s)\n", path)
		return 0
	}
	if s.Expired(now) {
		fmt.Printf("⚠️  Freeze EXPIRED (lapsed %s) — run 'claude-guard freeze off' to tidy.\n", s.ExpiresAt.Format("2006-01-02 15:04 MST"))
		return 0
	}
	fmt.Printf("🧊 RELEASE FREEZE ACTIVE\n")
	fmt.Printf("   Envs    : %s\n", strings.Join(s.FrozenEnvs, ","))
	fmt.Printf("   Scope   : %s\n", s.ScopeLabel())
	if s.Reason != "" {
		fmt.Printf("   Reason  : %s\n", s.Reason)
	}
	if s.SetBy != "" {
		fmt.Printf("   Set by  : %s%s\n", s.SetBy, ifSet(s.SetAt))
	}
	if s.ExpiresAt != nil {
		fmt.Printf("   Lifts   : %s\n", s.ExpiresAt.Format("2006-01-02 15:04 MST"))
	} else {
		fmt.Printf("   Lifts   : manual — no expiry set\n")
	}
	if len(s.Exclude) > 0 {
		fmt.Printf("   Excluded: %s\n", strings.Join(s.Exclude, ","))
	}
	if len(s.Include) > 0 {
		fmt.Printf("   Included: %s\n", includeSummary(s.Include))
	}
	fmt.Printf("   File    : %s\n", path)
	return 0
}

func freezeOn(args []string) int {
	f := parseFlags(args)
	envs := splitCSV(f["env"])
	if len(envs) == 0 {
		envs = []string{"prod"}
	}
	if bad := validateEnvs(envs); bad != "" {
		fmt.Fprintf(os.Stderr, "unknown --env %q (want: %s, or 'all')\n", bad, strings.Join(freeze.KnownEnvs, ","))
		return 2
	}
	s := &freeze.State{
		Version:    freeze.SchemaVersion,
		FrozenEnvs: envs,
		Projects:   splitCSV(f["project"]),
		Reason:     f["reason"],
		SetBy:      currentUser(),
		SetAt:      time.Now(),
		Exclude:    splitCSV(f["exclude"]),
	}
	if u := f["until"]; u != "" {
		exp, err := parseUntil(u)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bad --until %q: %v\n", u, err)
			return 2
		}
		s.ExpiresAt = &exp
	}
	if inc := f["include"]; inc != "" {
		ir, err := parseInclude(inc, envs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bad --include %q: %v\n", inc, err)
			return 2
		}
		s.Include = []freeze.IncludeRule{ir}
	}
	if err := s.Save(freeze.DefaultPath()); err != nil {
		fmt.Fprintf(os.Stderr, "could not write freeze file: %v\n", err)
		return 1
	}
	fmt.Printf("🧊 Release freeze ON — envs=%s, scope=%s\n", strings.Join(envs, ","), s.ScopeLabel())
	fmt.Println("   All agents in all sessions are now blocked on matching deploy commands.")
	fmt.Println("   Undo with:  claude-guard freeze off")
	return 0
}

func freezeOff(args []string) int {
	f := parseFlags(args)
	path := freeze.DefaultPath()
	s, err := freeze.Load(path)
	if err != nil {
		// Malformed file — safest to remove it so the guard is unambiguously unfrozen.
		_ = os.Remove(path)
		fmt.Println("✅ Removed malformed freeze file — not frozen.")
		return 0
	}
	if s == nil {
		fmt.Println("✅ No freeze was active.")
		return 0
	}
	// Lift a single env, leaving others frozen.
	if envArg := f["env"]; envArg != "" {
		keep := s.FrozenEnvs[:0]
		lift := splitCSV(envArg)
		for _, e := range s.FrozenEnvs {
			if !contains(lift, e) {
				keep = append(keep, e)
			}
		}
		if len(keep) == 0 {
			_ = os.Remove(path)
			fmt.Printf("✅ Lifted %s — no envs left frozen, freeze cleared.\n", envArg)
			return 0
		}
		s.FrozenEnvs = keep
		if err := s.Save(path); err != nil {
			fmt.Fprintf(os.Stderr, "could not update freeze file: %v\n", err)
			return 1
		}
		fmt.Printf("✅ Lifted %s — still frozen: %s\n", envArg, strings.Join(keep, ","))
		return 0
	}
	// Lift everything.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "could not remove freeze file: %v\n", err)
		return 1
	}
	fmt.Println("✅ Release freeze lifted — all envs unfrozen.")
	return 0
}

func freezeValidate() int {
	path := freeze.DefaultPath()
	s, err := freeze.Load(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ invalid freeze file: %v\n", err)
		return 1
	}
	if s == nil {
		fmt.Println("✅ No freeze file (or empty) — valid, not frozen.")
		return 0
	}
	if bad := validateEnvs(s.FrozenEnvs); bad != "" {
		fmt.Fprintf(os.Stderr, "❌ unknown env %q in freeze file\n", bad)
		return 1
	}
	fmt.Println("✅ Freeze file is valid.")
	return 0
}

// --- helpers ---

// parseFlags parses a minimal `--key value` / `--key=value` flag set. Unknown
// flags are ignored; boolean flags are not used by freeze.
func parseFlags(args []string) map[string]string {
	out := map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "--") {
			continue
		}
		a = strings.TrimPrefix(a, "--")
		if eq := strings.IndexByte(a, '='); eq >= 0 {
			out[a[:eq]] = a[eq+1:]
			continue
		}
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
			out[a] = args[i+1]
			i++
		} else {
			out[a] = "true"
		}
	}
	return out
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func validateEnvs(envs []string) string {
	for _, e := range envs {
		if e == freeze.EnvAll {
			continue
		}
		if !contains(freeze.KnownEnvs, e) {
			return e
		}
	}
	return ""
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// parseUntil accepts RFC3339 or a bare local YYYY-MM-DDTHH:MM. The result is
// always an absolute instant, stored with an explicit offset by yaml marshaling.
func parseUntil(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	// Bare local timestamp — interpret in the host's local zone.
	if t, err := time.ParseInLocation("2006-01-02T15:04", s, time.Local); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("want RFC3339 or YYYY-MM-DDTHH:MM")
}

// parseInclude parses "program:subcommand" (subcommand optional) into a rule.
func parseInclude(s string, envs []string) (freeze.IncludeRule, error) {
	parts := strings.SplitN(s, ":", 2)
	prog := strings.TrimSpace(parts[0])
	if prog == "" {
		return freeze.IncludeRule{}, fmt.Errorf("empty program")
	}
	ir := freeze.IncludeRule{Program: prog, Envs: envs}
	if len(parts) == 2 {
		ir.Subcommand = strings.TrimSpace(parts[1])
	}
	return ir, nil
}

func currentUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return "unknown"
}

func ifSet(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return " at " + t.Format("2006-01-02 15:04 MST")
}

func includeSummary(inc []freeze.IncludeRule) string {
	var parts []string
	for _, i := range inc {
		if i.Subcommand != "" {
			parts = append(parts, i.Program+":"+i.Subcommand)
		} else {
			parts = append(parts, i.Program)
		}
	}
	return strings.Join(parts, ",")
}
