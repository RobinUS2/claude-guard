package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/RobinUS2/claude-guard/internal/budget"
	"github.com/RobinUS2/claude-guard/internal/cache"
	"github.com/RobinUS2/claude-guard/internal/config"
	"github.com/RobinUS2/claude-guard/internal/freeze"
	"github.com/RobinUS2/claude-guard/internal/legacy"
	"github.com/RobinUS2/claude-guard/internal/llm"
	"github.com/RobinUS2/claude-guard/internal/llm/breaker"
	clog "github.com/RobinUS2/claude-guard/internal/log"
	"github.com/RobinUS2/claude-guard/internal/projectconfig"
	"github.com/RobinUS2/claude-guard/internal/store"
	"github.com/RobinUS2/claude-guard/internal/version"
)

// cmdDoctor runs a health check and prints a summary. Anything that would
// surprise a user at 2am gets its own line.
//
//	claude-guard doctor
func cmdDoctor(_ []string) int {
	fmt.Printf("claude-guard %s — health check\n", version.Version)
	fmt.Println()

	pass := true
	check := func(name string, ok bool, detail string) {
		mark := "[ok]  "
		if !ok {
			mark = "[fail]"
			pass = false
		}
		fmt.Printf("%s %-34s %s\n", mark, name, detail)
	}
	warn := func(name, detail string) {
		fmt.Printf("[warn] %-34s %s\n", name, detail)
	}
	errf := func(name, detail string) {
		fmt.Printf("[err]  %-34s %s\n", name, detail)
		pass = false
	}

	// 1. Config load
	cfgPath := config.DefaultConfigPath()
	result := config.Load("")
	if result.Warning != nil {
		warn("config", fmt.Sprintf("%s → %v (using defaults)", cfgPath, result.Warning))
	} else {
		check("config", true, cfgPath)
	}
	cfg := result.Config

	// 2. Rule counts
	check("rules:instant_block", len(cfg.InstantBlock) > 0,
		fmt.Sprintf("%d compiled-in rules", len(cfg.InstantBlock)))
	check("rules:instant_allow", len(cfg.InstantAllow) > 0,
		fmt.Sprintf("%d compiled-in rules", len(cfg.InstantAllow)))

	// 3. Log directory writable
	logDir := cfg.Log.Dir
	if logDir == "" {
		logDir = config.DefaultLogDir()
	}
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		check("log:dir", false, err.Error())
	} else {
		check("log:dir", true, logDir)
	}

	// 4. Shadow vs enforce mode
	if cfg.ShadowMode {
		warn("mode", "shadow (decisions logged, not enforced)")
	} else {
		check("mode", true, "enforce")
	}

	home, _ := os.UserHomeDir()

	// 5. LLM provider auto-selection from environment (AutoSelect already
	// tries the token-vault fallback internally, so a nil result here
	// means both env vars and vault lookup came up empty).
	classifier := llm.AutoSelect("anthropic", os.Getenv)
	if classifier == nil {
		if llm.TokenVaultInstalled() {
			// Distinct from "no LLM configured at all": token-vault is set
			// up, so a key was presumably expected to be reachable, but
			// neither an env var nor the scoped token-vault lookup found
			// one right now. Doesn't check whether some OTHER vault is
			// locked/unlocked — that's unrelated to whether the specific
			// Anthropic/Gemini secret this checks for is available.
			warn("llm:provider", "no AI key resolved (env vars and token-vault lookup both empty) — "+
				"commands needing AI review fall through to a manual prompt instead of auto-approval. "+
				"If this is unexpected, check that the relevant token-vault secret is unlocked.")
		} else if os.Getenv("CLAUDECODE") != "" {
			// Under Claude Code (CLAUDECODE=1) this is load-bearing: OAuth
			// does not expose an API key to subprocesses, so the hook's
			// LLM tier silently disables. Commands that need LLM review
			// fall through to a user prompt. Error, not warn.
			errf("llm:provider",
				"no ANTHROPIC_API_KEY / GEMINI_API_KEY in claude-guard subprocess env. Claude Code "+
					"uses OAuth and does NOT export an API key to subprocesses — LLM tier is disabled. "+
					"Commands that don't match tier 1/2 rules will fall through to a user prompt. Fix: "+
					"export ANTHROPIC_API_KEY in your shell profile or .envrc, OR rely on tier-2 "+
					"structural rules only.")
		} else {
			warn("llm:provider", "no API key in env (set ANTHROPIC_API_KEY or GEMINI_API_KEY)")
		}
	} else {
		check("llm:provider", true, fmt.Sprintf("%s (model=%s)", classifier.Provider(), classifier.Model()))
	}

	// 6. LLM circuit breaker state
	circuitPath := filepath.Join(home, ".cache", "claude-guard", "llm-circuit.json")
	br := breaker.New(circuitPath)
	state, _ := br.State()
	switch {
	case state == nil || state.Status == "" || state.Status == "closed":
		check("llm:circuit", true, "closed")
	case state.Status == "open":
		warn("llm:circuit",
			fmt.Sprintf("OPEN until %s (reason=%s, fails=%d, last=%s)",
				state.OpenUntil.Local().Format("15:04:05"),
				state.Reason,
				state.ConsecutiveFailures,
				state.LastError))
	default:
		warn("llm:circuit", state.Status)
	}

	// 6a. Release freeze
	freezeNow := time.Now()
	if fs, ferr := freeze.Load(freeze.DefaultPath()); ferr != nil {
		warn("freeze", fmt.Sprintf("malformed freeze file (%v) — treated as NOT frozen", ferr))
	} else if fs == nil {
		if es := freeze.EnvState(os.Getenv); es != nil {
			warn("freeze", fmt.Sprintf("CLAUDE_GUARD_FREEZE env active (this shell): %s", strings.Join(es.FrozenEnvs, ",")))
		} else {
			check("freeze", true, "none active")
		}
	} else if fs.Expired(freezeNow) {
		warn("freeze", fmt.Sprintf("EXPIRED %s (lapsed %s) — run 'claude-guard freeze off' to tidy",
			strings.Join(fs.FrozenEnvs, ","), fs.ExpiresAt.Format("2006-01-02 15:04 MST")))
	} else {
		lifts := "manual"
		if fs.ExpiresAt != nil {
			lifts = "lifts " + fs.ExpiresAt.Format("2006-01-02 15:04 MST")
		}
		warn("freeze", fmt.Sprintf("ACTIVE %s — scope=%s, %s", strings.Join(fs.FrozenEnvs, ","), fs.ScopeLabel(), lifts))
	}

	// 6b. Cache stats
	cacheDir := filepath.Join(home, ".cache", "claude-guard", "verdicts")
	cch := cache.New(cacheDir)
	if cs, err := cch.Stats(); err == nil {
		switch {
		case cs.Entries == 0:
			warn("llm:cache", "empty (will warm up after first LLM calls)")
		default:
			pending := cs.Entries - cs.Verified
			detail := fmt.Sprintf("%d entries (%d verified, %d pending, %d disagreements), %.1f KiB",
				cs.Entries, cs.Verified, pending, cs.Disagree, float64(cs.BytesOnDisk)/1024)
			if cs.Disagree > 0 {
				warn("llm:cache", detail)
			} else {
				check("llm:cache", true, detail)
			}
		}
	}

	// 6b2. Budget status
	cacheRoot := filepath.Join(home, ".cache", "claude-guard")
	bgt := budget.New(cacheRoot, cfg.DailyBudget.LLMCalls, cfg.DailyBudget.FileAnalysisCalls)
	bs := bgt.Status()
	budgetDetail := fmt.Sprintf("%d/%d LLM, %d/%d file-analysis",
		bs.LLMUsed, bs.LLMLimit, bs.FileUsed, bs.FileLimit)
	if bs.LLMUsed >= bs.LLMLimit || bs.FileUsed >= bs.FileLimit {
		warn("budget", budgetDetail+" (EXHAUSTED)")
	} else {
		check("budget", true, budgetDetail)
	}

	// 6b3. SQLite store status
	dbPath := defaultStorePath()
	if info, err := os.Stat(dbPath); err == nil {
		dbSize := float64(info.Size()) / 1024
		db, dbErr := store.Open(dbPath)
		if dbErr != nil {
			warn("sqlite", fmt.Sprintf("%s (open error: %v)", dbPath, dbErr))
		} else {
			defer db.Close()
			vs, _ := db.VerdictStats()
			pendingCount, _ := db.CountPending()
			learnedCount, _ := db.CountLearned()
			historyCount, _ := db.CountMetrics()
			detail := fmt.Sprintf("%.1f KiB, verdicts=%d, pending=%d, learned=%d, snapshots=%d",
				dbSize, vs.Entries, pendingCount, learnedCount, historyCount)
			check("sqlite", true, detail)
		}
	} else {
		check("sqlite", true, "not yet created (will be created on first learn)")
	}

	// 6c. Tier 5 legacy allow list
	legacyPath := filepath.Join(home, ".config", "claude-guard", "legacy-patterns.yaml")
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		legacyPath = filepath.Join(xdg, "claude-guard", "legacy-patterns.yaml")
	}
	if _, err := os.Stat(legacyPath); os.IsNotExist(err) {
		warn("legacy:patterns", "not migrated (run: claude-guard migrate)")
	} else if al, err := legacy.Load(legacyPath); err == nil && al != nil {
		check("legacy:patterns", true,
			fmt.Sprintf("%d patterns loaded from %s", len(al.Patterns), legacyPath))
	} else if err != nil {
		warn("legacy:patterns", err.Error())
	}

	// 6d. Per-project config (if cwd contains one)
	if cwd, err := os.Getwd(); err == nil {
		if projCfg, _ := projectconfig.Load(cwd); projCfg != nil {
			if projCfg.Warning != nil {
				warn("project:config",
					fmt.Sprintf("%s → %v (accepted %d rules)",
						projCfg.Path, projCfg.Warning, len(projCfg.Rules)))
			} else {
				label := projCfg.ProjectName
				if label == "" {
					label = "(no project_name)"
				}
				check("project:config", true,
					fmt.Sprintf("%s [%s, %d rule%s]",
						projCfg.Path, label, len(projCfg.Rules),
						plural(len(projCfg.Rules))))
			}
		}
	}

	// 7. Claude Code settings.json hook wiring
	settingsPath := filepath.Join(home, ".claude", "settings.json")
	wired, detail := checkHookWired(settingsPath)
	if wired {
		check("hook:wired", true, detail)
	} else {
		warn("hook:wired", detail)
	}
	stopWired, stopDetail := checkStopHookWired(settingsPath)
	if stopWired {
		check("hook:stop", true, stopDetail)
	} else {
		warn("hook:stop", stopDetail)
	}
	learnWired, learnDetail := checkLearnHookWired(settingsPath)
	if learnWired {
		check("hook:learn", true, learnDetail)
	} else {
		warn("hook:learn", learnDetail+" (self-learning disabled)")
	}

	// 7a. Settings.json credential scan
	credCount := scanSettingsCredentials(settingsPath)
	if credCount > 0 {
		warn("settings:credentials",
			fmt.Sprintf("%d entries in settings.json contain potential credentials (API tokens, passwords)", credCount))
	} else {
		check("settings:credentials", true, "no credentials detected in permissions.allow")
	}

	// 7b. Settings.json entry count
	if entryCount := countSettingsEntries(settingsPath); entryCount > 100 {
		warn("settings:bloat",
			fmt.Sprintf("%d entries in permissions.allow — consider running 'claude-guard settings audit'", entryCount))
	}

	// 8. Binary self-location
	self, err := os.Executable()
	if err == nil {
		expected := filepath.Join(home, ".claude", "bin", "claude-guard")
		if self == expected {
			check("binary:location", true, self)
		} else {
			warn("binary:location", fmt.Sprintf("%s (expected %s)", self, expected))
		}
	}

	paths := clog.DefaultPaths(logDir)
	fmt.Println()
	fmt.Println("log files:")
	fmt.Printf("  decisions (firehose):  %s\n", paths.Decisions)
	fmt.Printf("  denies (audit trail):  %s\n", paths.Denies)
	fmt.Printf("  app  (startup/errors): %s\n", paths.App)
	fmt.Println()
	fmt.Println("tips:")
	fmt.Println("  watch all decisions:           claude-guard monitor")
	fmt.Println("  watch only blocks:             claude-guard monitor --file denies")
	fmt.Println("  raw JSONL for jq:              claude-guard monitor --json | jq .")
	fmt.Println("  test a command interactively:  claude-guard test 'git status'")
	fmt.Println()
	if pass {
		fmt.Println("overall: OK")
		return 0
	}
	fmt.Println("overall: PROBLEMS FOUND — see lines marked [fail] or [err]")
	return 1
}

// plural returns "s" unless n == 1. For table output cosmetics only.
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// checkStopHookWired reports whether a Stop hook pointing to claude-guard stop
// is registered in settings.json.
func checkStopHookWired(settingsPath string) (bool, string) {
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		return false, fmt.Sprintf("cannot read %s: %v", settingsPath, err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return false, fmt.Sprintf("%s not valid JSON: %v", settingsPath, err)
	}
	hooks, _ := parsed["hooks"].(map[string]any)
	stopHooks, _ := hooks["Stop"].([]any)
	for _, entry := range stopHooks {
		m, _ := entry.(map[string]any)
		inner, _ := m["hooks"].([]any)
		for _, h := range inner {
			hm, _ := h.(map[string]any)
			if cmd, _ := hm["command"].(string); strings.Contains(cmd, "claude-guard stop") {
				return true, cmd
			}
		}
	}
	return false, fmt.Sprintf("no Stop hook pointing to 'claude-guard stop' in %s", settingsPath)
}

func checkLearnHookWired(settingsPath string) (bool, string) {
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		return false, fmt.Sprintf("cannot read %s: %v", settingsPath, err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return false, fmt.Sprintf("%s not valid JSON: %v", settingsPath, err)
	}
	hooks, _ := parsed["hooks"].(map[string]any)
	postHooks, _ := hooks["PostToolUse"].([]any)
	for _, entry := range postHooks {
		m, _ := entry.(map[string]any)
		inner, _ := m["hooks"].([]any)
		for _, h := range inner {
			hm, _ := h.(map[string]any)
			if cmd, _ := hm["command"].(string); strings.Contains(cmd, "claude-guard learn") {
				return true, cmd
			}
		}
	}
	return false, fmt.Sprintf("no PostToolUse hook pointing to 'claude-guard learn' in %s", settingsPath)
}

// checkHookWired reads settings.json and reports whether a PreToolUse
// Bash hook points to our binary. Best-effort: any parse failure just
// returns "not found".
func checkHookWired(settingsPath string) (bool, string) {
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		return false, fmt.Sprintf("cannot read %s: %v", settingsPath, err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return false, fmt.Sprintf("%s not valid JSON: %v", settingsPath, err)
	}
	hooks, _ := parsed["hooks"].(map[string]any)
	if hooks == nil {
		return false, fmt.Sprintf("no hooks key in %s", settingsPath)
	}
	pre, _ := hooks["PreToolUse"].([]any)
	if pre == nil {
		return false, fmt.Sprintf("no PreToolUse hook in %s", settingsPath)
	}
	for _, entry := range pre {
		m, _ := entry.(map[string]any)
		matcher, _ := m["matcher"].(string)
		if !strings.EqualFold(matcher, "Bash") {
			continue
		}
		inner, _ := m["hooks"].([]any)
		for _, h := range inner {
			hm, _ := h.(map[string]any)
			cmd, _ := hm["command"].(string)
			if strings.Contains(cmd, "claude-guard") {
				return true, cmd
			}
		}
	}
	return false, fmt.Sprintf("no Bash hook pointing to claude-guard in %s", settingsPath)
}

// scanSettingsCredentials counts permission entries that appear to contain
// credentials (API tokens, passwords, bearer tokens). Best-effort pattern
// matching — not a security scanner.
func scanSettingsCredentials(settingsPath string) int {
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		return 0
	}
	var parsed struct {
		Permissions struct {
			Allow []string `json:"allow"`
		} `json:"permissions"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return 0
	}
	credPatterns := []string{
		"ATATT3x", // Atlassian API token prefix
		"Bearer ",
		"token=",
		"password=",
		"secret=",
		"api_key=",
		"apikey=",
		"Authorization:",
		"ghp_", // GitHub personal access token
		"gho_", // GitHub OAuth token
		"sk-",  // OpenAI/Stripe key prefix
	}
	count := 0
	for _, entry := range parsed.Permissions.Allow {
		for _, pat := range credPatterns {
			if strings.Contains(entry, pat) {
				count++
				break
			}
		}
	}
	return count
}

// countSettingsEntries returns the number of entries in permissions.allow.
func countSettingsEntries(settingsPath string) int {
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		return 0
	}
	var parsed struct {
		Permissions struct {
			Allow []string `json:"allow"`
		} `json:"permissions"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return 0
	}
	return len(parsed.Permissions.Allow)
}
