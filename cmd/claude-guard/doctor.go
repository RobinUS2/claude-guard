package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/RobinUS2/claude-guard/internal/budget"
	"github.com/RobinUS2/claude-guard/internal/cache"
	"github.com/RobinUS2/claude-guard/internal/config"
	"github.com/RobinUS2/claude-guard/internal/legacy"
	"github.com/RobinUS2/claude-guard/internal/llm"
	"github.com/RobinUS2/claude-guard/internal/llm/breaker"
	clog "github.com/RobinUS2/claude-guard/internal/log"
	"github.com/RobinUS2/claude-guard/internal/projectconfig"
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

	// 5. LLM provider auto-selection from environment
	classifier := llm.AutoSelect("anthropic", os.Getenv)
	if classifier == nil {
		warn("llm:provider", "no API key in env (set ANTHROPIC_API_KEY or GEMINI_API_KEY)")
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

	// 7. Binary self-location
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
	fmt.Println("overall: PROBLEMS FOUND — see lines marked [fail]")
	return 1
}

// plural returns "s" unless n == 1. For table output cosmetics only.
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
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
