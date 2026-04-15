package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/RobinUS2/claude-guard/internal/config"
	clog "github.com/RobinUS2/claude-guard/internal/log"
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

	// 5. LLM toggle
	if cfg.LLM.Enabled {
		key := os.Getenv(cfg.LLM.APIKeyEnv)
		if key == "" {
			check("llm:enabled", false,
				fmt.Sprintf("enabled but %s is not set", cfg.LLM.APIKeyEnv))
		} else {
			check("llm:enabled", true,
				fmt.Sprintf("%s, %s set", cfg.LLM.Model, cfg.LLM.APIKeyEnv))
		}
	} else {
		warn("llm", "disabled (Phase 1 default)")
	}

	// 6. Claude Code settings.json hook wiring
	home, _ := os.UserHomeDir()
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
