// claude-guard is a PreToolUse hook for Claude Code that makes smart
// allow/deny decisions on Bash commands via AST-based rules, a cached
// semantic LLM classifier, and a legacy glob fallback.
//
// See docs/plans/2026-04-15-claude-guard.md in the cto-as-a-service repo.
package main

import (
	"fmt"
	"os"

	"github.com/RobinUS2/claude-guard/internal/version"
)

const usage = `claude-guard — smart PreToolUse guard for Claude Code

Usage:
  claude-guard <subcommand> [args]

Subcommands:
  decide              hook entrypoint (reads PreToolUse JSON on stdin, emits decision on stdout)
  test <command>      dry-run a command through the tiers (use --live to hit the real LLM)
  monitor [--since N] live-tail the decisions log with pretty-printing
  explain [-n N]      last N decisions from the log
  replay <log-id>     re-run a historical decision with the current config
  stats               tier-hit counts, cache hit rate, LLM latency
  doctor              health check: config, schema, API key, hook wiring
  migrate             settings.json allow-list → legacy-patterns.yaml
  backup [--dest D]   copy logs + cache + config to backup destination (default: Google Drive)
  cache <sub>         inspect/prune the verdict cache: stats, prune, clear
  stats [--since T]   aggregate decisions.jsonl: verdicts, tiers, latency, cache hit rate
  explain <id|--last> re-run a historical decision against the current rules
  dashboard           web dashboard: live stats, decisions, cache, learned patterns
  settings <sub>   audit/migrate settings.json permissions
  lint                validate config + run the adversarial corpus as self-tests
  trust "<cmd>"       override a verifier disagreement (future cache hits ALLOW)
  init-project-config write a starter .claude-guard.yml in cwd for per-project allow rules
  lint                validate config.yaml and run bundled rule tests
  eval-prompt         run the classifier against the eval corpus
  bench               engine latency against a corpus (no LLM)
  version             print version
  help                this message

Design doc: docs/plans/2026-04-15-claude-guard.md (cto-as-a-service repo)
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}

	switch args[0] {
	case "decide":
		return cmdDecide(args[1:])
	case "test":
		return cmdTest(args[1:])
	case "monitor", "tail":
		return cmdMonitor(args[1:])
	case "explain":
		return cmdExplain(args[1:])
	case "replay":
		return cmdReplay(args[1:])
	case "stats":
		return cmdStats(args[1:])
	case "stop":
		return cmdStop(args[1:])
	case "doctor":
		return cmdDoctor(args[1:])
	case "migrate":
		return cmdMigrate(args[1:])
	case "backup":
		return cmdBackup(args[1:])
	case "cache":
		return cmdCache(args[1:])
	case "learn":
		return cmdLearn(args[1:])
	case "settings":
		return cmdSettings(args[1:])
	case "trust":
		return cmdTrust(args[1:])
	case "init-project-config":
		return cmdInitProjectConfig(args[1:])
	case "lint":
		return cmdLint(args[1:])
	case "review":
		return cmdReview(args[1:])
	case "eval-prompt":
		return cmdEvalPrompt(args[1:])
	case "dashboard":
		return cmdDashboard(args[1:])
	case "bench":
		return cmdBench(args[1:])
	case "version", "--version", "-v":
		fmt.Println(version.Version)
		return 0
	case "help", "--help", "-h":
		fmt.Print(usage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %q\n\n", args[0])
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
}
