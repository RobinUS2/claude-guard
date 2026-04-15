# claude-guard

Smart PreToolUse guard for Claude Code. AST-based deterministic deny, semantic LLM-assisted allow, with a legacy glob fallback during migration.

**Status:** Phase 1 — core scaffolding in progress.

## What it does

Runs as a `PreToolUse` hook on the `Bash` tool. Every Bash command Claude Code is about to run is parsed into a shell AST and evaluated against a tiered rule engine:

1. **Instant block** (AST-based) — `rm -rf` on system dirs, `curl | sh`, force-push to protected branches, `sudo`, credential exfil patterns. Matches against parsed command nodes, not raw strings, so `R=rm; $R -rf /` is caught the same as `rm -rf /`.
2. **Instant allow** (AST-based) — read-only commands (`ls`, `cat`, `git status`, `gcloud ... list`, `terraform plan`, etc.) but only when they have no redirections, pipes, subshells, or command substitution.
3. **Cache** — prior verdicts keyed by `sha256(tool + command + cwd + branch + prompt_version + config_hash)`.
4. **LLM classifier** (approve-only) — Haiku 4.5 judges semantic safety. Can only auto-approve; blocks stay deterministic.
5. **Legacy allow list** — migrated glob patterns from your existing `settings.json` `permissions.allow`.
6. **Default** — fall through to normal Claude Code user prompt.

Design doc: [`docs/plans/2026-04-15-claude-guard.md`](https://github.com/RobinUS2/cto-as-a-service/blob/main/docs/plans/2026-04-15-claude-guard.md) (in the cto-as-a-service repo).

## Quickstart

```bash
make build          # builds bin/claude-guard
make install        # installs to ~/.claude/bin/claude-guard
make test           # go test -race ./...
make check          # fmt + vet + test
```

## CLI

```
claude-guard decide                         # hook entrypoint (reads PreToolUse JSON on stdin)
claude-guard test "<command>" [--live]      # dry-run a command through the tiers
claude-guard explain [-n 20]                # last N decisions from log
claude-guard replay <log-id>                # re-run a historical decision with current config
claude-guard stats [--since 1d]             # tier-hit counts, cache hit rate, LLM latency
claude-guard doctor                         # health check: config, schema, API key, hook wiring
claude-guard migrate [--verify]             # settings.json allow-list → legacy-patterns.yaml
claude-guard lint                           # validate config.yaml + rule self-tests
claude-guard eval-prompt                    # run classifier against eval corpus
claude-guard bench                          # engine latency against a corpus (no LLM)
claude-guard version
```

## License

TBD (private)
