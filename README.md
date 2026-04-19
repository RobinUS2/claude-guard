# claude-guard

Smart PreToolUse guard for Claude Code. AST-based deterministic deny, semantic LLM-assisted allow, with a legacy glob fallback during migration.

**Status:** Phase 1 — core scaffolding in progress.

## What it does

Runs as a `PreToolUse` hook on every tool Claude Code invokes. Each tool is routed to a dedicated evaluator:

- **Bash** — shell AST analysis. The same six-tier pipeline applies: instant block / instant allow / cache / LLM classifier / legacy globs / default user prompt.
- **Read / Write / Edit** — CWD scope check + secret scan + protected-path deny (`.ssh/`, `.aws/credentials`, `.bashrc`, etc.).
- **WebFetch / WebSearch** — SSRF guards (loopback, private CIDRs, cloud metadata, `file://`, `gopher://`) + credential-path deny.
- **Agent / MCP** — structural allowlist for harness-only tools (`Agent`, `ToolSearch`, `TodoWrite`, `mcp__ccd_session__*`, `mcp__mcp-registry__*`); read-verb heuristic for other MCPs (`list-*`, `get-*`); writes fall through to LLM tier.
- **Everything else** — fall through to LLM, or to the user prompt if no LLM is configured.

The Bash six-tier pipeline:

1. **Instant block** (AST-based) — `rm -rf` on system dirs, `curl | sh`, force-push to protected branches, `sudo`, credential exfil patterns. Matches against parsed command nodes, not raw strings, so `R=rm; $R -rf /` is caught the same as `rm -rf /`.
2. **Instant allow** (AST-based) — read-only commands (`ls`, `cat`, `git status`, `gcloud ... list`, `terraform plan`, `kubectl get pods`, etc.) but only when they have no pipes, subshells, command substitution, or redirections (other than `2>&1`).
3. **Cache** — prior verdicts keyed by `sha256(tool + command + cwd + branch + prompt_version + config_hash)`.
4. **LLM classifier** (approve-only) — Haiku 4.5 judges semantic safety. Can only auto-approve; blocks stay deterministic.
5. **Legacy allow list** — migrated glob patterns from your existing `settings.json` `permissions.allow`.
6. **Default** — fall through to normal Claude Code user prompt.

Design doc: [`docs/plans/2026-04-15-claude-guard.md`](https://github.com/RobinUS2/cto-as-a-service/blob/main/docs/plans/2026-04-15-claude-guard.md) (in the cto-as-a-service repo).

## Known limits

- **`NestedSubcommandAllow` matches the FIRST or LAST positional against the safe-verb list.** So
  `gcloud projects list` and `kubectl get pods` both auto-allow, but `gcloud projects describe my-project`
  does not (`my-project` is the tail and isn't a safe verb). Falls through to the LLM tier — or the user
  prompt when no LLM key is set.
- **Under Claude Code, no API key is exported to subprocesses.** Claude Code uses OAuth, so the hook's
  LLM tier is silently disabled inside `claude-guard decide`. Commands that don't match a tier-1 or
  tier-2 rule fall through to a `continue` verdict and the user is prompted. Two fixes:
  1. `export ANTHROPIC_API_KEY=...` in your shell profile / `.envrc` so the subprocess inherits it; or
  2. Rely on tier-2 only and accept user prompts for everything else.
  `claude-guard doctor` flags this as ERROR-level (not just warn) when `CLAUDECODE=1` is detected.
- **`gsutil ls gs://my-bucket` does NOT auto-allow** — the positional `gs://my-bucket` fails the safe-identifier
  check (`/`, `:` not allowed). `gsutil ls` (bare) does. This is intentional: arbitrary paths/URLs
  shouldn't be implicitly trusted by structural rules.

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

## Optional: vault gate

[`scripts/claude-guard-vault-gate`](scripts/claude-guard-vault-gate) is a PreToolUse
wrapper that requires an unlocked [`token-vault`](https://github.com/RobinUS2/token-vault)
session before any Bash command runs. When the vault is locked it emits a
deny decision that tells Claude to stop and ask the user to unlock. See
[`docs/vault-gate.md`](docs/vault-gate.md) for wire-up and testing.

## License

TBD (private)
