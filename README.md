# 🛡️ claude-guard

**Smart Security Guard for AI Agents.**

`claude-guard` is a high-performance security gate designed to protect your system from dangerous commands executed by AI agents (like Claude Code, Antigravity, or Gemini). It uses AST-based deterministic rules combined with semantic LLM classification to ensure every command is safe before it runs.

## 🚀 Key Features

- **AST-Based Analysis**: Parses shell commands into Abstract Syntax Trees (AST) to detect obfuscated attacks (e.g., `R=rm; $R -rf /` is caught as `rm -rf /`).
- **Six-Tier Pipeline**: 
  1. **Instant Block**: Hard-coded rules for system-critical paths.
  2. **Instant Allow**: Auto-approves safe, read-only commands (`ls`, `cat`, etc.).
  3. **Cache**: High-speed lookup for previously verified commands.
  4. **LLM Classifier**: Uses models like Claude Haiku to judge semantic safety.
  5. **Legacy Allow List**: Compatibility with existing glob-based permissions.
  6. **Human-in-the-loop**: Falls back to user prompt if no verdict is reached.
- **SSRF Protection**: Guards for `WebFetch`, `WebSearch`, and WebSocket `Monitor` targets.
- **Every Shell Path Covered**: `Bash` and `Monitor` both execute shell commands, so both run the identical tier pipeline. Wire the PreToolUse matcher as `Bash|Monitor` — a `Bash`-only matcher leaves `Monitor` commands unreviewed.
- **Cross-Provider Verification**: Optional second-opinion from a different LLM provider to defend against prompt injection.
- **Release Freeze**: An operator-toggled deploy lock enforced for every agent in every session — hard-blocks confident release commands, asks on ambiguous ones, scoped by environment and project. See below.

## 🧊 Release Freeze

Lock deploy/release commands during a code-freeze window. Enforced in Tier 1 for **all agents, all sessions** — no agent can bypass a freeze.

```bash
# Freeze prod releases for one project (leaves other repos shipping)
claude-guard freeze on --project ai-site-gen --reason "v2 launch prep"

# Freeze prod + staging with an auto-expiry
claude-guard freeze on --env prod,staging --until 2026-07-14T18:00

claude-guard freeze status          # what's frozen, scope, when it lifts
claude-guard freeze off --env prod  # lift one env
claude-guard freeze off             # lift everything
```

Behavior when a freeze is active (**"in doubt, ask; else hard block"**):

| Command | Outcome |
|---|---|
| Confident deploy — `make release`, `gcloud run deploy`, `make provision-prod` | **DENY** (hard block) |
| Ambiguous — `terraform apply`, `git push origin main` | **ASK** (dialog names the freeze) |
| Staging deploy under a prod freeze, dry-runs (`terraform plan`, `make provision-diff`), feature-branch push | **pass through** |

**Scope** — `--env prod|staging|dev|all` (default `prod`); `--project <substring>` matches the repo's origin remote (omit = all repos). A `CLAUDE_GUARD_FREEZE=prod` env var freezes just the current shell's agents. Genuine security denies (`rm -rf /`) still win over a freeze; a freeze never downgrades them to an ask.

## 🛠️ Quick Start

### Installation

```bash
make build          # Build the binary
make install        # Install to ~/.claude/bin/claude-guard
```

### Usage for Agents

Agents can "pre-flight" any command using the `test` command:

```bash
./bin/claude-guard test "ls -la"
# Output: verdict: allow (safe to run)

./bin/claude-guard test "rm -rf /"
# Output: verdict: deny (blocked)
```

For detailed agent integration, see [docs/AGENTS.md](docs/AGENTS.md).

## 📖 Documentation

- [Agent Integration Guide](docs/AGENTS.md)
- [Technical Architecture](docs/TECHNICAL.md)
- [Vault Gate (Security Wrapper)](docs/vault-gate.md)

## ⚖️ License

Licensed under the [Apache License, Version 2.0](LICENSE).
