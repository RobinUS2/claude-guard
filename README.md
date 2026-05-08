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
- **SSRF Protection**: Guards for `WebFetch` and `WebSearch` tools.
- **Cross-Provider Verification**: Optional second-opinion from a different LLM provider to defend against prompt injection.

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
