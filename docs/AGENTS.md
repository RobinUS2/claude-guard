# Agent Integration Guide: Antigravity & Gemini

This document explains how AI agents (like Antigravity, Gemini, or Claude) can use `claude-guard` to safely execute terminal commands.

## Overview

`claude-guard` provides a multi-tier security gate for terminal commands. Agents should use the `test` subcommand to "pre-flight" any command they intend to run.

## Integration Workflow

### 1. Locate the Binary
The `claude-guard` binary is typically built into the `bin/` directory of this repository.

### 2. Run a Pre-flight Check
Before executing any `run_command` or terminal task, the agent should run:
```bash
./bin/claude-guard test "<command>"
```

### 3. Interpret the Verdict
The command will return a JSON-like text output (or structured JSON via the `decide` command) with a `verdict`:

- **`verdict: allow`**: The command is safe. 
    - If `tier: instant_allow`, the agent can consider the command "SafeToAutoRun" (low risk, no user prompt needed if the agent's own rules allow it).
- **`verdict: deny`**: The command is dangerous or violates policy.
    - The agent **MUST NOT** execute the command.
    - The agent should report the `reason` and `rule` to the user.
- **`verdict: continue`**: No deterministic rule matched.
    - The agent should treat this as "manual review required" and prompt the user for approval.

## Example Usage

**Agent wants to run `ls -la`:**
```bash
./bin/claude-guard test "ls -la"
# Output: verdict: allow, tier: instant_allow, rule: posix-readonly
# Agent Action: Run command, potentially with SafeToAutoRun: true.
```

**Agent wants to run `rm -rf /`:**
```bash
./bin/claude-guard test "rm -rf /"
# Output: verdict: deny, tier: instant_block, rule: rm-rf-system
# Agent Action: Refuse to run, explain the safety violation to the user.
```

## Security Tiers
- **Tier 1 (Instant Block)**: Hard-coded AST rules for dangerous patterns.
- **Tier 2 (Instant Allow)**: Hard-coded AST rules for safe, read-only commands.
- **Tier 3 (Cache)**: Previous LLM-verified verdicts.
- **Tier 4 (LLM)**: Semantic safety check using high-reasoning models.
