# Technical Architecture: claude-guard

This document provides a deep dive into how `claude-guard` evaluates commands and tools.

## The Bash Pipeline

Every Bash command is routed through a six-tier pipeline:

1.  **Instant block (AST-based)** — `rm -rf` on system dirs, `curl | sh`, force-push to protected branches, `sudo`, credential exfil patterns. Matches against parsed command nodes, not raw strings.
2.  **Instant allow (AST-based)** — read-only commands (`ls`, `cat`, `git status`, `gcloud ... list`, `terraform plan`, `kubectl get pods`, etc.) but only when they have no pipes, subshells, command substitution, or redirections (other than `2>&1`).
3.  **Cache** — prior verdicts keyed by `sha256(tool + command + cwd + branch + prompt_version + config_hash)`.
4.  **LLM classifier (approve-only)** — Haiku 4.5 judges semantic safety. Can only auto-approve; blocks stay deterministic.
5.  **Legacy allow list** — migrated glob patterns from your existing `settings.json` `permissions.allow`.
6.  **Default** — fall through to normal agent user prompt.

## Tool Evaluators

Each tool is routed to a dedicated evaluator:

-   **Bash** — shell AST analysis (see above).
-   **Read / Write / Edit** — CWD scope check + secret scan + protected-path deny (`.ssh/`, `.aws/credentials`, `.bashrc`, etc.).
-   **WebFetch / WebSearch** — SSRF guards (loopback, private CIDRs, cloud metadata, `file://`, `gopher://`) + credential-path deny.
-   **Agent / MCP** — structural allowlist for harness-only tools; read-verb heuristic for other MCPs; writes fall through to LLM tier.

## Known Limits

-   **`NestedSubcommandAllow` matches the FIRST or LAST positional against the safe-verb list.** So `gcloud projects list` and `kubectl get pods` both auto-allow, but `gcloud projects describe my-project` does not.
-   **Binary Shadowing**: The hook binary is resolved in multiple places. Always use `make install` to ensure consistency between `~/.claude/bin/claude-guard` and your `$PATH`.
-   **Strict Identifier Check**: `gsutil ls gs://my-bucket` does NOT auto-allow because arbitrary URLs are not implicitly trusted by structural rules.

## Design Philosophy

The core philosophy is **Deterministic Deny, Semantic Allow**. We use hard-coded AST rules to block known-bad patterns with 100% certainty, while using LLMs to safely broaden the set of "allowable" commands based on context.
