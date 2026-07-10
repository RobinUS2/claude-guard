# Vault gate

`bin/claude-guard-vault-gate` is an optional PreToolUse wrapper for the `Bash`
matcher. When a `token-vault` is unlocked, it loads
`~/.config/claude-guard/keys.env` (if present) before forwarding to
`claude-guard decide`, so vault-sourced API keys reach the LLM tier without
being exported to your interactive shell. When no vault is unlocked, it
**warns and still forwards** — it no longer blocks the command.

This is useful when your Anthropic/Gemini API key (used by claude-guard's
own LLM classification tier) lives in a
[`token-vault`](https://github.com/RobinUS2/token-vault)-style session
store rather than a plain environment variable.

## Why it doesn't block anymore

An earlier version denied every Bash command outright when no vault was
unlocked, on the theory that shell work might need vault-sourced secrets.
In practice this created a deadlock: unlocking a vault requires an
interactive passphrase prompt that Claude can't supply through the Bash
tool, so if nobody was around to unlock it, Claude couldn't even run
harmless read-only commands (`git status`, `go build`, `ls`) to explain
what was stuck — none of which need a secret at all.

The vault's only real purpose from claude-guard's point of view is
supplying the Anthropic/Gemini key for Tier 4 (the LLM classifier,
approve-only — see `internal/llm`). `claude-guard decide` already handles
a missing key gracefully: Tier 4 is skipped, and the command falls
through the remaining tiers to a manual confirmation prompt if nothing
else resolves it. So the gate no longer duplicates that decision — it
just makes sure the key is loaded when available, and gets out of the
way (with a warning) when it isn't. You still get asked when a call
would have been auto-approved by the AI tier; the difference is that
now you actually get asked, instead of every command being denied
upfront.

## Behaviour

Stdin: the standard PreToolUse JSON payload from Claude Code.

1. Run `token-vault status`. Output is captured from stderr (where the
   real `token-vault` prints) merged into stdout.
2. If the output contains `[unlocked` for any vault → source
   `~/.config/claude-guard/keys.env` if present (safe, owner-only-file
   parsing, no `source`/eval), then forward stdin to `claude-guard
   decide` unchanged.
3. Otherwise → print a warning to stderr (bypass mode: no AI
   classification tier this call), then **still** forward stdin to
   `claude-guard decide` unchanged. No deny is emitted.

`claude-guard decide` itself also detects this condition independently
(via `llm.LookupVaultLockState()`) and prints its own rate-limited
stderr warning plus an app-log entry — so the bypass is visible even if
you invoke `claude-guard decide` directly, without this wrapper.
`claude-guard doctor` reports it too, distinct from "no LLM configured
at all":

```
[warn] llm:provider                       BYPASS MODE: token-vault is installed but locked — no AI key
                                           available. Commands needing AI review fall through to a
                                           manual prompt instead of auto-approval. Run 'token-vault
                                           decrypt --all' to restore it.
```

## Installation

Copy or symlink the script somewhere on your filesystem and reference it
from a PreToolUse hook with matcher `Bash`:

```bash
cp scripts/claude-guard-vault-gate ~/.claude/bin/claude-guard-vault-gate
chmod +x ~/.claude/bin/claude-guard-vault-gate
```

Then in `~/.claude/settings.json`, **replace** the existing
`claude-guard decide` Bash hook entry (the gate forwards to it either
way, so you don't want to run it twice):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/Users/you/.claude/bin/claude-guard-vault-gate"
          }
        ]
      }
    ]
  }
}
```

### Environment overrides

- `TOKEN_VAULT_BIN` — path to the `token-vault` binary (default: `token-vault`
  on `PATH`).
- `CLAUDE_GUARD_BIN` — path to the `claude-guard` binary (default: `claude-guard`
  on `PATH`).
- `CLAUDE_GUARD_VAULT_GATE_STRICT` — set to `1` to deny instead of warn-and-
  forward when no vault is unlocked, restoring the pre-bypass-mode behavior.
  Off by default, since turning it on reintroduces the exact deadlock bypass
  mode exists to avoid — enable it deliberately, in the hook command itself
  (see below), not as a global env var:
  ```json
  {
    "type": "command",
    "command": "CLAUDE_GUARD_VAULT_GATE_STRICT=1 /path/to/claude-guard-vault-gate"
  }
  ```

`TOKEN_VAULT_BIN`/`CLAUDE_GUARD_BIN` are useful for tests (shim with a fake
binary) and for non-standard install locations.

## Choosing the matcher

The gate is scoped to **`Bash` only** — the only tool where an LLM
classification tier is relevant in the first place.

If you want key-loading on more tools, add additional matchers pointing
at the same script.

## Testing locally

Unlocked path (loads keys.env, forwards to `claude-guard decide`):

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"ls"}}' \
  | ./scripts/claude-guard-vault-gate
# → {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow",...}}
```

Locked path via a fake `token-vault` shim — warns, but still forwards
and still gets a normal decide verdict (here `ls` matches a Tier 2 rule
that needs no LLM at all):

```bash
mkdir -p /tmp/fake-vault-bin
cat > /tmp/fake-vault-bin/token-vault <<'EOF'
#!/bin/bash
cat 1>&2 <<'STATUS'
[vault] Token Vaults

  demo  1 secret(s)  [locked]
STATUS
EOF
chmod +x /tmp/fake-vault-bin/token-vault

TOKEN_VAULT_BIN=/tmp/fake-vault-bin/token-vault \
  ./scripts/claude-guard-vault-gate <<< '{"tool_name":"Bash","tool_input":{"command":"ls"}}'
# stderr → claude-guard-vault-gate: WARNING: no token-vault unlocked — running in BYPASS MODE ...
# stdout → {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"tier=instant_allow rule=posix-readonly"}}
```

An ambiguous command that would normally rely on the LLM tier falls
through to no verdict (Claude Code's own permission prompt decides)
instead of being denied:

```bash
TOKEN_VAULT_BIN=/tmp/fake-vault-bin/token-vault \
  ./scripts/claude-guard-vault-gate <<< '{"tool_name":"Bash","tool_input":{"command":"some-random-custom-script.sh --deploy"}}'
# stdout → {}
```

## Known limits

- **No real cryptographic enforcement.** The gate trusts `token-vault
  status`. Anyone who can run the gate can also run `token-vault decrypt`.
  This is a workflow gate, not an authz boundary — it never was one, and
  now that it can't even deny, that's more explicit than before.
- **`token-vault status` writes to stderr.** The gate merges stderr into
  stdout before grepping. If your `token-vault` fork changes the output
  format, update the grep pattern (currently `\[unlocked`).
- **Unlock state scope.** `token-vault` persists lease state to a file
  readable from any shell, so the hook's subshell sees the same state as
  your interactive shell. Implementations that store state in environment
  variables only won't work with this gate without modification.
- **The bypass warning can't distinguish "no vault installed" from
  "vault installed but locked" at the shell-script level** — that
  distinction needs `token-vault status`'s exit behavior, which the
  gate doesn't parse beyond the `[unlocked` grep. `claude-guard doctor`
  and `claude-guard decide`'s own warning (both backed by
  `llm.LookupVaultLockState()`) do make that distinction, since they
  can tell an exec failure (not installed) apart from a locked status
  report.
