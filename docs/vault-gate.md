# Vault gate

`bin/claude-guard-vault-gate` is an optional PreToolUse wrapper for the `Bash`
matcher. It requires at least one `token-vault` to be unlocked before any
shell command can run. When the vault is locked it emits a deny decision
whose `permissionDecisionReason` instructs Claude to stop and ask the user
to unlock — so the assistant surfaces the gate instead of silently failing.

This is useful when secrets referenced by shell work (API keys, service
account impersonation tokens, customer credentials) live in a
[`token-vault`](https://github.com/RobinUS2/token-vault)-style session store
and you don't want Claude to attempt commands against a locked vault.

## Behaviour

Stdin: the standard PreToolUse JSON payload from Claude Code.

1. Run `token-vault status`. Output is captured from stderr (where the
   real `token-vault` prints) merged into stdout.
2. If the output contains `[unlocked` for any vault → fall through:
   source `~/.config/claude-guard/keys.env` if present, then forward the
   original stdin to `claude-guard decide`. The regular six-tier
   classifier runs unchanged.
3. Otherwise → emit a PreToolUse decision:

   ```json
   {
     "hookSpecificOutput": {
       "hookEventName": "PreToolUse",
       "permissionDecision": "deny",
       "permissionDecisionReason": "claude-guard: token vault is locked. Stop here and ask the user to unlock before running any shell command. Suggested: `token-vault decrypt --all` (or `token-vault decrypt <customer>` for a single vault). Do not retry this tool call until the user confirms the vault is unlocked."
     }
   }
   ```

   Claude receives the `reason` as the block message and stops retrying.

## Installation

Copy or symlink the script somewhere on your filesystem and reference it
from a PreToolUse hook with matcher `Bash`:

```bash
cp scripts/claude-guard-vault-gate ~/.claude/bin/claude-guard-vault-gate
chmod +x ~/.claude/bin/claude-guard-vault-gate
```

Then in `~/.claude/settings.json`, **replace** the existing
`claude-guard decide` Bash hook entry (the gate forwards to it when
unlocked, so you don't want to run it twice):

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

Both are useful for tests (shim with a fake binary) and for non-standard
install locations.

## Choosing the matcher

The gate is scoped to **`Bash` only**. Earlier iterations used an all-tools
matcher (`""`), but that blocks `Read`, `Grep`, `Glob` etc. — Claude can't
even investigate the repo to tell the user what's going on. Bash-only is
the minimum scope that still gates anything the vault is likely to be
needed for.

If you need the gate on more tools, add additional matchers pointing at
the same script — but expect a degraded experience when locked.

## Testing locally

Unlocked path (forwards to `claude-guard decide`):

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"ls"}}' \
  | ./scripts/claude-guard-vault-gate
# → {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow",...}}
```

Locked path via a fake `token-vault` shim:

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
# → {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",...}}
```

## Known limits

- **No real cryptographic enforcement.** The gate trusts `token-vault
  status`. Anyone who can run the gate can also run `token-vault decrypt`.
  This is a workflow gate, not an authz boundary.
- **`token-vault status` writes to stderr.** The gate merges stderr into
  stdout before grepping. If your `token-vault` fork changes the output
  format, update the grep pattern (currently `\[unlocked`).
- **Unlock state scope.** `token-vault` persists lease state to a file
  readable from any shell, so the hook's subshell sees the same state as
  your interactive shell. Implementations that store state in environment
  variables only won't work with this gate without modification.
