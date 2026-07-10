# Vault gate

`bin/claude-guard-vault-gate` is an optional PreToolUse wrapper for the `Bash`
matcher. It loads `~/.config/claude-guard/keys.env` (if present) into the
environment, then forwards unconditionally to `claude-guard decide`. That's
the whole job — it does not gate on vault lock state at all.

This is useful when your Anthropic/Gemini API key (used by claude-guard's
own LLM classification tier) lives in a
[`token-vault`](https://github.com/RobinUS2/token-vault)-style session
store rather than a plain environment variable.

## Why this doesn't check vault lock state anymore

Two earlier versions of this script tried to answer "is it safe to proceed"
by checking `token-vault status` for a lock/unlock marker:

- v1 denied every Bash command outright when no vault was unlocked. This
  deadlocked: unlocking a vault needs an interactive passphrase Claude
  can't supply through the Bash tool, so if nobody was around to unlock
  it, Claude couldn't even run harmless read-only commands (`git status`,
  `go build`, `ls`) to explain what was stuck.
- v2 replaced the deny with a warn-and-forward default, plus an opt-in
  `CLAUDE_GUARD_VAULT_GATE_STRICT` toggle back to denying. This still broke
  in practice: the token-vault CLI's tiered rewrite silently stopped
  printing lock-state text in `status` output at all, so the grep this
  script depended on never matched — meaning strict mode denied *every*
  command regardless of whether anything was actually unlocked, in every
  session using it, the moment it shipped.

The deeper problem both versions shared: **"is some vault unlocked
somewhere" was never the right question.** This hook only cares about one
thing — can claude-guard get the Anthropic/Gemini key it uses for its own
LLM classification tier. A Standard-tier customer being unlocked (or
locked) says nothing about whether that specific key is available, and
`token-vault status`'s output format isn't a stable contract to grep
against — it already changed shape once and silently broke this exact
check.

The precise question is already answered correctly elsewhere:
`llm.LookupTokenVaultAnthropic()` (in the claude-guard Go binary) tries the
specific candidate `(vault, secret)` pairs directly, with its own bounded
timeout, independent of any other vault's lock state. So this script no
longer duplicates that logic at all — it just loads `keys.env` (a plain
local file, not the vault itself, so no lock-state check is needed to read
it either) and forwards. `claude-guard decide` already falls through to a
manual confirmation prompt when no key is available and nothing else
resolves the command; see `CLAUDE_GUARD_REQUIRE_LLM` below if you want that
case to deny instead.

## Behaviour

Stdin: the standard PreToolUse JSON payload from Claude Code.

1. If `~/.config/claude-guard/keys.env` exists and is owner-only (not
   group- or world-readable), parse it line-by-line (`KEY=VALUE`, no
   `source`/eval) and export each variable.
2. Forward stdin to `claude-guard decide` unconditionally.

That's it — no vault status check, no deny path, no strict/bypass modes in
this script. `claude-guard decide` handles the "no LLM key available" case
itself, using the scoped candidate lookup described above.

## Making "no LLM key" deny instead of fall through

Set `CLAUDE_GUARD_REQUIRE_LLM=1` on the hook command line (inherited by
`claude-guard decide` via `exec`, since this wrapper doesn't need to know
about it at all):

```json
{
  "type": "command",
  "command": "CLAUDE_GUARD_REQUIRE_LLM=1 /path/to/claude-guard-vault-gate"
}
```

When set, `claude-guard decide`'s Tier 6 (the final fallback, reached only
when nothing else — Tier 1 block, Tier 2 allow, cache, LLM, legacy list —
already resolved the command) denies instead of falling through, but only
when the reason Tier 4 didn't run is specifically "no classifier available"
(`e.llm == nil` — env vars and the scoped token-vault lookup both came up
empty). It does not fire when:
- a classifier *is* available but returned an unsure/unsafe verdict (that
  case already falls through by design — the LLM tier is approve-only), or
- Tier 4 was skipped for an unrelated reason (LLM daily budget exhausted,
  circuit breaker open) — those already have their own `SkipReason` and
  shouldn't be reported as "no key configured".

Off by default: most setups never configure an LLM key at all, and denying
every unmatched command in that case would be a surprising default.

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

- `CLAUDE_GUARD_BIN` — path to the `claude-guard` binary (default:
  `claude-guard` on `PATH`). Useful for tests and non-standard install
  locations.
- `CLAUDE_GUARD_REQUIRE_LLM` — see above. Read directly by `claude-guard
  decide`, not by this wrapper.

## Choosing the matcher

The gate is scoped to **`Bash` only** — the only tool where an LLM
classification tier is relevant in the first place.

If you want key-loading on more tools, add additional matchers pointing
at the same script.

## Testing locally

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"ls"}}' \
  | ./scripts/claude-guard-vault-gate
# → {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow",...}}
```

An ambiguous command with no LLM key available and `CLAUDE_GUARD_REQUIRE_LLM`
unset falls through to no verdict (Claude Code's own permission prompt
decides):

```bash
env -i HOME="$HOME" PATH=/usr/bin:/bin CLAUDE_GUARD_BIN=claude-guard \
  ./scripts/claude-guard-vault-gate <<< '{"tool_name":"Bash","tool_input":{"command":"some-random-custom-script.sh --deploy"}}'
# stdout → {}
```

Same, with `CLAUDE_GUARD_REQUIRE_LLM=1`:

```bash
env -i HOME="$HOME" PATH=/usr/bin:/bin CLAUDE_GUARD_BIN=claude-guard CLAUDE_GUARD_REQUIRE_LLM=1 \
  ./scripts/claude-guard-vault-gate <<< '{"tool_name":"Bash","tool_input":{"command":"some-random-custom-script.sh --deploy"}}'
# stdout → {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",...}}
```

(`env -i` with a bare `PATH=/usr/bin:/bin` is only needed to prove the
deny path in an environment that has no real key configured anywhere —
in practice, if you already have `ANTHROPIC_API_KEY`/`GEMINI_API_KEY` set
or a working token-vault, decide will find a real key and this won't
trigger.)

## Known limits

- **No real cryptographic enforcement.** Anyone who can run this gate can
  also run `token-vault decrypt` or read `keys.env` directly. This is a
  workflow convenience, not an authz boundary.
- **`keys.env` covers Gemini too; the Go-level token-vault lookup is
  Anthropic-only.** `llm.LookupTokenVaultAnthropic()` only tries Anthropic
  candidate secrets. If your Gemini key lives in a vault rather than an
  env var, `keys.env` (populated by you, however you like) is currently
  the only path that gets it into claude-guard's environment.
