# Install safety: never `cp` over a live claude-guard

Replacing the `claude-guard` binary while a Claude Code session is
running will deadlock that session if you do it with `cp`. Use
`install` (or `mv`). This is not a style preference — the failure is
total and it looks like a hang, not a crash.

## What goes wrong

`claude-guard` runs as a PreToolUse hook. Every Bash call in a live
session spawns one, so at almost any moment there is a `claude-guard
decide` process executing from the binary on disk. The vault-gate
wrapper resolves it via `PATH`, which on this machine means
`~/go/bin/claude-guard` rather than `~/.claude/bin/claude-guard`.

`cp` opens the destination with `O_TRUNC` and rewrites it **in place**.
Same inode, same vnode, new contents.

macOS validates code pages lazily, against the vnode, as they fault in.
Go binaries are ad-hoc signed — a spindump shows `Codesigning ID:
a.out`. Rewriting the file invalidates the cached page hashes, so the
kernel sends **SIGKILL** to every process running that image.

That includes the hook process gating the very command doing the copy.
It dies before writing its JSON response to stdout. Claude Code is
blocked waiting on a PreToolUse hook that will never answer, so the
current tool call hangs and every subsequent Bash call queues behind
it. The session is wedged.

The killed hooks get reparented to `launchd` and sit unreaped. A
spindump of one shows the signature of the incident:

```
Process:  claude-guard [1572] (suspended) (zombie)
Path:     /Users/robin/go/bin/claude-guard
Parent:   launchd [1]
Note:     Suspended for 344 samples
Note:     Terminated (zombie) for 344 samples
```

A shell that survives long enough to report anything shows exit code
**137** (128 + 9 = SIGKILL). That is the tell. If you see 137 from a
`claude-guard` invocation right after replacing the binary, you have
already killed the hook — do not keep going.

## Why `install` is safe

From `man install`:

> Historically, `-S` also enabled the use of temporary files to ensure
> atomicity when replacing an existing target. **Temporary files are no
> longer optional.**

`install` writes to `INS@XXXXXX` in the target directory and
`rename(2)`s it into place. The rename creates a **new inode**.
Processes already executing the old image keep their existing vnode
alive and run to completion against unchanged pages; new processes pick
up the new file. Nothing gets killed.

`make install` already does this correctly (`install -m 755 ...`). The
hazard was only ever in the stale-PATH warning it prints, which used to
suggest `cp`.

## The rule

```bash
# Safe
install -m 755 ~/.claude/bin/claude-guard ~/go/bin/claude-guard
mv new-binary ~/go/bin/claude-guard          # also a rename

# Deadlocks the session
cp ~/.claude/bin/claude-guard ~/go/bin/claude-guard
```

Deleting first (`rm` then copy) also avoids the SIGKILL, since the
unlink detaches the running vnode. But it leaves a window where the
hook binary does not exist, and a hook that fails to execute is its own
problem. Prefer `install`.

## Recovering a wedged session

The killed hooks leave no lock to clear — there is nothing to clean up
in `~/.cache/claude-guard/`. Interrupt the hanging tool call, confirm
no `claude-guard` processes are stuck:

```bash
ps -eo pid,ppid,etime,stat,command | grep claude-guard | grep -v grep
ps -eo pid,ppid,stat,command | awk '$3 ~ /Z/'
```

Then verify the guard answers again, which also confirms both copies
are on the same build:

```bash
command -v claude-guard && claude-guard version
~/.claude/bin/claude-guard version
~/.claude/bin/claude-guard doctor
```
