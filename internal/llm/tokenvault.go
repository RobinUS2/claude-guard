package llm

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// TokenVaultAnthropicCandidates is the ordered list of (vault, secret)
// pairs claude-guard will try if no Anthropic env var is set. The
// first one that returns a non-empty value wins. All queries are
// bounded by a short timeout so a slow token-vault subprocess cannot
// stall the hook.
//
// To teach claude-guard about a new vault/secret, append to this
// slice. The defaults match Robin's personal vault naming convention
// (robin_verlangen / taufinity). Users with other vault layouts should
// export ANTHROPIC_API_KEY (or an alias) directly.
var TokenVaultAnthropicCandidates = []struct {
	Vault  string
	Secret string
}{
	{"robin_verlangen", "anthropic_api_key"},
	{"robin_verlangen", "anthropic"},
	{"taufinity", "anthropic_api_key"},
	{"taufinity", "anthropic"},
}

// tokenVaultTimeout caps the time we'll wait on any single subprocess
// spawn. The vault might be locked (requires passphrase), in which
// case the CLI exits quickly with an error — but we don't want a hung
// process to block the hook.
const tokenVaultTimeout = 300 * time.Millisecond

// tokenVaultBinary is the path we invoke. Set as a package-level var
// for testability (tests stub it with a mock script). Default is to
// rely on PATH lookup.
var tokenVaultBinary = "token-vault"

// tokenVaultNegativeCacheTTL is how long we remember "no vault candidate
// returned a secret" before trying again. The full candidate sweep takes
// up to tokenVaultTimeout * len(candidates) which is ~1.2s worst case.
// Paying that on every hook invocation when the user has no vault is
// unacceptable; 5 minutes of cached miss keeps the hook fast while
// still picking up "I just unlocked the vault" within a reasonable
// window.
const tokenVaultNegativeCacheTTL = 5 * time.Minute

// tokenVaultNegativeCachePath is a tiny file we touch when every
// candidate misses. If the file's mtime is within TTL, we short-circuit.
func tokenVaultNegativeCachePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	base := filepath.Join(home, ".cache", "claude-guard")
	if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
		base = filepath.Join(xdg, "claude-guard")
	}
	return filepath.Join(base, "token-vault-miss.marker")
}

// inProcessCache holds a resolved secret for the lifetime of a single
// claude-guard process invocation. We also check this inside the hook
// path (AutoSelect is called once per tier 4 attempt, verifier +
// classifier).
var inProcessCache struct {
	sync.Mutex
	value   string
	checked bool
}

// lookupTokenVaultAnthropic tries each candidate in order and returns
// the first non-empty secret. Uses a negative-result file cache to
// avoid paying the full 1.2s candidate sweep on every hook invocation
// when no vault is configured.
//
// This is a best-effort fallback. Silent failure is the correct
// behavior — the hook should not log a warning every invocation just
// because the user hasn't set up an Anthropic key. doctor handles the
// user-facing "hey, no LLM configured" message.
func lookupTokenVaultAnthropic() string {
	inProcessCache.Lock()
	defer inProcessCache.Unlock()
	if inProcessCache.checked {
		return inProcessCache.value
	}
	defer func() { inProcessCache.checked = true }()

	// Bail out cheaply if token-vault isn't installed.
	if _, err := exec.LookPath(tokenVaultBinary); err != nil {
		return ""
	}

	// Check the on-disk negative cache: if we recently swept every
	// candidate and found nothing, don't re-sweep.
	if path := tokenVaultNegativeCachePath(); path != "" {
		if info, err := os.Stat(path); err == nil {
			if time.Since(info.ModTime()) < tokenVaultNegativeCacheTTL {
				return ""
			}
		}
	}

	for _, c := range TokenVaultAnthropicCandidates {
		if v := lookupOne(c.Vault, c.Secret); v != "" {
			inProcessCache.value = v
			return v
		}
	}

	// All candidates missed — record a negative marker so the next
	// invocation doesn't re-sweep.
	if path := tokenVaultNegativeCachePath(); path != "" {
		_ = os.MkdirAll(filepath.Dir(path), 0o755)
		_ = os.WriteFile(path, []byte(""), 0o640)
	}
	return ""
}

func lookupOne(vault, secret string) string {
	ctx, cancel := context.WithTimeout(context.Background(), tokenVaultTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, tokenVaultBinary, "get", vault, secret)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
