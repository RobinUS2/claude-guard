// Package lock hints claude-guard about the release-lock (see
// cto-as-a-service/scripts/release-lock.sh): a GitHub Issue based signal
// that someone is currently releasing prod/staging for a project. Unlike
// the freeze package (internal/freeze, an operator-armed "no deploys until
// X" window), the lock check is always active — it never needs to be
// manually turned on — and never hard-blocks. It only surfaces the normal
// permission dialog (Ask) with the holder's info when a deploy-shaped
// command is about to run and someone else appears to be mid-release.
//
// Fails open by design: any lookup error, missing repo, or same-actor lock
// results in Pass. A broken network check must never become a new way for
// every deploy-shaped command in every repo to get blocked.
package lock

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Info is the parsed metadata of a held release-lock issue. Field names and
// the underlying "key: value" body format match what
// cto-as-a-service/scripts/release-lock.sh writes on acquire.
type Info struct {
	IssueNumber int
	Who         string
	Host        string
	Agent       string
	Task        string
	Reason      string
	CreatedAt   time.Time
}

// Checker looks up whether env is currently locked for repo ("owner/repo").
// Returns (nil, nil) when clear. Returns (nil, err) on a lookup failure —
// callers must treat that the same as "unknown" and fail open.
type Checker interface {
	Status(ctx context.Context, repo, env string) (*Info, error)
}

// GHChecker shells out to `gh issue list`, querying the exact same
// label/state filter release-lock.sh itself uses, so the two stay
// consistent by construction.
type GHChecker struct {
	// Timeout bounds the gh subprocess. Defaults to 2s — this runs inline
	// in the PreToolUse hook path, so it must stay well under the hook's
	// overall budget even on a slow network.
	Timeout time.Duration
}

func (c GHChecker) Status(ctx context.Context, repo, env string) (*Info, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "gh", "issue", "list",
		"--repo", repo,
		"--label", "release-lock,env:"+env,
		"--state", "open",
		"--json", "number,body,createdAt",
	)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var raw []struct {
		Number    int    `json:"number"`
		Body      string `json:"body"`
		CreatedAt string `json:"createdAt"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, nil
	}

	first := raw[0]
	info := parseBody(first.Body)
	info.IssueNumber = first.Number
	info.CreatedAt, _ = time.Parse(time.RFC3339, first.CreatedAt)
	return info, nil
}

// parseBody reads the "key: value" lines release-lock.sh writes as the
// issue body (who/host/agent/task/reason). Unknown keys are ignored so the
// format can grow without breaking this parser.
func parseBody(body string) *Info {
	info := &Info{}
	for _, line := range strings.Split(body, "\n") {
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch strings.TrimSpace(key) {
		case "who":
			info.Who = val
		case "host":
			info.Host = val
		case "agent":
			info.Agent = val
		case "task":
			info.Task = val
		case "reason":
			info.Reason = val
		}
	}
	return info
}

// CurrentWhoHost returns this machine/user's identity in the same shape
// release-lock.sh's `who`/`host` fields use, so a held lock created by the
// *same* actor doesn't trigger a self-nag. Best-effort: git errors leave
// who empty, which simply means it'll never match a real lock's who — safe,
// just less precise.
func CurrentWhoHost(cwd string) (who, host string) {
	host, _ = os.Hostname()
	name := runGitConfig(cwd, "user.name")
	email := runGitConfig(cwd, "user.email")
	if name != "" || email != "" {
		who = name + " <" + email + ">"
	}
	return who, host
}

func runGitConfig(cwd, key string) string {
	if cwd == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "config", key)
	cmd.Dir = cwd
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// CachingChecker wraps a Checker with a short TTL cache so a burst of
// deploy-shaped commands doesn't hit the GitHub API once per command. Safe
// for concurrent use.
type CachingChecker struct {
	Inner Checker
	// TTL defaults to 30s if zero — comfortably shorter than a real release
	// (minutes), long enough to absorb a burst of matching commands.
	TTL time.Duration

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	info      *Info
	err       error
	expiresAt time.Time
}

func (c *CachingChecker) Status(ctx context.Context, repo, env string) (*Info, error) {
	ttl := c.TTL
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	key := repo + ":" + env
	now := time.Now()

	c.mu.Lock()
	if e, ok := c.cache[key]; ok && now.Before(e.expiresAt) {
		c.mu.Unlock()
		return e.info, e.err
	}
	c.mu.Unlock()

	info, err := c.Inner.Status(ctx, repo, env)

	c.mu.Lock()
	if c.cache == nil {
		c.cache = make(map[string]cacheEntry)
	}
	c.cache[key] = cacheEntry{info: info, err: err, expiresAt: now.Add(ttl)}
	c.mu.Unlock()

	return info, err
}
