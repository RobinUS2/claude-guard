package stop

import (
	"context"
	"os/exec"
	"sync"
	"time"
)

// ShellContext runs shell commands with a per-invocation timeout.
// Results are cached within a single Stop evaluation (same cmd → same output).
type ShellContext interface {
	Run(cmd string) (stdout string, err error)
}

type shellContext struct {
	timeout time.Duration
	mu      sync.Mutex
	cache   map[string]shellResult
}

type shellResult struct {
	out string
	err error
}

func newShellContext(timeout time.Duration) *shellContext {
	return &shellContext{
		timeout: timeout,
		cache:   map[string]shellResult{},
	}
}

func (s *shellContext) Run(cmd string) (string, error) {
	s.mu.Lock()
	if r, ok := s.cache[cmd]; ok {
		s.mu.Unlock()
		return r.out, r.err
	}
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	raw, err := exec.CommandContext(ctx, "sh", "-c", cmd).Output()
	r := shellResult{out: string(raw), err: err}

	s.mu.Lock()
	s.cache[cmd] = r
	s.mu.Unlock()
	return r.out, r.err
}
