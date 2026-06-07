package engine

// gitPushScore computes a 0–10 risk score for git push commands.
// It combines registry-based repo classification with heuristics
// (branch name, CI/CD presence, diff size) to decide:
//   - Score 0–3: auto-allow (Tier 2.7)
//   - Score 4–6: send to LLM with push context injected into prompt
//   - Score 7+:  LLM + flag as require-user (LLM result still cached for future)
//
// All shell checks are best-effort — failures are treated as neutral (+0 score).
// Results are cached by (cwd, gitHead) for the process lifetime.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/RobinUS2/claude-guard/internal/reporisk"
)

const (
	// PushScoreAutoAllow: score <= this → instant allow (Tier 2.7).
	PushScoreAutoAllow = 3
	// PushScoreRequireUser: score >= this → LLM + always prompt user.
	PushScoreRequireUser = 7
)

// gitPushCache caches (remoteURL, cicdPresent, diffStat) by (cwd+head)
// so repeated evaluate calls within one hook invocation don't re-shell.
var (
	gitPushMu    sync.Mutex
	gitPushCache = map[string]gitPushContext{}
)

type gitPushContext struct {
	remoteURL   string
	branch      string
	cicdPresent bool
	diffFiles   int
}

// evaluateGitPush scores a git push command and returns (score, explanation, pushContext).
// explanation is a short string describing the scoring for LLM prompt injection.
func (e *Engine) evaluateGitPush(in Input) (score int, explanation string, ctx gitPushContext) {
	cmd := strings.TrimSpace(in.Command)
	if !isGitPush(cmd) {
		return 0, "", gitPushContext{}
	}

	ctx = e.getGitPushContext(in.CWD)
	branchFromCmd := extractBranchFromCommand(cmd)
	if branchFromCmd != "" {
		ctx.branch = branchFromCmd
	}

	regLevel := reporisk.LevelMedium
	if e.repoRisk != nil {
		regLevel = e.repoRisk.Score(ctx.remoteURL)
	}

	var reasons []string

	// Registry-based scoring.
	switch regLevel {
	case reporisk.LevelHigh:
		score += 5
		reasons = append(reasons, "repo=high-risk (registry)")
	case reporisk.LevelLow:
		score -= 4
		reasons = append(reasons, "repo=low-risk (registry)")
	}

	// Branch scoring.
	branch := strings.ToLower(ctx.branch)
	if isProtectedBranch(branch) {
		score += 2
		reasons = append(reasons, "branch="+ctx.branch+" (protected)")
	} else if isFeatureBranch(branch) {
		score -= 1
		reasons = append(reasons, "branch="+ctx.branch+" (feature)")
	}

	// CI/CD detection.
	if ctx.cicdPresent {
		score += 2
		reasons = append(reasons, "ci/cd=yes")
	}

	// Diff size scoring.
	switch {
	case ctx.diffFiles > 100:
		score += 3
		reasons = append(reasons, "diff=large (>100 files)")
	case ctx.diffFiles > 20:
		score += 2
		reasons = append(reasons, "diff=medium (>20 files)")
	case ctx.diffFiles > 0:
		reasons = append(reasons, "diff=small")
	}

	// Clamp to [0, 10].
	if score < 0 {
		score = 0
	}
	if score > 10 {
		score = 10
	}

	explanation = buildPushExplanation(ctx, regLevel, score, reasons)
	return score, explanation, ctx
}

func (e *Engine) getGitPushContext(cwd string) gitPushContext {
	// Cache key: cwd + git HEAD sha (invalidates when commits change).
	head := gitHead(cwd)
	key := cwd + "\x00" + head

	gitPushMu.Lock()
	if cached, ok := gitPushCache[key]; ok {
		gitPushMu.Unlock()
		return cached
	}
	gitPushMu.Unlock()

	ctx := gitPushContext{
		remoteURL:   runGit(cwd, "remote", "get-url", "origin"),
		branch:      runGit(cwd, "rev-parse", "--abbrev-ref", "HEAD"),
		cicdPresent: detectCICD(cwd),
		diffFiles:   countDiffFiles(cwd),
	}

	gitPushMu.Lock()
	gitPushCache[key] = ctx
	gitPushMu.Unlock()

	return ctx
}

// gitHead reads .git/HEAD to get a short identifier for cache invalidation.
// Not exec-based — reads directly from disk for speed.
func gitHead(cwd string) string {
	if cwd == "" {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(cwd, ".git", "HEAD"))
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(data))
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// runGit executes a git command in cwd and returns trimmed stdout.
// Returns "" on error or timeout.
func runGit(cwd string, args ...string) string {
	if cwd == "" {
		return ""
	}
	ctx, cancel := gitPushTimeout(300 * time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = cwd
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// detectCICD checks whether the repo has a CI/CD configuration file.
func detectCICD(cwd string) bool {
	if cwd == "" {
		return false
	}
	indicators := []string{
		".github/workflows",
		"cloudbuild.yaml",
		"cloudbuild.yml",
		".circleci/config.yml",
		".travis.yml",
		"Jenkinsfile",
		".gitlab-ci.yml",
	}
	for _, ind := range indicators {
		path := filepath.Join(cwd, ind)
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

// countDiffFiles runs `git diff --stat origin/<branch>` and counts changed files.
// Returns 0 on error (treated as neutral).
func countDiffFiles(cwd string) int {
	if cwd == "" {
		return 0
	}
	// Get current branch first.
	branch := runGit(cwd, "rev-parse", "--abbrev-ref", "HEAD")
	if branch == "" || branch == "HEAD" {
		return 0
	}
	ctx, cancel := gitPushTimeout(500 * time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "diff", "--stat", "origin/"+branch)
	cmd.Dir = cwd
	out, err := cmd.Output()
	if err != nil {
		return 0
	}
	// Count lines that look like "file | N ..." — each is one changed file.
	lines := strings.Split(string(out), "\n")
	count := 0
	for _, line := range lines {
		if strings.Contains(line, "|") {
			count++
		}
	}
	return count
}

// isGitPush returns true when the command is a bare git push (first token: git,
// subcommand: push). Does not fire for other git commands.
func isGitPush(cmd string) bool {
	parts := strings.Fields(cmd)
	if len(parts) < 2 {
		return false
	}
	return (parts[0] == "git" || strings.HasSuffix(parts[0], "/git")) &&
		parts[1] == "push"
}

// extractBranchFromCommand tries to parse the branch name from the push command.
// Handles: `git push`, `git push origin`, `git push origin branch`, `git push origin HEAD:branch`.
func extractBranchFromCommand(cmd string) string {
	parts := strings.Fields(cmd)
	// git push [remote] [branch]
	// Find the branch: it's everything after "push [remote]" that doesn't start with "-".
	start := 2 // after "git push"
	for i := start; i < len(parts); i++ {
		if strings.HasPrefix(parts[i], "-") {
			continue // flag
		}
		if i == start {
			// First non-flag after "push" is usually the remote (e.g. "origin").
			continue
		}
		// Second non-flag token is the branch (or refspec like HEAD:main).
		branch := parts[i]
		if idx := strings.LastIndex(branch, ":"); idx >= 0 {
			branch = branch[idx+1:]
		}
		return branch
	}
	return ""
}

func isProtectedBranch(branch string) bool {
	protected := []string{"main", "master", "production", "prod", "release"}
	for _, p := range protected {
		if branch == p || strings.HasPrefix(branch, "release/") {
			return true
		}
	}
	return false
}

func isFeatureBranch(branch string) bool {
	for _, prefix := range []string{"feature/", "fix/", "bugfix/", "hotfix/", "feat/", "chore/"} {
		if strings.HasPrefix(branch, prefix) {
			return true
		}
	}
	return false
}

func buildPushExplanation(ctx gitPushContext, regLevel reporisk.Level, score int, reasons []string) string {
	var b strings.Builder
	b.WriteString("GIT PUSH RISK CONTEXT:\n")
	if ctx.remoteURL != "" {
		b.WriteString("  remote: " + ctx.remoteURL + "\n")
	}
	if ctx.branch != "" {
		b.WriteString("  branch: " + ctx.branch + "\n")
	}
	b.WriteString("  risk-registry: " + string(regLevel) + "\n")
	if ctx.cicdPresent {
		b.WriteString("  ci/cd: yes (pipeline will trigger)\n")
	}
	if ctx.diffFiles > 0 {
		b.WriteString("  files-changed: ~" + itoa(ctx.diffFiles) + "\n")
	}
	b.WriteString("  risk-score: " + itoa(score) + "/10 (" + strings.Join(reasons, ", ") + ")\n")
	if score >= PushScoreRequireUser {
		b.WriteString("This is a HIGH-RISK push. Be conservative: approve only if changes\n")
		b.WriteString("are routine and the user clearly intends to ship to production now.\n")
	} else {
		b.WriteString("Use this context to decide whether to approve the push.\n")
	}
	return b.String()
}

// gitPushTimeout creates a context with the given deadline for shell ops.
func gitPushTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
