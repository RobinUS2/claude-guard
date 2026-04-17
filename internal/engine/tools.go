// Package engine — per-tool evaluators for non-Bash tools.
//
// Each evaluator follows the same tier pattern as Bash:
//   tier-1 deny → tier-2 allow → cache → LLM → default
// but with tool-specific matchers instead of shell AST analysis.
package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/RobinUS2/claude-guard/internal/cache"
	"github.com/RobinUS2/claude-guard/internal/redact"
	"github.com/RobinUS2/claude-guard/internal/rules"
)

// --- WebFetch evaluator ---

// ssrfDenyCIDRs are private/loopback/link-local ranges that should
// never be fetched from a development tool.
var ssrfDenyCIDRs = func() []*net.IPNet {
	cidrs := []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // link-local (includes AWS/GCP metadata)
		"0.0.0.0/8",      // "this" network
		"::1/128",        // IPv6 loopback
		"fc00::/7",       // IPv6 unique local
		"fe80::/10",      // IPv6 link-local
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, _ := net.ParseCIDR(c)
		if n != nil {
			out = append(out, n)
		}
	}
	return out
}()

var ssrfDenyHosts = map[string]struct{}{
	"localhost":                  {},
	"metadata.google.internal":  {},
	"metadata.internal":         {},
}

var ssrfDenySchemes = map[string]struct{}{
	"file":   {},
	"ftp":    {},
	"gopher": {},
}

var ssrfDenyPaths = []string{
	"/.env", "/.git/config", "/.git/HEAD",
	"/.aws/credentials", "/.aws/config",
	"/etc/passwd", "/etc/shadow",
}

func (e *Engine) decideWebFetch(in Input, start time.Time) Output {
	out := Output{Verdict: Continue, Tier: "default"}

	if in.URL != "" {
		if verdict, rule, reason := checkURLDeny(in.URL); verdict {
			if !e.cfg.ShadowMode {
				out.Verdict = Deny
				out.Tier = "instant_block"
				out.Rule = rule
				out.Reason = reason
				out.Latency = time.Since(start)
				e.record(in, out)
				return out
			}
			out.Shadow.Tier1Rule = rule
			out.Shadow.Tier1Reason = reason
		}
	}

	// Fall through to LLM (tier 4) via shared infrastructure.
	out = e.decideLLMFallback(in, start, out)
	return out
}

// checkURLDeny normalizes a URL and checks it against SSRF deny
// rules. Returns (true, ruleName, reason) on match.
func checkURLDeny(rawURL string) (deny bool, rule, reason string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false, "", ""
	}

	// Scheme check.
	scheme := strings.ToLower(u.Scheme)
	if _, bad := ssrfDenySchemes[scheme]; bad {
		return true, "webfetch-ssrf-scheme", fmt.Sprintf("%s:// scheme blocked", scheme)
	}

	host := strings.ToLower(u.Hostname())

	// Known-dangerous hostnames (exact match, not substring).
	if _, bad := ssrfDenyHosts[host]; bad {
		return true, "webfetch-ssrf-host", fmt.Sprintf("host %q is blocked (SSRF)", host)
	}

	// IP-based checks: resolve host to net.IP — catches decimal,
	// hex, octal, IPv6 variant encodings.
	if ip := net.ParseIP(host); ip != nil {
		for _, cidr := range ssrfDenyCIDRs {
			if cidr.Contains(ip) {
				return true, "webfetch-ssrf-cidr", fmt.Sprintf("IP %s in blocked range %s", ip, cidr)
			}
		}
	}

	// Path-based credential endpoint check.
	path := u.Path
	for _, dp := range ssrfDenyPaths {
		if path == dp || strings.HasSuffix(path, dp) {
			return true, "webfetch-credential-path", fmt.Sprintf("URL path %q matches blocked credential endpoint", dp)
		}
	}

	return false, "", ""
}

// --- WebSearch evaluator ---

func (e *Engine) decideWebSearch(in Input, start time.Time) Output {
	// No tier-1 rules for search queries — they're read-only.
	// Fall through to LLM directly.
	return e.decideLLMFallback(in, time.Now(), Output{Verdict: Continue, Tier: "default"})
}

// --- Read evaluator ---

func (e *Engine) decideRead(in Input, start time.Time) Output {
	out := Output{Verdict: Continue, Tier: "default"}

	// Tier-1: PathAccess deny (reuse existing path rules).
	if in.FilePath != "" {
		for _, r := range e.cfg.InstantBlock {
			pa, ok := r.(*rules.PathAccess)
			if !ok {
				continue
			}
			// Skip WriteOnly rules for Read — reading ~/.bashrc is fine.
			if pa.WriteOnly {
				continue
			}
			if rules.PathMatchesAny(in.FilePath, pa.Paths) {
				if !e.cfg.ShadowMode {
					out.Verdict = Deny
					out.Tier = "instant_block"
					out.Rule = pa.Name()
					out.Reason = pa.Reason
					out.Latency = time.Since(start)
					e.record(in, out)
					return out
				}
				out.Shadow.Tier1Rule = pa.Name()
				out.Shadow.Tier1Reason = pa.Reason
				break
			}
		}
	}

	// Tier-2: CWD fast-path — files within the project directory are
	// inherently safe to read. Avoids an LLM call per file when Claude
	// explores a codebase (30-50 Reads in seconds).
	if isWithinCWD(in.FilePath, in.CWD) && out.Shadow.Tier1Rule == "" {
		if !e.cfg.ShadowMode {
			out.Verdict = Allow
			out.Tier = "instant_allow"
			out.Rule = "read-cwd-scope"
			out.Reason = "file within project CWD"
			out.Latency = time.Since(start)
			e.record(in, out)
			return out
		}
		out.Shadow.Tier2Rule = "read-cwd-scope"
	}

	// Tier 3-4: cache + LLM.
	return e.decideLLMFallback(in, start, out)
}

// --- Write / Edit evaluator ---

func (e *Engine) decideWrite(in Input, start time.Time) Output {
	out := Output{Verdict: Continue, Tier: "default"}

	// Tier-1: PathAccess deny — ALL rules (both general and WriteOnly).
	if in.FilePath != "" {
		for _, r := range e.cfg.InstantBlock {
			pa, ok := r.(*rules.PathAccess)
			if !ok {
				continue
			}
			if rules.PathMatchesAny(in.FilePath, pa.Paths) {
				if !e.cfg.ShadowMode {
					out.Verdict = Deny
					out.Tier = "instant_block"
					out.Rule = pa.Name()
					out.Reason = pa.Reason
					out.Latency = time.Since(start)
					e.record(in, out)
					return out
				}
				out.Shadow.Tier1Rule = pa.Name()
				out.Shadow.Tier1Reason = pa.Reason
				break
			}
		}
	}

	// Content secret scan (Write only, 8KB cap).
	if in.IsWrite && in.Content != "" && e.redactor != nil {
		scanLen := len(in.Content)
		if scanLen > 8192 {
			scanLen = 8192
		}
		res := e.redactor.Scan(in.Content[:scanLen])
		if res.Decision == redact.Skip {
			if !e.cfg.ShadowMode {
				out.Verdict = Deny
				out.Tier = "instant_block"
				out.Rule = "write-contains-secret"
				out.Reason = "content contains secret: " + res.SkipReason
				out.Latency = time.Since(start)
				e.record(in, out)
				return out
			}
			out.Shadow.Tier1Rule = "write-contains-secret"
		}
	}

	// Tier-2: CWD fast-path.
	if isWithinCWD(in.FilePath, in.CWD) && out.Shadow.Tier1Rule == "" {
		if !e.cfg.ShadowMode {
			out.Verdict = Allow
			out.Tier = "instant_allow"
			out.Rule = "write-cwd-scope"
			out.Reason = "file within project CWD"
			out.Latency = time.Since(start)
			e.record(in, out)
			return out
		}
		out.Shadow.Tier2Rule = "write-cwd-scope"
	}

	return e.decideLLMFallback(in, start, out)
}

// --- Generic (MCP) evaluator ---

// mcpReadVerbs are action-verb prefixes that indicate a structurally
// read-only MCP tool call. Auto-allowed at tier 2 without LLM.
var mcpReadVerbs = []string{
	"list", "get", "read", "search", "show", "describe",
	"view", "fetch", "query", "check", "status", "info",
}

func (e *Engine) decideGeneric(in Input, start time.Time) Output {
	out := Output{Verdict: Continue, Tier: "default"}

	// Tier-2: MCP read-verb heuristic.
	action := extractMCPAction(in.ToolName)
	if action != "" {
		for _, rv := range mcpReadVerbs {
			if strings.HasPrefix(strings.ToLower(action), rv) {
				if !e.cfg.ShadowMode {
					out.Verdict = Allow
					out.Tier = "instant_allow"
					out.Rule = "mcp-read-verb"
					out.Reason = "MCP tool with read-verb action: " + action
					out.Latency = time.Since(start)
					e.record(in, out)
					return out
				}
				out.Shadow.Tier2Rule = "mcp-read-verb"
				break
			}
		}
	}

	return e.decideLLMFallback(in, start, out)
}

// extractMCPAction extracts the action part from an MCP tool name.
// `mcp__gdrive__gdrive_read_file` → `read_file`
// `mcp__google-calendar__list-events` → `list-events`
// Non-MCP tools → returns the full name.
func extractMCPAction(toolName string) string {
	// MCP tools use `mcp__<provider>__<action>` convention.
	if i := strings.LastIndex(toolName, "__"); i >= 0 && i+2 < len(toolName) {
		action := toolName[i+2:]
		// Strip provider prefix from action if repeated:
		// `gdrive_read_file` → strip `gdrive_` → `read_file`
		if j := strings.Index(action, "_"); j >= 0 && j+1 < len(action) {
			rest := action[j+1:]
			// Only strip if the prefix is a plausible provider name
			// (no spaces, not too long).
			if len(action[:j]) <= 20 {
				return rest
			}
		}
		return action
	}
	return toolName
}

// --- Shared helpers ---

// isWithinCWD reports whether path is inside the project CWD tree.
// Used by Read/Write evaluators as a tier-2 fast-path — files within
// the project are inherently safe to read/write.
func isWithinCWD(path, cwd string) bool {
	if cwd == "" || path == "" {
		return false
	}
	cleanPath := filepath.Clean(path)
	cleanCWD := filepath.Clean(cwd)
	return strings.HasPrefix(cleanPath, cleanCWD+"/") || cleanPath == cleanCWD
}

// decideLLMFallback runs the shared tier-3 (cache) + tier-4 (LLM)
// pipeline for a non-Bash tool. Reuses the existing cache + LLM
// infrastructure from the Bash flow but skips tiers 1/2 (those are
// tool-specific and already evaluated by the caller) and tier 5
// (legacy, Bash-only).
//
// The shadow trace from the caller's tier-1/2 evaluation is passed
// through via `out.Shadow` and preserved.
func (e *Engine) decideLLMFallback(in Input, start time.Time, out Output) Output {
	// Redaction: check command text (which contains the tool-specific
	// summary like "WebFetch URL: …" or "Read: <path>") for secrets.
	if e.redactor != nil {
		res := e.redactor.Scan(in.Command)
		if res.Decision == redact.Skip {
			out.Latency = time.Since(start)
			e.record(in, out)
			return out
		}
	}

	// Cache lookup.
	projRules, projHash := e.loadProjectConfig(in.CWD)
	_ = projRules // not used for non-Bash tools
	keyInputs := e.buildKeyInputs(in, projHash)
	globalKey := ""
	projectKey := ""
	if e.cache != nil && e.llm != nil {
		globalKey = cache.GlobalKey(keyInputs)
		projectKey = cache.Key(keyInputs)
		for _, attempt := range []struct {
			key   string
			scope string
		}{
			{globalKey, "global"},
			{projectKey, "project"},
		} {
			entry, hit := e.cache.Get(attempt.key)
			if !hit {
				continue
			}
			eff := entry.EffectiveVerdict()
			if !e.cfg.ShadowMode && eff == cache.VerdictAllow {
				out.Verdict = Allow
				out.Tier = "cache"
				out.Rule = entry.Tier + "/" + entry.Provider
				out.Reason = entry.Reason
				out.Latency = time.Since(start)
				e.record(in, out)
				return out
			}
		}
	}

	// LLM classifier.
	if e.llm != nil {
		llmVerdict := e.runLLMTier(in, keyInputs, globalKey, projectKey)
		out.Shadow.Tier4LLM = llmVerdict.shadow
		if e.cache != nil && llmVerdict.allow {
			e.persistLLMAllow(in, llmVerdict, keyInputs, globalKey, projectKey)
		}
		if llmVerdict.shadow != "timeout-async-pending" {
			if llmVerdict.reason != "" {
				out.Reason = llmVerdict.reason
			}
			if e.llm != nil {
				out.Rule = e.llm.Provider() + "/" + e.llm.Model()
			}
		}
		if !e.cfg.ShadowMode && llmVerdict.allow {
			out.Verdict = Allow
			out.Tier = "llm"
			out.Latency = time.Since(start)
			e.record(in, out)
			return out
		}
	}

	// No legacy tier for non-Bash tools.
	out.Latency = time.Since(start)
	e.record(in, out)
	return out
}

// buildKeyInputs constructs cache.KeyInputs for the current command.
func (e *Engine) buildKeyInputs(in Input, projHash string) cache.KeyInputs {
	return cache.KeyInputs{
		Tool:              in.ToolName,
		Command:           in.Command,
		CWD:               in.CWD,
		GitBranch:         gitBranchOf(in.CWD),
		PromptVersion:     e.promptVersion,
		RulesHash:         e.rulesHash,
		ProjectConfigHash: projHash,
	}
}

// mcpInputHash returns a short hash of the full MCP input JSON.
func mcpInputHash(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])[:16]
}
