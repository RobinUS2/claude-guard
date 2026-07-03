// Package engine — per-tool evaluators for non-Bash tools.
//
// Each evaluator follows the same tier pattern as Bash:
//
//	tier-1 deny → tier-2 allow → cache → LLM → default
//
// but with tool-specific matchers instead of shell AST analysis.
package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
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
	"localhost":                {},
	"metadata.google.internal": {},
	"metadata.internal":        {},
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

	// Safe Browsing API check for new domains (between tier-1 SSRF
	// and LLM). Only fires when API key is configured and the domain
	// hasn't been seen before (file-cached). Fail-open on errors.
	if in.URL != "" && out.Shadow.Tier1Rule == "" {
		if threat := e.checkSafeBrowsing(in.URL, in.ToolUseID); threat != "" {
			if !e.cfg.ShadowMode {
				out.Verdict = Deny
				out.Tier = "instant_block"
				out.Rule = "webfetch-safe-browsing"
				out.Reason = "Google Safe Browsing: " + threat
				out.Latency = time.Since(start)
				e.record(in, out)
				return out
			}
			out.Shadow.Tier1Rule = "webfetch-safe-browsing"
			out.Shadow.Tier1Reason = threat
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

// safeBuiltinTools are first-party Claude Code tools that have no
// shell / file / network side effects. Agent spawns subagents that
// re-enter the hook for every inner tool call (verified via decision
// log: subagents' inner tool calls do trigger PreToolUse, so auto-
// allowing the outer Agent call is NOT a bypass — the inner work
// still gets evaluated). ToolSearch loads tool schemas; TodoWrite
// is local conversation state. Monitor streams stdout from a
// background process already started via Bash (which went through
// the hook itself) — reading its output is harmless.
// None reach outside the harness.
var safeBuiltinTools = map[string]bool{
	"Agent":      true,
	"ToolSearch": true,
	"TodoWrite":  true,
	"Monitor":    true,
}

// safeMCPServerPrefixes match MCP servers whose entire surface is
// harness-internal (UI markers, session state, tool discovery). All
// tools under these servers are auto-allowed at tier 2.
//
// DO NOT add servers that touch external systems (gdrive,
// google-calendar, atlassian, etc.) — those can have write shapes
// and need LLM review.
//
// Deliberately omitted: `mcp__scheduled-tasks__` — create_scheduled_task
// persists intent across sessions, which is a real side effect. Falls
// through to LLM tier.
var safeMCPServerPrefixes = []string{
	"mcp__ccd_session__",  // mark_chapter, spawn_task (spawn creates a new session whose actions re-enter PreToolUse)
	"mcp__mcp-registry__", // search_mcp_registry (read-only discovery)
}

// isStructurallySafeTool reports whether a tool name is known safe
// without further analysis. Returns (true, rule) on match.
func isStructurallySafeTool(toolName string) (bool, string) {
	if safeBuiltinTools[toolName] {
		return true, "safe-builtin-tool"
	}
	for _, p := range safeMCPServerPrefixes {
		if strings.HasPrefix(toolName, p) {
			return true, "safe-mcp-server"
		}
	}
	return false, ""
}

func (e *Engine) decideGeneric(in Input, start time.Time) Output {
	out := Output{Verdict: Continue, Tier: "default"}

	// Tier-2: structural allowlist for harness-internal tools that
	// have no shell / file / network surface. Avoids the non-Bash
	// fallthrough where Agent / ToolSearch / session-markers would
	// hit the user prompt default when the LLM tier is unavailable.
	if safe, rule := isStructurallySafeTool(in.ToolName); safe {
		if !e.cfg.ShadowMode {
			out.Verdict = Allow
			out.Tier = "instant_allow"
			out.Rule = rule
			out.Reason = "structurally safe non-Bash tool: " + in.ToolName
			out.Latency = time.Since(start)
			e.record(in, out)
			return out
		}
		out.Shadow.Tier2Rule = rule
	}

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

// --- Google Safe Browsing ---

// checkSafeBrowsing queries Google Safe Browsing API v4 for the given
// URL's domain. Returns the threat type string on match ("MALWARE",
// "SOCIAL_ENGINEERING", etc.) or "" when safe / error / no API key.
//
// Results are file-cached under ~/.cache/claude-guard/safebrowsing/
// keyed by sha256(domain). Safe domains cache for 1h, unsafe for 24h.
// Only fires on cache miss (new domain). Fail-open on API errors.
func (e *Engine) checkSafeBrowsing(rawURL, toolUseID string) string {
	apiKey := os.Getenv("GOOGLE_SAFE_BROWSING_API_KEY")
	if apiKey == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	domain := strings.ToLower(u.Hostname())
	if domain == "" {
		return ""
	}

	// File cache check.
	cacheDir := filepath.Join(os.Getenv("HOME"), ".cache", "claude-guard", "safebrowsing")
	domHash := sha256.Sum256([]byte(domain))
	cachePath := filepath.Join(cacheDir, hex.EncodeToString(domHash[:])+".json")

	type sbCacheEntry struct {
		Domain  string    `json:"domain"`
		Safe    bool      `json:"safe"`
		Threat  string    `json:"threat,omitempty"`
		Expires time.Time `json:"expires"`
	}
	if data, err := os.ReadFile(cachePath); err == nil {
		var entry sbCacheEntry
		if json.Unmarshal(data, &entry) == nil && time.Now().Before(entry.Expires) {
			if !entry.Safe {
				return entry.Threat
			}
			return ""
		}
	}

	// Call Safe Browsing API.
	type sbReq struct {
		Client struct {
			ClientID      string `json:"clientId"`
			ClientVersion string `json:"clientVersion"`
		} `json:"client"`
		ThreatInfo struct {
			ThreatTypes      []string `json:"threatTypes"`
			PlatformTypes    []string `json:"platformTypes"`
			ThreatEntryTypes []string `json:"threatEntryTypes"`
			ThreatEntries    []struct {
				URL string `json:"url"`
			} `json:"threatEntries"`
		} `json:"threatInfo"`
	}
	var body sbReq
	body.Client.ClientID = "claude-guard"
	body.Client.ClientVersion = "1.0"
	body.ThreatInfo.ThreatTypes = []string{"MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"}
	body.ThreatInfo.PlatformTypes = []string{"ANY_PLATFORM"}
	body.ThreatInfo.ThreatEntryTypes = []string{"URL"}
	body.ThreatInfo.ThreatEntries = []struct {
		URL string `json:"url"`
	}{{URL: rawURL}}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Pass the API key as a header rather than a URL query parameter so it
	// does not appear in Cloud Logging request URLs or HTTP access logs.
	apiURL := "https://safebrowsing.googleapis.com/v4/threatMatches:find"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(jsonBody))
	if err != nil {
		return ""
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Goog-Api-Key", apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.appLog().Info("safe_browsing_error", "err", err.Error(), "domain", domain, "tool_use_id", toolUseID)
		return "" // fail-open
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		e.appLog().Info("safe_browsing_error", "status", resp.StatusCode, "domain", domain, "tool_use_id", toolUseID)
		return "" // fail-open
	}

	type sbResp struct {
		Matches []struct {
			ThreatType string `json:"threatType"`
		} `json:"matches,omitempty"`
	}
	var result sbResp
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return ""
	}

	// Build cache entry.
	entry := sbCacheEntry{Domain: domain, Safe: true, Expires: time.Now().Add(1 * time.Hour)}
	threat := ""
	if len(result.Matches) > 0 {
		threat = result.Matches[0].ThreatType
		entry.Safe = false
		entry.Threat = threat
		entry.Expires = time.Now().Add(24 * time.Hour)
		e.appLog().Warn("safe_browsing_threat",
			"domain", domain, "threat", threat, "url", rawURL, "tool_use_id", toolUseID)
	} else {
		e.appLog().Info("safe_browsing_ok", "domain", domain, "tool_use_id", toolUseID)
	}

	// Write cache (best-effort).
	_ = os.MkdirAll(cacheDir, 0o755)
	if cacheData, err := json.Marshal(entry); err == nil {
		_ = os.WriteFile(cachePath, cacheData, 0o640)
	}

	return threat
}
