// Package webinspect pre-fetches a URL using realistic Chrome headers and
// calls Anthropic Haiku to decide whether the content is safe to visit.
//
// It is used by the PermissionRequest hook for WebFetch calls that are not
// already pre-approved by the domain allow-list in settings.json.
//
// Design contract:
//   - Fail open on every error (network, API, parse). The inspector is a
//     convenience guard, not a hard security boundary. Claude's own judgment,
//     the domain allow-list, and transcript audit are the real defences.
//   - Flag UNSAFE only for active phishing, malware delivery, credential-
//     harvesting forms, or obvious data-exfiltration endpoints. All normal
//     dev content (docs, APIs, articles, GitHub, share links) is SAFE.
package webinspect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	// DefaultMaxBodyBytes is how much of the response body we read before
	// closing the connection. 8 KB is enough for page title + meta structure.
	DefaultMaxBodyBytes = 8192

	// DefaultFetchTimeout is the wall-clock budget for the pre-fetch.
	DefaultFetchTimeout = 8 * time.Second

	// DefaultInspectTimeout is the budget for the Anthropic API call.
	DefaultInspectTimeout = 15 * time.Second

	// DefaultModel is the cheapest Haiku that is fast enough for triage.
	DefaultModel = "claude-haiku-4-5-20251001"

	// DefaultMaxTokens caps the verdict to a single short line.
	DefaultMaxTokens = 60

	// DefaultAnthropicBase is the Anthropic Messages API base URL.
	DefaultAnthropicBase = "https://api.anthropic.com"

	// DefaultGeminiBase is the Gemini generateContent API base URL.
	DefaultGeminiBase = "https://generativelanguage.googleapis.com"

	// DefaultGeminiModel is the cheapest Gemini model for triage.
	DefaultGeminiModel = "gemini-2.5-flash-lite"
)

// errSSRF is returned by checkSSRF when a URL resolves to a private,
// loopback, link-local, or cloud-metadata IP. It is treated distinctly from
// ordinary fetch errors: Inspect returns Allow=false (user prompt) rather
// than failing open (auto-allow).
var errSSRF = errors.New("ssrf: private or internal IP")

// privateRanges holds the CIDR blocks that must never be pre-fetched.
// Compiled once at init to avoid per-call allocation.
var privateRanges []*net.IPNet

func init() {
	for _, cidr := range []string{
		"0.0.0.0/8",
		"10.0.0.0/8",
		"100.64.0.0/10",  // CGN
		"127.0.0.0/8",    // loopback
		"169.254.0.0/16", // link-local + AWS/GCP/Azure/DO metadata endpoints
		"172.16.0.0/12",  // private
		"192.168.0.0/16", // private
		"::1/128",        // IPv6 loopback
		"fc00::/7",       // IPv6 ULA
		"fe80::/10",      // IPv6 link-local
	} {
		_, block, _ := net.ParseCIDR(cidr)
		if block != nil {
			privateRanges = append(privateRanges, block)
		}
	}
}

func isPrivateIP(ip net.IP) bool {
	for _, block := range privateRanges {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// checkSSRF parses rawURL, resolves the hostname, and returns errSSRF if any
// resolved IP falls in a private/loopback/link-local/metadata range.
// DNS failures return nil so the inspector fails open; the fetch will fail
// anyway and Inspect will allow through to the user prompt.
func checkSSRF(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil // unparseable URL — the fetch will also fail
	}
	host := u.Hostname()
	if host == "" {
		return nil
	}

	// Fast path: host is already a numeric IP, no DNS needed.
	if ip := net.ParseIP(host); ip != nil {
		if isPrivateIP(ip) {
			return fmt.Errorf("%w: %s", errSSRF, ip)
		}
		return nil
	}

	// Resolve and check every returned address.
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil // DNS failure — treat as safe (fetch will fail)
	}
	for _, ip := range ips {
		if isPrivateIP(ip) {
			return fmt.Errorf("%w: %s resolves to %s", errSSRF, host, ip)
		}
	}
	return nil
}

// chromeHeaders are sent with every pre-fetch request to pass common
// bot-detection walls. Ordered to match a real Chrome 131 macOS request.
var chromeHeaders = [][2]string{
	{"User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"},
	{"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
	{"Accept-Language", "en-US,en;q=0.9,nl;q=0.8"},
	{"Accept-Encoding", "gzip, deflate, br"},
	{"Sec-Ch-Ua", `"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"`},
	{"Sec-Ch-Ua-Mobile", "?0"},
	{"Sec-Ch-Ua-Platform", `"macOS"`},
	{"Sec-Fetch-Dest", "document"},
	{"Sec-Fetch-Mode", "navigate"},
	{"Sec-Fetch-Site", "none"},
	{"Sec-Fetch-User", "?1"},
	{"Upgrade-Insecure-Requests", "1"},
	{"Cache-Control", "max-age=0"},
}

// Verdict is the outcome of an Inspect call.
type Verdict struct {
	Allow  bool
	Reason string
}

// Config controls inspector behaviour. Zero value uses all defaults.
type Config struct {
	APIKey           string        // Anthropic API key; falls back to ANTHROPIC_API_KEY env var
	GeminiKey        string        // Gemini API key; falls back to GEMINI_API_KEY / GOOGLE_API_KEY
	AnthropicURL     string        // override for testing; default: DefaultAnthropicBase
	GeminiURL        string        // override for testing; default: DefaultGeminiBase
	MaxBodyBytes     int64         // default: DefaultMaxBodyBytes
	FetchTimeout     time.Duration // default: DefaultFetchTimeout
	InspectModel     string        // default: DefaultModel
	HTTP             *http.Client  // shared client; a new one is created if nil
	DisableSSRFCheck bool          // test-only: bypass private-IP guard; never set in production
}

func (c *Config) apiKey() string {
	if c.APIKey != "" {
		return c.APIKey
	}
	return os.Getenv("ANTHROPIC_API_KEY")
}

// geminiKey returns the Gemini API key from config or env (GEMINI_API_KEY, then GOOGLE_API_KEY).
func (c *Config) geminiKey() string {
	if c.GeminiKey != "" {
		return c.GeminiKey
	}
	if k := os.Getenv("GEMINI_API_KEY"); k != "" {
		return k
	}
	return os.Getenv("GOOGLE_API_KEY")
}

// AnyAPIKey returns the first available API key (Anthropic, then Gemini) or "".
// Useful for callers that want to warn when no inspection can happen.
func (c *Config) AnyAPIKey() string {
	if k := c.apiKey(); k != "" {
		return k
	}
	return c.geminiKey()
}

func (c *Config) geminiURL() string {
	if c.GeminiURL != "" {
		return c.GeminiURL
	}
	return DefaultGeminiBase
}

func (c *Config) maxBodyBytes() int64 {
	if c.MaxBodyBytes > 0 {
		return c.MaxBodyBytes
	}
	return DefaultMaxBodyBytes
}

func (c *Config) fetchTimeout() time.Duration {
	if c.FetchTimeout > 0 {
		return c.FetchTimeout
	}
	return DefaultFetchTimeout
}

func (c *Config) model() string {
	if c.InspectModel != "" {
		return c.InspectModel
	}
	return DefaultModel
}

func (c *Config) anthropicURL() string {
	if c.AnthropicURL != "" {
		return c.AnthropicURL
	}
	return DefaultAnthropicBase
}

func (c *Config) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: c.fetchTimeout()}
}

// Inspect pre-fetches url with Chrome headers, then asks Haiku whether
// the content is safe. Returns a Verdict with Allow=true and a reason.
// All errors fail open (Allow=true) per the package contract, with one
// exception: private/loopback/metadata URLs return Allow=false so the
// user sees the permission prompt rather than the inspector auto-approving
// a request to an internal service.
func Inspect(ctx context.Context, url string, cfg Config) Verdict {
	allow := func(reason string) Verdict { return Verdict{Allow: true, Reason: reason} }

	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return allow("non-http url")
	}

	// Fast path: determine which API key (if any) we can use BEFORE making
	// any network request. Without a key we can't call an LLM, so skip the
	// fetch entirely and fail open immediately. The SSRF guard still runs
	// because we must never auto-approve requests to internal services.
	anthropicKey := cfg.apiKey()
	geminiKey := cfg.geminiKey()

	// SSRF guard: reject private/loopback/link-local/metadata URLs before
	// making any outbound request.
	if !cfg.DisableSSRFCheck {
		if err := checkSSRF(url); err != nil {
			return Verdict{Allow: false, Reason: "SSRF guard: private/internal URL blocked"}
		}
	}

	if anthropicKey == "" && geminiKey == "" {
		return allow("no API key configured")
	}

	body, contentType, err := fetch(ctx, url, cfg)
	if errors.Is(err, errSSRF) {
		// A redirect led to a private IP — surface to user prompt.
		return Verdict{Allow: false, Reason: "SSRF guard: redirect to private/internal URL blocked"}
	}
	if err != nil || body == "" {
		return allow("fetch failed or empty")
	}

	if !isTextContent(contentType) {
		return allow("binary content-type skipped")
	}

	var verdict string
	if anthropicKey != "" {
		verdict, err = callHaiku(ctx, url, body, anthropicKey, cfg)
		if err != nil {
			verdict = ""
		}
	}
	if verdict == "" && geminiKey != "" {
		verdict, err = callGemini(ctx, url, body, geminiKey, cfg)
		if err != nil {
			verdict = ""
		}
	}
	if verdict == "" {
		return allow("inspection error")
	}

	if strings.HasPrefix(verdict, "SAFE") {
		return Verdict{Allow: true, Reason: "safe"}
	}
	if strings.HasPrefix(verdict, "UNSAFE") {
		reason := strings.TrimSpace(strings.TrimPrefix(verdict, "UNSAFE:"))
		if len(reason) > 120 {
			reason = reason[:120]
		}
		return Verdict{Allow: false, Reason: "flagged: " + reason}
	}

	return allow("inconclusive verdict")
}

// fetch retrieves url with Chrome headers. Returns empty string + nil error
// when the server responds with a non-2xx status (not malicious, just unavailable).
func fetch(ctx context.Context, url string, cfg Config) (body string, contentType string, err error) {
	client := cfg.httpClient()

	fetchCtx, cancel := context.WithTimeout(ctx, cfg.fetchTimeout())
	defer cancel()

	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, url, nil)
	if err != nil {
		return "", "", err
	}
	for _, h := range chromeHeaders {
		req.Header.Set(h[0], h[1])
	}

	// Limit redirects — follow enough to handle common CDN hops.
	// Also re-check SSRF on each hop so a public→private redirect is caught.
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return http.ErrUseLastResponse
		}
		if !cfg.DisableSSRFCheck {
			if ssrfErr := checkSSRF(req.URL.String()); ssrfErr != nil {
				return errSSRF // propagated to Inspect via errors.Is
			}
		}
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", nil
	}

	contentType = resp.Header.Get("Content-Type")

	// Go's default transport auto-decompresses gzip (DisableCompression=false).
	limited, err := io.ReadAll(io.LimitReader(resp.Body, cfg.maxBodyBytes()))
	if err != nil {
		return "", contentType, err
	}

	return string(limited), contentType, nil
}

// isTextContent returns true for content types worth sending to Haiku.
// Binary formats (images, archives, etc.) are never inspected.
func isTextContent(contentType string) bool {
	ct := strings.ToLower(contentType)
	for _, prefix := range []string{"text/", "application/json", "application/xml", "application/xhtml"} {
		if strings.Contains(ct, prefix) {
			return true
		}
	}
	return ct == "" // empty content-type: be permissive
}

// --- Anthropic API call -------------------------------------------------

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
}

const inspectPrompt = `URL: %s

Content (first 8KB):
---
%s
---

Reply with exactly one line:
SAFE
or
UNSAFE: <reason under 80 chars>

Flag UNSAFE only for: active phishing, malware delivery, credential-harvesting forms, obvious data-exfiltration endpoints.
Dev docs, APIs, articles, GitHub, share links, release notes, error pages = SAFE.`

func callHaiku(ctx context.Context, url, body, apiKey string, cfg Config) (string, error) {
	reqBody, err := json.Marshal(anthropicRequest{
		Model:     cfg.model(),
		MaxTokens: DefaultMaxTokens,
		Messages: []anthropicMessage{
			{Role: "user", Content: fmt.Sprintf(inspectPrompt, url, body)},
		},
	})
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}

	callCtx, cancel := context.WithTimeout(ctx, DefaultInspectTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(callCtx, http.MethodPost, cfg.anthropicURL()+"/v1/messages", bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	httpClient := cfg.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: DefaultInspectTimeout}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("anthropic %d: %s", resp.StatusCode, truncate(string(raw), 100))
	}

	var ar anthropicResponse
	if err := json.Unmarshal(raw, &ar); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}
	for _, block := range ar.Content {
		if block.Type == "text" {
			return strings.TrimSpace(block.Text), nil
		}
	}
	return "", fmt.Errorf("no text block in response")
}

// --- Gemini API call -------------------------------------------------------

type geminiRequest struct {
	Contents []geminiContent `json:"contents"`
}

type geminiContent struct {
	Role  string       `json:"role"`
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
}

func callGemini(ctx context.Context, url, body, apiKey string, cfg Config) (string, error) {
	prompt := fmt.Sprintf(inspectPrompt, url, body)
	reqBody, err := json.Marshal(geminiRequest{
		Contents: []geminiContent{
			{Role: "user", Parts: []geminiPart{{Text: prompt}}},
		},
	})
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}

	callCtx, cancel := context.WithTimeout(ctx, DefaultInspectTimeout)
	defer cancel()

	endpoint := fmt.Sprintf("%s/v1beta/models/%s:generateContent?key=%s",
		cfg.geminiURL(), DefaultGeminiModel, apiKey)
	req, err := http.NewRequestWithContext(callCtx, http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	httpClient := cfg.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: DefaultInspectTimeout}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gemini %d: %s", resp.StatusCode, truncate(string(raw), 100))
	}

	var gr geminiResponse
	if err := json.Unmarshal(raw, &gr); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}
	for _, candidate := range gr.Candidates {
		for _, part := range candidate.Content.Parts {
			if t := strings.TrimSpace(part.Text); t != "" {
				return t, nil
			}
		}
	}
	return "", fmt.Errorf("no text in gemini response")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
