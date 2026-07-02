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
	"fmt"
	"io"
	"net/http"
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
)

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
	APIKey       string        // Anthropic API key; falls back to ANTHROPIC_API_KEY env var
	AnthropicURL string        // override for testing; default: DefaultAnthropicBase
	MaxBodyBytes int64         // default: DefaultMaxBodyBytes
	FetchTimeout time.Duration // default: DefaultFetchTimeout
	InspectModel string        // default: DefaultModel
	HTTP         *http.Client  // shared client; a new one is created if nil
}

func (c *Config) apiKey() string {
	if c.APIKey != "" {
		return c.APIKey
	}
	return os.Getenv("ANTHROPIC_API_KEY")
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
// All errors fail open (Allow=true) per the package contract.
func Inspect(ctx context.Context, url string, cfg Config) Verdict {
	allow := func(reason string) Verdict { return Verdict{Allow: true, Reason: reason} }

	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return allow("non-http url")
	}

	body, contentType, err := fetch(ctx, url, cfg)
	if err != nil || body == "" {
		return allow("fetch failed or empty")
	}

	if !isTextContent(contentType) {
		return allow("binary content-type skipped")
	}

	apiKey := cfg.apiKey()
	if apiKey == "" {
		return allow("no ANTHROPIC_API_KEY")
	}

	verdict, err := callHaiku(ctx, url, body, apiKey, cfg)
	if err != nil {
		return allow("haiku error")
	}

	if strings.HasPrefix(verdict, "SAFE") {
		return Verdict{Allow: true, Reason: "Haiku: safe"}
	}
	if strings.HasPrefix(verdict, "UNSAFE") {
		reason := strings.TrimSpace(strings.TrimPrefix(verdict, "UNSAFE:"))
		if len(reason) > 120 {
			reason = reason[:120]
		}
		return Verdict{Allow: false, Reason: "Haiku flagged: " + reason}
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
	client.CheckRedirect = func(_ *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return http.ErrUseLastResponse
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
