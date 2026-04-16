package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/RobinUS2/claude-guard/internal/llm/breaker"
)

// DefaultAnthropicModel is the model used when none is specified.
// Haiku 4.5 is the right pick: fast (sub-second p95), cheap, and the
// same model family Claude Code itself runs on, so the prompt language
// behaves predictably.
const DefaultAnthropicModel = "claude-haiku-4-5"

// AnthropicClassifier hits the Anthropic Messages API for classification.
type AnthropicClassifier struct {
	APIKey       string
	ModelName    string
	BaseURL      string        // default: https://api.anthropic.com
	Timeout      time.Duration // default: 3s
	MaxTokens    int           // default: 200
	SystemPrompt string        // default: DefaultSystemPrompt()
	HTTP         *http.Client
}

// NewAnthropic constructs an AnthropicClassifier with sensible defaults.
func NewAnthropic(apiKey, model string) *AnthropicClassifier {
	if model == "" {
		model = DefaultAnthropicModel
	}
	return &AnthropicClassifier{
		APIKey:       apiKey,
		ModelName:    model,
		BaseURL:      "https://api.anthropic.com",
		Timeout:      3 * time.Second,
		MaxTokens:    400,
		SystemPrompt: DefaultSystemPrompt(),
		HTTP:         &http.Client{Timeout: 3 * time.Second},
	}
}

// Provider identifies this implementation in logs and stats.
func (c *AnthropicClassifier) Provider() string { return "anthropic" }

// Model returns the configured model identifier.
func (c *AnthropicClassifier) Model() string { return c.ModelName }

// Classify sends the input to Anthropic. Inline retries (up to 2 attempts
// total) handle transient 5xx and brief 429s. Longer outages return an
// error for the caller's circuit breaker to handle.
func (c *AnthropicClassifier) Classify(ctx context.Context, in ClassifyInput) (*Decision, error) {
	if c.APIKey == "" {
		return nil, fmt.Errorf("llm: anthropic: missing API key")
	}
	if c.ModelName == "" {
		return nil, fmt.Errorf("llm: anthropic: missing model")
	}

	body, err := json.Marshal(c.buildRequest(in))
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	const maxAttempts = 2
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		dec, err := c.callOnce(ctx, body)
		if err == nil {
			return dec, nil
		}
		lastErr = err

		retry, wait := shouldRetry(err)
		if !retry || attempt == maxAttempts {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, &breaker.TimeoutError{After: c.Timeout}
		case <-time.After(wait):
		}
	}
	return nil, lastErr
}

func (c *AnthropicClassifier) callOnce(ctx context.Context, body []byte) (*Decision, error) {
	reqCtx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "POST", c.BaseURL+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		if reqCtx.Err() == context.DeadlineExceeded {
			return nil, &breaker.TimeoutError{After: c.Timeout}
		}
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	switch {
	case resp.StatusCode == http.StatusOK:
		return c.parseResponse(respBytes)
	case resp.StatusCode == http.StatusTooManyRequests:
		retryAfter := parseRetryAfter(resp.Header.Get("retry-after"), time.Now())
		return nil, &breaker.RateLimitError{
			RetryAfter: retryAfter,
			Detail:     truncate(string(respBytes), 200),
		}
	case resp.StatusCode >= 500 && resp.StatusCode < 600:
		return nil, &breaker.ServerError{
			StatusCode: resp.StatusCode,
			Detail:     truncate(string(respBytes), 200),
		}
	default:
		return nil, fmt.Errorf("anthropic API %d: %s", resp.StatusCode, truncate(string(respBytes), 200))
	}
}

// parseRetryAfter handles both "<seconds>" and "<HTTP-date>" formats.
// Returns now + 60s as a fallback when the header is unparseable.
func parseRetryAfter(header string, now time.Time) time.Time {
	if header == "" {
		return now.Add(60 * time.Second)
	}
	header = strings.TrimSpace(header)
	if secs, err := strconv.Atoi(header); err == nil && secs >= 0 {
		return now.Add(time.Duration(secs) * time.Second)
	}
	if t, err := http.ParseTime(header); err == nil {
		return t
	}
	return now.Add(60 * time.Second)
}

// --- request shape ---

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

func (c *AnthropicClassifier) buildRequest(in ClassifyInput) anthropicRequest {
	return anthropicRequest{
		Model:     c.ModelName,
		MaxTokens: c.MaxTokens,
		System:    c.SystemPrompt,
		Messages:  []anthropicMessage{{Role: "user", Content: buildUserMessage(in)}},
	}
}

// --- response shape ---

type anthropicResponse struct {
	Content []anthropicContent `json:"content"`
}

type anthropicContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func (c *AnthropicClassifier) parseResponse(raw []byte) (*Decision, error) {
	var resp anthropicResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("parse api response: %w", err)
	}
	if len(resp.Content) == 0 || resp.Content[0].Text == "" {
		return nil, fmt.Errorf("api returned empty content")
	}
	return extractDecision(resp.Content[0].Text)
}
