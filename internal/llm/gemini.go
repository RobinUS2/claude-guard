package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/RobinUS2/claude-guard/internal/llm/breaker"
)

// DefaultGeminiModel is Gemini 2.5 Flash — fast, cheap, good at strict
// JSON output. The 2.5 Flash family is significantly cheaper than Haiku
// for short prompts and typically returns in under 500ms.
const DefaultGeminiModel = "gemini-2.5-flash"

// GeminiClassifier hits Google's Gemini API for classification.
type GeminiClassifier struct {
	APIKey       string
	ModelName    string
	BaseURL      string        // default: https://generativelanguage.googleapis.com
	Timeout      time.Duration // default: 3s
	MaxTokens    int           // default: 200
	SystemPrompt string        // default: DefaultSystemPrompt()
	HTTP         *http.Client
}

// NewGemini constructs a GeminiClassifier with sensible defaults.
//
// MaxTokens default is 600 — Gemini 2.5 Flash sometimes prefixes JSON
// output with brief preamble before honoring strict-JSON mode, and the
// previous 200-token budget got truncated mid-preamble. 600 leaves plenty
// of room for the actual JSON object plus any leading framing.
func NewGemini(apiKey, model string) *GeminiClassifier {
	if model == "" {
		model = DefaultGeminiModel
	}
	return &GeminiClassifier{
		APIKey:       apiKey,
		ModelName:    model,
		BaseURL:      "https://generativelanguage.googleapis.com",
		Timeout:      4 * time.Second,
		MaxTokens:    600,
		SystemPrompt: DefaultSystemPrompt(),
		HTTP:         &http.Client{Timeout: 4 * time.Second},
	}
}

func (c *GeminiClassifier) Provider() string { return "gemini" }
func (c *GeminiClassifier) Model() string    { return c.ModelName }

// Classify sends the input to Gemini. Same retry semantics as Anthropic:
// 1 retry on 5xx after 200ms, 1 retry on brief 429.
func (c *GeminiClassifier) Classify(ctx context.Context, in ClassifyInput) (*Decision, error) {
	if c.APIKey == "" {
		return nil, fmt.Errorf("llm: gemini: missing API key")
	}
	if c.ModelName == "" {
		return nil, fmt.Errorf("llm: gemini: missing model")
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

func (c *GeminiClassifier) callOnce(ctx context.Context, body []byte) (*Decision, error) {
	reqCtx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()

	// Gemini auth: API key as query param OR x-goog-api-key header.
	// Header is cleaner — doesn't end up in any logs that capture URLs.
	url := fmt.Sprintf("%s/v1beta/models/%s:generateContent", c.BaseURL, c.ModelName)
	req, err := http.NewRequestWithContext(reqCtx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-goog-api-key", c.APIKey)

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
		// Gemini uses a richer error envelope but also honors retry-after.
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
		return nil, fmt.Errorf("gemini API %d: %s", resp.StatusCode, truncate(string(respBytes), 200))
	}
}

// --- request shape ---

type geminiRequest struct {
	SystemInstruction *geminiSystem    `json:"systemInstruction,omitempty"`
	Contents          []geminiContent  `json:"contents"`
	GenerationConfig  geminiGenConfig  `json:"generationConfig"`
}

type geminiSystem struct {
	Parts []geminiPart `json:"parts"`
}

type geminiContent struct {
	Role  string       `json:"role"`
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text string `json:"text"`
}

// geminiResponseSchema is the JSON Schema we hand Gemini to force the
// output shape. responseSchema in combination with responseMimeType is
// the supported way to get strict JSON out of the v1beta API.
type geminiResponseSchema struct {
	Type       string                       `json:"type"`
	Properties map[string]geminiSchemaField `json:"properties"`
	Required   []string                     `json:"required,omitempty"`
}

type geminiSchemaField struct {
	Type        string   `json:"type"`
	Description string   `json:"description,omitempty"`
	Enum        []string `json:"enum,omitempty"`
}

type geminiGenConfig struct {
	MaxOutputTokens  int                   `json:"maxOutputTokens"`
	Temperature      float64               `json:"temperature"`
	ResponseMIMEType string                `json:"responseMimeType,omitempty"`
	ResponseSchema   *geminiResponseSchema `json:"responseSchema,omitempty"`
}

// classifierResponseSchema describes the strict shape we expect from the
// classifier. With responseMimeType=application/json + this schema, Gemini
// 2.5 Flash returns a valid JSON object on the first attempt.
var classifierResponseSchema = &geminiResponseSchema{
	Type: "object",
	Properties: map[string]geminiSchemaField{
		"decision": {
			Type:        "string",
			Description: "safe | unsafe | unsure",
			Enum:        []string{"safe", "unsafe", "unsure"},
		},
		"category": {
			Type:        "string",
			Description: "category tag for the command",
			Enum: []string{
				"read_only_query", "file_read", "file_write_scoped",
				"external_write", "destructive", "exfil", "unknown",
			},
		},
		"reason": {
			Type:        "string",
			Description: "1-2 sentence plain-English explanation",
		},
	},
	Required: []string{"decision", "reason"},
}

func (c *GeminiClassifier) buildRequest(in ClassifyInput) geminiRequest {
	return geminiRequest{
		SystemInstruction: &geminiSystem{
			Parts: []geminiPart{{Text: c.SystemPrompt}},
		},
		Contents: []geminiContent{
			{
				Role:  "user",
				Parts: []geminiPart{{Text: buildUserMessage(in)}},
			},
		},
		GenerationConfig: geminiGenConfig{
			MaxOutputTokens:  c.MaxTokens,
			Temperature:      0,
			ResponseMIMEType: "application/json",
			ResponseSchema:   classifierResponseSchema,
		},
	}
}

// --- response shape ---

type geminiResponse struct {
	Candidates []geminiCandidate `json:"candidates"`
}

type geminiCandidate struct {
	Content geminiContent `json:"content"`
}

func (c *GeminiClassifier) parseResponse(raw []byte) (*Decision, error) {
	var resp geminiResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("parse api response: %w", err)
	}
	if len(resp.Candidates) == 0 || len(resp.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("gemini returned empty content")
	}
	return extractDecision(resp.Candidates[0].Content.Parts[0].Text)
}
