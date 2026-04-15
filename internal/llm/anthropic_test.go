package llm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RobinUS2/claude-guard/internal/llm/breaker"
)

func newStubServer(handler http.HandlerFunc) (*httptest.Server, *AnthropicClassifier) {
	srv := httptest.NewServer(handler)
	c := NewAnthropic("test-key", "claude-haiku-4-5")
	c.BaseURL = srv.URL
	c.Timeout = 2 * time.Second
	c.HTTP = &http.Client{Timeout: 2 * time.Second}
	return srv, c
}

func writeMessagesResponse(w http.ResponseWriter, decisionJSON string) {
	resp := anthropicResponse{
		Content: []anthropicContent{{Type: "text", Text: decisionJSON}},
	}
	body, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func TestClassify_Safe(t *testing.T) {
	srv, c := newStubServer(func(w http.ResponseWriter, r *http.Request) {
		writeMessagesResponse(w, `{"decision":"safe","category":"read_only_query","reason":"git status is read-only"}`)
	})
	defer srv.Close()

	dec, err := c.Classify(context.Background(), ClassifyInput{Command: "git status"})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if dec.Verdict != VerdictSafe {
		t.Errorf("Verdict = %q, want safe", dec.Verdict)
	}
	if dec.Reason == "" {
		t.Error("Reason should be populated")
	}
}

func TestClassify_Unsafe(t *testing.T) {
	srv, c := newStubServer(func(w http.ResponseWriter, r *http.Request) {
		writeMessagesResponse(w, `{"decision":"unsafe","category":"destructive","reason":"removes data"}`)
	})
	defer srv.Close()

	dec, err := c.Classify(context.Background(), ClassifyInput{Command: "rm -rf /"})
	if err != nil {
		t.Fatal(err)
	}
	if dec.Verdict != VerdictUnsafe {
		t.Errorf("Verdict = %q", dec.Verdict)
	}
}

func TestClassify_Unsure(t *testing.T) {
	srv, c := newStubServer(func(w http.ResponseWriter, r *http.Request) {
		writeMessagesResponse(w, `{"decision":"unsure","category":"unknown","reason":"opaque script"}`)
	})
	defer srv.Close()

	dec, err := c.Classify(context.Background(), ClassifyInput{Command: "./run.sh"})
	if err != nil {
		t.Fatal(err)
	}
	if dec.Verdict != VerdictUnsure {
		t.Errorf("Verdict = %q", dec.Verdict)
	}
}

func TestClassify_JSONInProse(t *testing.T) {
	// Model wraps the JSON in markdown — extractor should still find it.
	srv, c := newStubServer(func(w http.ResponseWriter, r *http.Request) {
		writeMessagesResponse(w, "Sure, here's my classification:\n\n```json\n{\"decision\":\"safe\",\"reason\":\"trivial read\"}\n```")
	})
	defer srv.Close()

	dec, err := c.Classify(context.Background(), ClassifyInput{Command: "ls"})
	if err != nil {
		t.Fatal(err)
	}
	if dec.Verdict != VerdictSafe {
		t.Errorf("Verdict = %q", dec.Verdict)
	}
}

func TestClassify_5xxRetryThenSucceed(t *testing.T) {
	var calls int32
	srv, c := newStubServer(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("overloaded"))
			return
		}
		writeMessagesResponse(w, `{"decision":"safe","reason":"ok"}`)
	})
	defer srv.Close()

	dec, err := c.Classify(context.Background(), ClassifyInput{Command: "git status"})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if dec.Verdict != VerdictSafe {
		t.Errorf("Verdict = %q", dec.Verdict)
	}
	if atomic.LoadInt32(&calls) != 2 {
		t.Errorf("expected 2 calls, got %d", calls)
	}
}

func TestClassify_5xxBothFail(t *testing.T) {
	srv, c := newStubServer(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("upstream"))
	})
	defer srv.Close()

	_, err := c.Classify(context.Background(), ClassifyInput{Command: "ls"})
	if err == nil {
		t.Fatal("expected error after retry exhaustion")
	}
	var srvErr *breaker.ServerError
	if !errors.As(err, &srvErr) {
		t.Errorf("error type = %T, want *breaker.ServerError", err)
	}
}

func TestClassify_429WithBriefRetryAfter(t *testing.T) {
	var calls int32
	srv, c := newStubServer(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			w.Header().Set("retry-after", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		writeMessagesResponse(w, `{"decision":"safe","reason":"ok"}`)
	})
	defer srv.Close()

	dec, err := c.Classify(context.Background(), ClassifyInput{Command: "git status"})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if dec.Verdict != VerdictSafe {
		t.Errorf("Verdict = %q", dec.Verdict)
	}
}

func TestClassify_429WithLongRetryAfter_NoRetry(t *testing.T) {
	var calls int32
	srv, c := newStubServer(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("retry-after", "900") // 15 minutes
		w.WriteHeader(http.StatusTooManyRequests)
	})
	defer srv.Close()

	_, err := c.Classify(context.Background(), ClassifyInput{Command: "git status"})
	if err == nil {
		t.Fatal("expected RateLimitError")
	}
	var rl *breaker.RateLimitError
	if !errors.As(err, &rl) {
		t.Errorf("error type = %T, want *breaker.RateLimitError", err)
	}
	if rl.RetryAfter.Before(time.Now().Add(800 * time.Second)) {
		t.Errorf("RetryAfter too soon: %v", rl.RetryAfter)
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Errorf("should not have retried; got %d calls", calls)
	}
}

func TestClassify_4xxNoRetry(t *testing.T) {
	var calls int32
	srv, c := newStubServer(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("bad request"))
	})
	defer srv.Close()

	_, err := c.Classify(context.Background(), ClassifyInput{Command: "ls"})
	if err == nil {
		t.Fatal("expected error")
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Errorf("should not have retried 4xx; got %d calls", calls)
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("error should mention status: %v", err)
	}
}

func TestClassify_Timeout(t *testing.T) {
	srv, c := newStubServer(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
	})
	defer srv.Close()
	c.Timeout = 50 * time.Millisecond
	c.HTTP = &http.Client{Timeout: 50 * time.Millisecond}

	_, err := c.Classify(context.Background(), ClassifyInput{Command: "ls"})
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestClassify_MalformedResponse(t *testing.T) {
	srv, c := newStubServer(func(w http.ResponseWriter, r *http.Request) {
		writeMessagesResponse(w, `not json at all`)
	})
	defer srv.Close()

	_, err := c.Classify(context.Background(), ClassifyInput{Command: "ls"})
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestClassify_MissingAPIKey(t *testing.T) {
	c := NewAnthropic("", "claude-haiku-4-5")
	_, err := c.Classify(context.Background(), ClassifyInput{Command: "ls"})
	if err == nil {
		t.Error("expected error for missing API key")
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		header string
		want   time.Time
	}{
		{"60", now.Add(60 * time.Second)},
		{"0", now},
		{"", now.Add(60 * time.Second)},
		{"not a number", now.Add(60 * time.Second)},
	}
	for _, tc := range cases {
		got := parseRetryAfter(tc.header, now)
		if !got.Equal(tc.want) {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", tc.header, got, tc.want)
		}
	}
}

func TestBuildUserMessage_IncludesAllContext(t *testing.T) {
	in := ClassifyInput{
		Command:     "git status",
		Description: "check git state",
		CWD:         "/tmp/test",
		GitBranch:   "main",
	}
	msg := buildUserMessage(in)
	if !strings.Contains(msg, "git status") {
		t.Error("missing command")
	}
	if !strings.Contains(msg, "check git state") {
		t.Error("missing description")
	}
	if !strings.Contains(msg, "/tmp/test") {
		t.Error("missing cwd")
	}
	if !strings.Contains(msg, "main") {
		t.Error("missing branch")
	}
}

func TestRequestShape(t *testing.T) {
	var captured anthropicRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&captured)
		writeMessagesResponse(w, `{"decision":"safe","reason":"ok"}`)
	}))
	defer srv.Close()
	c := NewAnthropic("test-key", "claude-haiku-4-5")
	c.BaseURL = srv.URL

	_, _ = c.Classify(context.Background(), ClassifyInput{Command: "git status"})

	if captured.Model != "claude-haiku-4-5" {
		t.Errorf("Model = %q", captured.Model)
	}
	if captured.MaxTokens == 0 {
		t.Error("MaxTokens should be set")
	}
	if !strings.Contains(captured.System, "security classifier") {
		t.Errorf("System prompt missing or wrong: %q", captured.System[:60])
	}
	if len(captured.Messages) != 1 || captured.Messages[0].Role != "user" {
		t.Errorf("Messages = %+v", captured.Messages)
	}
}
