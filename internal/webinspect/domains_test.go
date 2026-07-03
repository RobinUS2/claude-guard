package webinspect

// Domain scenario tests: table-driven inspection of realistic content types.
//
// All network calls use httptest servers — no real DNS, no real internet.
// Two axes:
//   1. Content flavour (news, docs, phishing, malware, API, RSS, binary…)
//   2. Plumbing (Gemini fallback, warning propagation, redirect SSRF, gzip)

import (
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// llmSrv spins up a mock LLM API server that always returns verdict.
// It speaks both the Anthropic and Gemini response shapes depending on the
// path prefix — the tests wire them via Config.AnthropicURL / Config.GeminiURL.
func llmSrv(t *testing.T, verdict string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "generateContent") {
			// Gemini shape
			_, _ = w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"` + verdict + `"}]}}]}`))
		} else {
			// Anthropic shape
			_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"` + verdict + `"}]}`))
		}
	}))
}

// pageSrv spins up a content server returning body with content-type ct.
func pageSrv(t *testing.T, ct, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", ct)
		_, _ = w.Write([]byte(body))
	}))
}

// --- Content-type domain scenarios ----------------------------------------

func TestDomains_NewsSite_Safe(t *testing.T) {
	llm := llmSrv(t, "SAFE")
	defer llm.Close()
	page := pageSrv(t, "text/html; charset=utf-8",
		`<html><head><title>Nieuws - NU.nl</title></head>
		<body><article><h1>Breaking news</h1><p>Some article text here.</p></article></body></html>`)
	defer page.Close()

	v := Inspect(context.Background(), page.URL, Config{
		APIKey:           "fake-key",
		AnthropicURL:     llm.URL,
		HTTP:             page.Client(),
		DisableSSRFCheck: true,
	})
	if !v.Allow {
		t.Errorf("news site should be allowed; reason=%q warnings=%v", v.Reason, v.Warnings)
	}
	if len(v.Warnings) > 0 {
		t.Errorf("no warnings expected for clean news page; got %v", v.Warnings)
	}
}

func TestDomains_DevDocs_Safe(t *testing.T) {
	llm := llmSrv(t, "SAFE")
	defer llm.Close()
	page := pageSrv(t, "text/html",
		`<html><body><h1>Go HTTP package</h1>
		<pre><code>func Get(url string) (*Response, error)</code></pre>
		<p>Get issues a GET to the specified URL.</p></body></html>`)
	defer page.Close()

	v := Inspect(context.Background(), page.URL, Config{
		APIKey:           "fake-key",
		AnthropicURL:     llm.URL,
		HTTP:             page.Client(),
		DisableSSRFCheck: true,
	})
	if !v.Allow {
		t.Errorf("dev docs should be allowed; reason=%q", v.Reason)
	}
}

func TestDomains_GitHubPR_Safe(t *testing.T) {
	llm := llmSrv(t, "SAFE")
	defer llm.Close()
	page := pageSrv(t, "text/html",
		`<html><body><h1>Pull Request #42 — fix: handle nil pointer</h1>
		<div class="diff">-old line +new line</div></body></html>`)
	defer page.Close()

	v := Inspect(context.Background(), page.URL, Config{
		APIKey:           "fake-key",
		AnthropicURL:     llm.URL,
		HTTP:             page.Client(),
		DisableSSRFCheck: true,
	})
	if !v.Allow {
		t.Errorf("GitHub PR should be allowed; reason=%q", v.Reason)
	}
}

func TestDomains_RSSFeed_Safe(t *testing.T) {
	llm := llmSrv(t, "SAFE")
	defer llm.Close()
	page := pageSrv(t, "application/rss+xml",
		`<?xml version="1.0"?><rss version="2.0"><channel>
		<title>News feed</title><item><title>Article</title></item>
		</channel></rss>`)
	defer page.Close()

	v := Inspect(context.Background(), page.URL, Config{
		APIKey:           "fake-key",
		AnthropicURL:     llm.URL,
		HTTP:             page.Client(),
		DisableSSRFCheck: true,
	})
	if !v.Allow {
		t.Errorf("RSS feed should be allowed; reason=%q", v.Reason)
	}
	// application/rss+xml must be recognised as text so LLM inspection runs,
	// not skipped as binary (which would emit a warning).
	if len(v.Warnings) > 0 {
		t.Errorf("RSS feed should be inspected via LLM, not skipped; warnings=%v", v.Warnings)
	}
}

func TestDomains_JSONapi_Safe(t *testing.T) {
	llm := llmSrv(t, "SAFE")
	defer llm.Close()
	page := pageSrv(t, "application/json",
		`{"version":"1.0","endpoints":[{"path":"/health","method":"GET"}]}`)
	defer page.Close()

	v := Inspect(context.Background(), page.URL, Config{
		APIKey:           "fake-key",
		AnthropicURL:     llm.URL,
		HTTP:             page.Client(),
		DisableSSRFCheck: true,
	})
	if !v.Allow {
		t.Errorf("JSON API response should be allowed; reason=%q", v.Reason)
	}
}

func TestDomains_Phishing_Blocked(t *testing.T) {
	llm := llmSrv(t, "UNSAFE: credential harvesting form")
	defer llm.Close()
	page := pageSrv(t, "text/html",
		`<html><body><h1>Your account has been suspended</h1>
		<form><input type="text" placeholder="Enter your bank username">
		<input type="password" placeholder="Password">
		<input type="text" placeholder="Credit card number">
		<button>Verify now</button></form></body></html>`)
	defer page.Close()

	v := Inspect(context.Background(), page.URL, Config{
		APIKey:           "fake-key",
		AnthropicURL:     llm.URL,
		HTTP:             page.Client(),
		DisableSSRFCheck: true,
	})
	if v.Allow {
		t.Errorf("phishing page should be blocked; reason=%q", v.Reason)
	}
	if !strings.Contains(v.Reason, "credential harvesting") {
		t.Errorf("reason should mention credential harvesting; got %q", v.Reason)
	}
}

func TestDomains_MalwareDelivery_Blocked(t *testing.T) {
	llm := llmSrv(t, "UNSAFE: malware delivery page with auto-download")
	defer llm.Close()
	page := pageSrv(t, "text/html",
		`<html><head><meta http-equiv="refresh" content="0;url=payload.exe"></head>
		<body><script>window.location='evil.exe'</script>Your file is downloading...</body></html>`)
	defer page.Close()

	v := Inspect(context.Background(), page.URL, Config{
		APIKey:           "fake-key",
		AnthropicURL:     llm.URL,
		HTTP:             page.Client(),
		DisableSSRFCheck: true,
	})
	if v.Allow {
		t.Errorf("malware delivery page should be blocked; reason=%q", v.Reason)
	}
}

// --- Binary / non-text content --------------------------------------------

func TestDomains_ImagePNG_AllowedWithoutInspection(t *testing.T) {
	// No LLM server needed — binary content is allowed without calling LLM.
	page := pageSrv(t, "image/png", "\x89PNG\r\n\x1a\nbinary image data")

	v := Inspect(context.Background(), page.URL, Config{
		APIKey:           "fake-key",
		HTTP:             page.Client(),
		DisableSSRFCheck: true,
	})
	if !v.Allow {
		t.Errorf("PNG should be allowed (binary, skip inspection); reason=%q", v.Reason)
	}
	// A warning should note that binary content was skipped.
	found := false
	for _, w := range v.Warnings {
		if strings.Contains(w, "binary") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected binary-content warning; warnings=%v", v.Warnings)
	}
}

func TestDomains_PDF_AllowedWithoutInspection(t *testing.T) {
	page := pageSrv(t, "application/pdf", "%PDF-1.4 binary pdf content")

	v := Inspect(context.Background(), page.URL, Config{
		APIKey:           "fake-key",
		HTTP:             page.Client(),
		DisableSSRFCheck: true,
	})
	if !v.Allow {
		t.Errorf("PDF should be allowed (binary, skip inspection); reason=%q", v.Reason)
	}
}

// --- Gzip decompression ---------------------------------------------------

func TestDomains_GzipContent_Decompressed(t *testing.T) {
	// Serve gzip-encoded HTML — Go transport auto-decompresses when it adds
	// Accept-Encoding itself (which it does when the caller doesn't set it).
	llm := llmSrv(t, "SAFE")
	defer llm.Close()

	gzipSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		_, _ = gz.Write([]byte("<html><body>gzip compressed news article</body></html>"))
		_ = gz.Close()
	}))
	defer gzipSrv.Close()

	v := Inspect(context.Background(), gzipSrv.URL, Config{
		APIKey:           "fake-key",
		AnthropicURL:     llm.URL,
		HTTP:             gzipSrv.Client(),
		DisableSSRFCheck: true,
	})
	if !v.Allow {
		t.Errorf("gzip content should decompress and be allowed; reason=%q warnings=%v", v.Reason, v.Warnings)
	}
}

// --- Gemini fallback ------------------------------------------------------

func TestDomains_GeminiPrimary_Safe(t *testing.T) {
	// Anthropic key absent → only Gemini is tried.
	gemini := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"SAFE"}]}}]}`))
	}))
	defer gemini.Close()

	page := pageSrv(t, "text/html", "<html><body>docs page</body></html>")
	defer page.Close()

	v := Inspect(context.Background(), page.URL, Config{
		GeminiKey:        "fake-gemini-key",
		GeminiURL:        gemini.URL,
		HTTP:             page.Client(),
		DisableSSRFCheck: true,
	})
	if !v.Allow {
		t.Errorf("Gemini-primary safe verdict should allow; reason=%q", v.Reason)
	}
}

func TestDomains_GeminiFallback_WhenHaikuFails(t *testing.T) {
	// Haiku returns 500; Gemini returns SAFE → should still allow.
	haikuFail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"overloaded"}`))
	}))
	defer haikuFail.Close()

	geminiOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"SAFE"}]}}]}`))
	}))
	defer geminiOK.Close()

	page := pageSrv(t, "text/html", "<html><body>article content</body></html>")
	defer page.Close()

	v := Inspect(context.Background(), page.URL, Config{
		APIKey:           "fake-anthropic-key",
		GeminiKey:        "fake-gemini-key",
		AnthropicURL:     haikuFail.URL,
		GeminiURL:        geminiOK.URL,
		HTTP:             page.Client(),
		DisableSSRFCheck: true,
	})
	if !v.Allow {
		t.Errorf("should allow when Haiku fails but Gemini succeeds; reason=%q warnings=%v", v.Reason, v.Warnings)
	}
	// Haiku failure should appear in warnings.
	found := false
	for _, w := range v.Warnings {
		if strings.Contains(w, "haiku") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected haiku error in warnings; got %v", v.Warnings)
	}
}

func TestDomains_BothLLMsFail_FailOpen(t *testing.T) {
	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer fail.Close()

	page := pageSrv(t, "text/html", "<html><body>content</body></html>")
	defer page.Close()

	v := Inspect(context.Background(), page.URL, Config{
		APIKey:           "fake-key",
		GeminiKey:        "fake-gemini-key",
		AnthropicURL:     fail.URL,
		GeminiURL:        fail.URL,
		HTTP:             page.Client(),
		DisableSSRFCheck: true,
	})
	if !v.Allow {
		t.Errorf("should fail open when all LLMs fail; reason=%q", v.Reason)
	}
	if len(v.Warnings) < 2 {
		t.Errorf("expected warnings from both LLM failures; got %v", v.Warnings)
	}
}

// --- Warning propagation --------------------------------------------------

func TestDomains_Warnings_FetchError(t *testing.T) {
	// Point to a server that immediately closes the connection.
	closed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Hijack and close to force a fetch error.
		hj, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(500)
			return
		}
		conn, _, _ := hj.Hijack()
		conn.Close()
	}))
	defer closed.Close()

	v := Inspect(context.Background(), closed.URL, Config{
		APIKey:           "fake-key",
		HTTP:             closed.Client(),
		DisableSSRFCheck: true,
	})
	if !v.Allow {
		t.Errorf("fetch error should fail open; reason=%q", v.Reason)
	}
	found := false
	for _, w := range v.Warnings {
		if strings.Contains(w, "fetch error") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected fetch error in warnings; got %v", v.Warnings)
	}
}

func TestDomains_Warnings_EmptyBody(t *testing.T) {
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Write nothing — empty body.
	}))
	defer empty.Close()

	v := Inspect(context.Background(), empty.URL, Config{
		APIKey:           "fake-key",
		HTTP:             empty.Client(),
		DisableSSRFCheck: true,
	})
	if !v.Allow {
		t.Errorf("empty body should fail open; reason=%q", v.Reason)
	}
	found := false
	for _, w := range v.Warnings {
		if strings.Contains(w, "empty body") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected empty-body warning; got %v", v.Warnings)
	}
}

func TestDomains_Warnings_InconclusiveLLMVerdict(t *testing.T) {
	weird := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"MAYBE: not sure"}]}`))
	}))
	defer weird.Close()

	page := pageSrv(t, "text/html", "<html><body>content</body></html>")
	defer page.Close()

	v := Inspect(context.Background(), page.URL, Config{
		APIKey:           "fake-key",
		AnthropicURL:     weird.URL,
		HTTP:             page.Client(),
		DisableSSRFCheck: true,
	})
	if !v.Allow {
		t.Errorf("inconclusive verdict should fail open; reason=%q", v.Reason)
	}
	found := false
	for _, w := range v.Warnings {
		if strings.Contains(w, "inconclusive") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected inconclusive warning; got %v", v.Warnings)
	}
}

// --- SSRF redirect --------------------------------------------------------

func TestDomains_SSRFViaRedirect_Blocked(t *testing.T) {
	// The test server listens on 127.0.0.1. With the SSRF guard enabled,
	// Inspect rejects the initial URL (loopback) before any redirect is followed.
	redirectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer redirectSrv.Close()

	v := Inspect(context.Background(), redirectSrv.URL, Config{
		APIKey: "fake-key",
		HTTP:   redirectSrv.Client(),
		// SSRF check enabled (default)
	})
	if v.Allow {
		t.Errorf("loopback URL should be blocked by SSRF guard; reason=%q", v.Reason)
	}
	if !strings.Contains(v.Reason, "SSRF") {
		t.Errorf("reason should mention SSRF; got %q", v.Reason)
	}
}

func TestFetch_SSRFViaRedirect_Blocked(t *testing.T) {
	// Server redirects to the AWS metadata endpoint. checkSSRF fires inside
	// CheckRedirect before any real connection attempt to 169.254.169.254.
	redirectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer redirectSrv.Close()

	_, _, err := fetch(context.Background(), redirectSrv.URL, Config{
		HTTP:             redirectSrv.Client(),
		DisableSSRFCheck: false, // SSRF guard active on redirects
	})
	if !errors.Is(err, errSSRF) {
		t.Errorf("redirect to private IP should return errSSRF; got %v", err)
	}
}

// --- callGemini -----------------------------------------------------------

func TestCallGemini_Safe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"SAFE"}]}}],"usageMetadata":{"promptTokenCount":95,"candidatesTokenCount":1}}`))
	}))
	defer srv.Close()

	verdict, usage, err := callGemini(context.Background(), "https://example.com", "article text", "fake-key", Config{
		GeminiURL: srv.URL,
		HTTP:      srv.Client(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict != "SAFE" {
		t.Errorf("verdict = %q, want SAFE", verdict)
	}
	if usage.Model != DefaultGeminiModel {
		t.Errorf("usage.Model = %q, want %q", usage.Model, DefaultGeminiModel)
	}
	if usage.In != 95 || usage.Out != 1 {
		t.Errorf("usage tokens = %d in / %d out, want 95/1", usage.In, usage.Out)
	}
}

func TestCallGemini_Unsafe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"UNSAFE: phishing form"}]}}],"usageMetadata":{"promptTokenCount":90,"candidatesTokenCount":4}}`))
	}))
	defer srv.Close()

	verdict, _, err := callGemini(context.Background(), "https://evil.example", "steal creds", "fake-key", Config{
		GeminiURL: srv.URL,
		HTTP:      srv.Client(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict != "UNSAFE: phishing form" {
		t.Errorf("verdict = %q", verdict)
	}
}

func TestCallGemini_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"message":"quota exceeded"}}`))
	}))
	defer srv.Close()

	_, _, err := callGemini(context.Background(), "https://example.com", "content", "fake-key", Config{
		GeminiURL: srv.URL,
		HTTP:      srv.Client(),
	})
	if err == nil {
		t.Error("expected error for non-200 response")
	}
}

func TestCallGemini_EmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"candidates":[]}`))
	}))
	defer srv.Close()

	_, _, err := callGemini(context.Background(), "https://example.com", "content", "fake-key", Config{
		GeminiURL: srv.URL,
		HTTP:      srv.Client(),
	})
	if err == nil {
		t.Error("expected error for empty candidates")
	}
}

// --- Reason truncation ----------------------------------------------------

func TestDomains_LongUnsafeReason_Truncated(t *testing.T) {
	longReason := strings.Repeat("x", 200)
	llm := llmSrv(t, "UNSAFE: "+longReason)
	defer llm.Close()
	page := pageSrv(t, "text/html", "<html><body>evil</body></html>")
	defer page.Close()

	v := Inspect(context.Background(), page.URL, Config{
		APIKey:           "fake-key",
		AnthropicURL:     llm.URL,
		HTTP:             page.Client(),
		DisableSSRFCheck: true,
	})
	if v.Allow {
		t.Error("expected deny for UNSAFE verdict")
	}
	if len(v.Reason) > 130 {
		t.Errorf("reason not truncated: len=%d reason=%q", len(v.Reason), v.Reason)
	}
}

// --- Non-HTTP schemes -----------------------------------------------------

func TestDomains_FTPScheme_Allowed(t *testing.T) {
	v := Inspect(context.Background(), "ftp://files.example.com/pub/readme.txt", Config{})
	if !v.Allow {
		t.Errorf("ftp scheme should be allowed (non-http fast path); reason=%q", v.Reason)
	}
}

func TestDomains_DataURI_Allowed(t *testing.T) {
	v := Inspect(context.Background(), "data:text/html,<h1>hello</h1>", Config{})
	if !v.Allow {
		t.Errorf("data URI should be allowed (non-http fast path); reason=%q", v.Reason)
	}
}
