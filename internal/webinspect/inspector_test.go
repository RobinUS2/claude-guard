package webinspect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- isTextContent -------------------------------------------------------

func TestIsTextContent(t *testing.T) {
	tests := []struct {
		ct   string
		want bool
	}{
		{"text/html; charset=utf-8", true},
		{"text/plain", true},
		{"application/json", true},
		{"application/xml", true},
		{"application/xhtml+xml", true},
		{"image/png", false},
		{"application/zip", false},
		{"application/octet-stream", false},
		{"", true}, // unknown → permissive
	}
	for _, tc := range tests {
		if got := isTextContent(tc.ct); got != tc.want {
			t.Errorf("isTextContent(%q) = %v, want %v", tc.ct, got, tc.want)
		}
	}
}

// --- fetch ---------------------------------------------------------------

func TestFetch_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Chrome headers are present.
		if r.Header.Get("User-Agent") == "" {
			t.Error("User-Agent header missing")
		}
		if r.Header.Get("Sec-Fetch-Mode") != "navigate" {
			t.Errorf("Sec-Fetch-Mode = %q, want navigate", r.Header.Get("Sec-Fetch-Mode"))
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>hello</body></html>"))
	}))
	defer srv.Close()

	body, ct, err := fetch(context.Background(), srv.URL, Config{HTTP: srv.Client(), DisableSSRFCheck: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if body == "" {
		t.Error("expected non-empty body")
	}
	if ct != "text/html" {
		t.Errorf("content-type = %q, want text/html", ct)
	}
}

func TestFetch_NonHTTP(t *testing.T) {
	v := Inspect(context.Background(), "ftp://example.com/file", Config{})
	if !v.Allow {
		t.Errorf("expected allow for non-http url, got reason: %s", v.Reason)
	}
}

func TestFetch_Non2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	body, _, err := fetch(context.Background(), srv.URL, Config{HTTP: srv.Client(), DisableSSRFCheck: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if body != "" {
		t.Errorf("expected empty body for 404, got %q", body)
	}
}

func TestFetch_BodyCap(t *testing.T) {
	const big = 100_000
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		for i := 0; i < big; i++ {
			_, _ = w.Write([]byte("x"))
		}
	}))
	defer srv.Close()

	body, _, err := fetch(context.Background(), srv.URL, Config{
		HTTP:             srv.Client(),
		MaxBodyBytes:     100,
		DisableSSRFCheck: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if int64(len(body)) > 100 {
		t.Errorf("body not capped: got %d bytes", len(body))
	}
}

// --- callHaiku -----------------------------------------------------------

func TestCallHaiku_Safe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"SAFE"}]}`))
	}))
	defer srv.Close()

	verdict, err := callHaiku(context.Background(), "https://example.com", "hello world", "fake-key", Config{
		AnthropicURL: srv.URL,
		HTTP:         srv.Client(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict != "SAFE" {
		t.Errorf("verdict = %q, want SAFE", verdict)
	}
}

func TestCallHaiku_Unsafe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"UNSAFE: phishing login form"}]}`))
	}))
	defer srv.Close()

	verdict, err := callHaiku(context.Background(), "https://evil.example", "steal creds", "fake-key", Config{
		AnthropicURL: srv.URL,
		HTTP:         srv.Client(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict != "UNSAFE: phishing login form" {
		t.Errorf("verdict = %q", verdict)
	}
}

func TestCallHaiku_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()

	_, err := callHaiku(context.Background(), "https://example.com", "content", "fake-key", Config{
		AnthropicURL: srv.URL,
		HTTP:         srv.Client(),
	})
	if err == nil {
		t.Error("expected error for 500 response")
	}
}

// --- Inspect (integration of fetch + haiku) ------------------------------

func TestInspect_FullPipeline_Safe(t *testing.T) {
	// Fake Haiku says SAFE.
	haikuSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"SAFE"}]}`))
	}))
	defer haikuSrv.Close()

	// Target page.
	pageSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>normal docs page</html>"))
	}))
	defer pageSrv.Close()

	v := Inspect(context.Background(), pageSrv.URL, Config{
		APIKey:           "fake-key",
		AnthropicURL:     haikuSrv.URL,
		HTTP:             pageSrv.Client(),
		DisableSSRFCheck: true,
	})
	if !v.Allow {
		t.Errorf("expected allow, got deny: %s", v.Reason)
	}
}

func TestInspect_FullPipeline_Unsafe(t *testing.T) {
	haikuSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"UNSAFE: credential harvesting"}]}`))
	}))
	defer haikuSrv.Close()

	pageSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<form>enter password:</form>"))
	}))
	defer pageSrv.Close()

	v := Inspect(context.Background(), pageSrv.URL, Config{
		APIKey:           "fake-key",
		AnthropicURL:     haikuSrv.URL,
		HTTP:             pageSrv.Client(),
		DisableSSRFCheck: true,
	})
	if v.Allow {
		t.Errorf("expected deny, got allow: %s", v.Reason)
	}
	if v.Reason == "" {
		t.Error("expected non-empty reason")
	}
}

func TestInspect_FailOpen_NoAPIKey(t *testing.T) {
	pageSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("some content"))
	}))
	defer pageSrv.Close()

	v := Inspect(context.Background(), pageSrv.URL, Config{
		APIKey:           "", // no key → fail open
		HTTP:             pageSrv.Client(),
		DisableSSRFCheck: true,
	})
	if !v.Allow {
		t.Errorf("expected fail-open allow with no API key, got: %s", v.Reason)
	}
}

func TestInspect_FailOpen_BinaryContent(t *testing.T) {
	pageSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("\x89PNG binary data"))
	}))
	defer pageSrv.Close()

	v := Inspect(context.Background(), pageSrv.URL, Config{
		APIKey:           "fake-key",
		HTTP:             pageSrv.Client(),
		DisableSSRFCheck: true,
	})
	if !v.Allow {
		t.Errorf("expected allow for binary content-type, got: %s", v.Reason)
	}
}

// --- SSRF guard -----------------------------------------------------------

func TestCheckSSRF_BlocksPrivateIPs(t *testing.T) {
	blocked := []string{
		"http://127.0.0.1/",
		"http://127.0.0.1:8080/path",
		"http://10.0.0.1/",
		"http://10.255.255.255/",
		"http://192.168.1.100/",
		"http://172.16.0.1/",
		"http://172.31.255.254/",
		"http://169.254.169.254/latest/meta-data/",    // AWS metadata
		"http://169.254.169.254/computeMetadata/v1/",  // GCP metadata
		"http://[::1]/",
		"http://100.64.0.1/", // CGN
	}
	for _, u := range blocked {
		if err := checkSSRF(u); err == nil {
			t.Errorf("checkSSRF(%q) = nil, want error (private IP should be blocked)", u)
		}
	}
}

func TestCheckSSRF_AllowsPublicIPs(t *testing.T) {
	// Use literal IPs to avoid flaky DNS lookups in tests.
	allowed := []string{
		"http://1.1.1.1/",
		"http://8.8.8.8/",
		"https://1.0.0.1/",
		"https://104.21.0.1/", // Cloudflare range
	}
	for _, u := range allowed {
		if err := checkSSRF(u); err != nil {
			t.Errorf("checkSSRF(%q) = %v, want nil (public IP should be allowed)", u, err)
		}
	}
}

func TestInspect_BlocksPrivateURL(t *testing.T) {
	// Loopback URL must return Allow=false so the user sees the permission
	// prompt rather than the inspector silently pre-fetching an internal service.
	for _, u := range []string{
		"http://127.0.0.1:12345/page",
		"http://169.254.169.254/latest/meta-data/",
		"http://10.0.0.1/internal",
	} {
		v := Inspect(context.Background(), u, Config{
			APIKey: "fake-key",
			// DisableSSRFCheck intentionally NOT set
		})
		if v.Allow {
			t.Errorf("Inspect(%q).Allow = true, want false (SSRF guard should block)", u)
		}
		if !strings.Contains(v.Reason, "SSRF") {
			t.Errorf("Inspect(%q).Reason = %q, want SSRF mention", u, v.Reason)
		}
	}
}
