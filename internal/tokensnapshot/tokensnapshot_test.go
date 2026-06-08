package tokensnapshot_test

import (
	"os"
	"testing"

	"github.com/RobinUS2/claude-guard/internal/tokensnapshot"
)

func TestCount_EmptyFile(t *testing.T) {
	f := t.TempDir() + "/transcript.jsonl"
	if err := os.WriteFile(f, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	if n := tokensnapshot.Count(f); n != 0 {
		t.Fatalf("empty file: want 0, got %d", n)
	}
}

func TestCount_NonZero(t *testing.T) {
	f := t.TempDir() + "/transcript.jsonl"
	// 100+ bytes → expect roughly 20 tokens (bytes/5)
	content := `{"role":"user","content":"hello world this is a test message for counting"}` + "\n" +
		`{"role":"assistant","content":"acknowledged"}` + "\n"
	if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	n := tokensnapshot.Count(f)
	if n < 10 || n > 50 {
		t.Fatalf("want roughly 20 tokens, got %d (file: %d bytes)", n, len(content))
	}
}

func TestCount_MissingFile(t *testing.T) {
	if n := tokensnapshot.Count("/nonexistent/path/transcript.jsonl"); n != 0 {
		t.Fatalf("missing file: want 0, got %d", n)
	}
}

func TestCount_EmptyPath(t *testing.T) {
	if n := tokensnapshot.Count(""); n != 0 {
		t.Fatalf("empty path: want 0, got %d", n)
	}
}
