package stop

import (
	"testing"
	"time"
)

func TestShellContext_Run(t *testing.T) {
	sh := newShellContext(500 * time.Millisecond)
	out, err := sh.Run("echo hello")
	if err != nil {
		t.Fatal(err)
	}
	if out != "hello\n" {
		t.Errorf("got %q, want %q", out, "hello\n")
	}
}

func TestShellContext_Cached(t *testing.T) {
	sh := newShellContext(500 * time.Millisecond)
	out1, _ := sh.Run("echo same")
	out2, _ := sh.Run("echo same")
	if out1 != out2 {
		t.Error("cached results should be identical")
	}
}

func TestShellContext_Timeout(t *testing.T) {
	sh := newShellContext(50 * time.Millisecond)
	_, err := sh.Run("sleep 2")
	if err == nil {
		t.Error("expected timeout error")
	}
}
