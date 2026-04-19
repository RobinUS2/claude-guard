package shellparse

import "testing"

func TestOnlyStderrMergeRedirect(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want bool
	}{
		{"bare 2>&1", "cmd 2>&1", true},
		{"gcloud with 2>&1", "gcloud projects list 2>&1", true},
		{"file redirect then stderr merge", "cmd > /tmp/out 2>&1", false},
		{"file redirect only", "cmd > /dev/null", false},
		{"stderr to file", "cmd 2>/tmp/err", false},
		{"stdin redirect", "cmd < /etc/hosts", false},
		{"literal 2>&1 inside echo (no redirect)", `echo "2>&1"`, false},
		{"no redirect at all", "cmd", false},
		{"append redirect", "cmd >> /tmp/log", false},
		{"double 2>&1 (still only merges)", "cmd 2>&1 2>&1", true},
		{"heredoc", "cmd <<EOF\nfoo\nEOF", false},
		{"stdout to stderr", "cmd 1>&2", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Parse(tc.cmd)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.cmd, err)
			}
			got := p.OnlyStderrMergeRedirect()
			if got != tc.want {
				t.Errorf("OnlyStderrMergeRedirect(%q) = %v, want %v (features=%+v)",
					tc.cmd, got, tc.want, p.Features)
			}
		})
	}
}
