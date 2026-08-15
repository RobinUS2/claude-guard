package rules

import (
	"testing"

	"github.com/RobinUS2/claude-guard/internal/shellparse"
)

func TestCopyOntoExecutable(t *testing.T) {
	r := &CopyOntoExecutable{
		RuleName:     "cp-over-executable-path",
		Programs:     []string{"cp"},
		DestPrefixes: []string{"$HOME/.claude/bin", "$HOME/go/bin", "/usr/local/bin"},
		Reason:       "in-place rewrite kills running processes",
	}
	cases := []struct {
		cmd  string
		want Verdict
		why  string
	}{
		// The exact command that wedged the session.
		{"cp /Users/robin/.claude/bin/claude-guard /Users/robin/go/bin/claude-guard", Match, "the incident"},
		{"cp ~/.claude/bin/claude-guard ~/go/bin/claude-guard", Match, "tilde form"},
		{"cp bin/claude-guard /usr/local/bin/claude-guard", Match, "system bin"},
		{"cp -f build/tool ~/go/bin/tool", Match, "flags do not matter"},
		{"cp a b ~/go/bin/", Match, "multi-source, dest is last"},
		{"cp -R dist/ /usr/local/bin", Match, "bare dir dest"},

		// Copying OUT of a bin dir is harmless — this is what a
		// blanket any-positional match would have wrongly blocked.
		{"cp ~/go/bin/claude-guard /tmp/backup", NoMatch, "source in bin, dest elsewhere"},
		{"cp /usr/local/bin/tool ./vendor/tool", NoMatch, "copying out"},

		// Safe verbs must stay allowed — they rename, not rewrite.
		{"install -m 755 bin/claude-guard ~/go/bin/claude-guard", NoMatch, "install is the fix"},
		{"mv bin/claude-guard ~/go/bin/claude-guard", NoMatch, "mv renames"},

		// Unrelated destinations.
		{"cp a.txt /tmp/b.txt", NoMatch, "ordinary copy"},
		{"cp a.txt ~/Documents/b.txt", NoMatch, "home but not bin"},
		// Prefix must be a path boundary, not a substring.
		{"cp a.txt ~/go/binaries/x", NoMatch, "binaries is not bin/"},
		// Malformed cp has nothing to block.
		{"cp ~/go/bin/x", NoMatch, "single positional"},
	}
	for _, tc := range cases {
		p, err := shellparse.Parse(tc.cmd)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.cmd, err)
		}
		got, _ := r.Eval(p)
		if got != tc.want {
			t.Errorf("Eval(%q) = %v, want %v (%s)", tc.cmd, got, tc.want, tc.why)
		}
	}
}
