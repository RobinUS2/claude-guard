package main

import "testing"

func TestMatcherCovers(t *testing.T) {
	cases := []struct {
		matcher string
		tool    string
		want    bool
	}{
		{"Bash", "Bash", true},
		{"Bash", "Monitor", false},
		{"Bash|Monitor", "Bash", true},
		{"Bash|Monitor", "Monitor", true},
		{"Bash | Monitor", "Monitor", true},
		{"bash|monitor", "Monitor", true},
		{"Monitor", "Bash", false},
		{"", "Monitor", true},
		{"*", "Bash", true},
		{"WebFetch", "Bash", false},
	}
	for _, tc := range cases {
		if got := matcherCovers(tc.matcher, tc.tool); got != tc.want {
			t.Errorf("matcherCovers(%q, %q) = %v, want %v", tc.matcher, tc.tool, got, tc.want)
		}
	}
}
