// Package corpus exposes the embedded bash_* test corpora so both the
// Go test harness (internal/engine/golden_test.go) and the `lint`
// CLI subcommand can run the same 275-case check without reading the
// filesystem. Shipping the corpus inside the binary also makes `lint`
// work correctly regardless of cwd or install location.
package corpus

import _ "embed"

//go:embed testdata/bash_allow.txt
var Allow string

//go:embed testdata/bash_deny.txt
var Deny string

//go:embed testdata/bash_continue.txt
var Continue string

//go:embed testdata/bash_adversarial.txt
var Adversarial string

//go:embed testdata/bash_ask.txt
var Ask string

// LegacyPatterns is the fixture tier-5 allow list (settings.json
// `Bash(...)` entries, one per line) used with LegacyAllow and
// LegacyNotAllow. The main corpora above run without any legacy list.
//
//go:embed testdata/legacy_patterns.txt
var LegacyPatterns string

// LegacyAllow must reach Allow via tier 5 with LegacyPatterns loaded.
//
//go:embed testdata/bash_legacy_allow.txt
var LegacyAllow string

// LegacyNotAllow must reach any verdict except Allow with LegacyPatterns
// loaded: each line starts with a listed prefix but carries more.
//
//go:embed testdata/bash_legacy_notallow.txt
var LegacyNotAllow string
