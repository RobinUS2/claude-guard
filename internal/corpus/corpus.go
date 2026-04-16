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
