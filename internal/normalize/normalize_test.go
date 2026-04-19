package normalize

import (
	"strings"
	"testing"
)

// --- Validators: tight by design; test edges ---

func TestValidateDomain(t *testing.T) {
	ok := []string{
		"example.com", "foo.bar.nl", "sub-domain.example.io", "a.b.c.dev",
		"EXAMPLE.COM", // case-insensitive via (?i)
	}
	bad := []string{
		"", ".", "com", "example", "-foo.com", "foo-.com",
		"http://example.com",              // scheme
		"/tmp/example.com",                // path
		"example.com:8080",                // port
		"example.com with space",          // whitespace
		"1.2.3.4",                         // IPv4 should not pass as domain (no TLD letters)
		"example..com",                    // double dot
		strings.Repeat("a.", 130) + "com", // too long
	}
	for _, s := range ok {
		if !validateDomain(s) {
			t.Errorf("validateDomain(%q) = false, want true", s)
		}
	}
	for _, s := range bad {
		if validateDomain(s) {
			t.Errorf("validateDomain(%q) = true, want false", s)
		}
	}
}

func TestValidateIPv4(t *testing.T) {
	ok := []string{"1.2.3.4", "127.0.0.1", "10.0.0.0", "255.255.255.255"}
	bad := []string{"", "1.2.3", "1.2.3.4.5", "256.0.0.1", "01.02.03.04", "a.b.c.d", "1.2.3.4:80"}
	for _, s := range ok {
		if !validateIPv4(s) {
			t.Errorf("validateIPv4(%q) = false, want true", s)
		}
	}
	for _, s := range bad {
		if validateIPv4(s) {
			t.Errorf("validateIPv4(%q) = true, want false", s)
		}
	}
}

func TestValidateUUID(t *testing.T) {
	if !validateUUID("550e8400-e29b-41d4-a716-446655440000") {
		t.Error("lowercase uuid rejected")
	}
	if !validateUUID("550E8400-E29B-41D4-A716-446655440000") {
		t.Error("uppercase uuid rejected")
	}
	if validateUUID("not-a-uuid") {
		t.Error("non-uuid accepted")
	}
	if validateUUID("550e8400-e29b-41d4-a716-44665544") {
		t.Error("truncated uuid accepted")
	}
}

func TestValidateInteger(t *testing.T) {
	ok := []string{"0", "1", "42", "-5", "123456789"}
	bad := []string{"", "1.5", "1e10", "abc", "0x1f"}
	for _, s := range ok {
		if !validateInteger(s) {
			t.Errorf("validateInteger(%q) = false", s)
		}
	}
	for _, s := range bad {
		if validateInteger(s) {
			t.Errorf("validateInteger(%q) = true", s)
		}
	}
}

func TestValidateHexHash(t *testing.T) {
	if !validateHexHash("abc12345") {
		t.Error("8-hex rejected")
	}
	if !validateHexHash("ABCDEF1234567890") {
		t.Error("uppercase hex rejected")
	}
	if validateHexHash("abc123") {
		t.Error("7-char hex accepted (min 8)")
	}
	if validateHexHash("ghijk123456789") {
		t.Error("non-hex letters accepted")
	}
}

func TestValidateURLPathSegment(t *testing.T) {
	ok := []string{"foo", "user-123", "a.b.c", "~user"}
	bad := []string{"", "foo/bar", "foo bar", "foo?query", "foo#frag", "foo/"}
	for _, s := range ok {
		if !validateURLPathSegment(s) {
			t.Errorf("validateURLPathSegment(%q) = false", s)
		}
	}
	for _, s := range bad {
		if validateURLPathSegment(s) {
			t.Errorf("validateURLPathSegment(%q) = true", s)
		}
	}
}

func TestValidateFilepathTmp_RejectsTraversal(t *testing.T) {
	// Security canary — path traversal MUST NOT pass as SlotFilepathTmp.
	bad := []string{
		"/tmp/../etc/passwd",
		"/tmp/..",
		"/tmp/foo/..",
		"/etc/passwd",
		"",
		"relative/path",
		"/tmp\x00/zero",
	}
	for _, s := range bad {
		if validateFilepathTmp(s) {
			t.Errorf("CRITICAL: validateFilepathTmp(%q) = true — path traversal bypass", s)
		}
	}
	// Accept legitimate paths.
	ok := []string{"/tmp/foo", "/tmp/a/b/c.log", "/tmp"}
	for _, s := range ok {
		if !validateFilepathTmp(s) {
			t.Errorf("validateFilepathTmp(%q) = false", s)
		}
	}
}

func TestValidateFilepathCache_RejectsTraversal(t *testing.T) {
	bad := []string{
		"/etc/passwd",
		"~/.cache/../../etc",
		"",
		"../.cache",
	}
	for _, s := range bad {
		if validateFilepathCache(s) {
			t.Errorf("CRITICAL: validateFilepathCache(%q) = true", s)
		}
	}
	ok := []string{"~/.cache/foo", "~/.cache/claude-guard/verdicts", "/Users/robin/.cache/something"}
	for _, s := range ok {
		if !validateFilepathCache(s) {
			t.Errorf("validateFilepathCache(%q) = false", s)
		}
	}
}

func TestValidateDNSRecordType(t *testing.T) {
	if !validateDNSRecordType("A") || !validateDNSRecordType("AAAA") || !validateDNSRecordType("MX") {
		t.Error("basic dns record types rejected")
	}
	if !validateDNSRecordType("a") {
		t.Error("case-insensitive match failed")
	}
	if validateDNSRecordType("FOOBAR") {
		t.Error("unknown dns type accepted")
	}
}

func TestValidateHTTPMethod(t *testing.T) {
	if !validateHTTPMethod("GET") || !validateHTTPMethod("post") {
		t.Error("basic http method rejected")
	}
	if validateHTTPMethod("JUMP") {
		t.Error("unknown http method accepted")
	}
}

// --- Normalize: happy paths ---

func TestNormalize_DigCommand(t *testing.T) {
	canonical, dropped, err := Normalize(`dig example.com A`, []Slot{
		{Position: "arg1", Type: SlotDomain},
		{Position: "arg2", Type: SlotDNSRecordType},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(dropped) > 0 {
		t.Errorf("unexpected dropped slots: %+v", dropped)
	}
	if canonical != "dig {DOMAIN} {DNS_TYPE}" {
		t.Errorf("canonical = %q", canonical)
	}
}

func TestNormalize_ThreeDigCommandsShareCanonical(t *testing.T) {
	slots := []Slot{
		{Position: "arg1", Type: SlotDomain},
		{Position: "arg2", Type: SlotDNSRecordType},
	}
	inputs := []string{
		`dig example.com A`,
		`dig foo.bar.nl NS`,
		`dig felixportaal.nl MX`,
	}
	first := ""
	for i, cmd := range inputs {
		canonical, _, err := Normalize(cmd, slots)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = canonical
			continue
		}
		if canonical != first {
			t.Errorf("input %d canonical %q differs from first %q", i, canonical, first)
		}
	}
}

func TestNormalize_IntegerSlot(t *testing.T) {
	canonical, _, err := Normalize(`head -n 42`, []Slot{
		{Position: "arg2", Type: SlotInteger},
	})
	if err != nil {
		t.Fatal(err)
	}
	if canonical != "head -n {N}" {
		t.Errorf("canonical = %q", canonical)
	}
}

// --- Normalize: slot validation rejects mismatches ---

func TestNormalize_RejectsSlotTypeMismatch(t *testing.T) {
	// LLM claims arg1 is a domain but it's actually `/etc/passwd`.
	canonical, dropped, err := Normalize(`cat /etc/passwd`, []Slot{
		{Position: "arg1", Type: SlotDomain},
	})
	if err != nil {
		t.Fatal(err)
	}
	if canonical != "" {
		t.Errorf("bad slot should not produce canonical; got %q", canonical)
	}
	if len(dropped) != 1 || dropped[0].Reason != "token failed validator" {
		t.Errorf("expected validator rejection; got %+v", dropped)
	}
}

func TestNormalize_UnknownSlotTypeDropped(t *testing.T) {
	_, dropped, _ := Normalize(`cmd arg`, []Slot{
		{Position: "arg1", Type: SlotType("made_up_type")},
	})
	if len(dropped) != 1 || dropped[0].Reason != "unknown slot type" {
		t.Errorf("unknown type should be dropped; got %+v", dropped)
	}
}

func TestNormalize_InvalidPositionDropped(t *testing.T) {
	_, dropped, _ := Normalize(`cmd foo`, []Slot{
		{Position: "arg99", Type: SlotDomain},
	})
	if len(dropped) != 1 || dropped[0].Reason != "position not found" {
		t.Errorf("out-of-range arg should be dropped; got %+v", dropped)
	}
}

func TestNormalize_PartialValidity(t *testing.T) {
	// One good slot + one bad slot → canonical uses just the good one.
	canonical, dropped, _ := Normalize(`dig example.com A`, []Slot{
		{Position: "arg1", Type: SlotDomain},
		{Position: "arg2", Type: SlotIPv4}, // `A` is not an IPv4
	})
	if canonical != "dig {DOMAIN} A" {
		t.Errorf("canonical = %q (wanted only domain replaced)", canonical)
	}
	if len(dropped) != 1 {
		t.Errorf("expected 1 dropped slot; got %d", len(dropped))
	}
}

// --- Normalize: complex commands are opted out ---

func TestNormalize_PipeCommandNotCanonicalized(t *testing.T) {
	canonical, _, _ := Normalize(`cat /etc/hosts | grep foo`, []Slot{
		{Position: "arg1", Type: SlotDomain},
	})
	if canonical != "" {
		t.Errorf("piped command should not canonicalize; got %q", canonical)
	}
}

func TestNormalize_CompoundCommandNotCanonicalized(t *testing.T) {
	canonical, _, _ := Normalize(`cd /tmp && ls`, []Slot{
		{Position: "arg1", Type: SlotFilepathTmp},
	})
	if canonical != "" {
		t.Errorf("compound command should not canonicalize; got %q", canonical)
	}
}

// --- Normalize: MaxSlots cap ---

func TestNormalize_CapsAtMaxSlots(t *testing.T) {
	// 30 slots provided; only first 20 considered.
	slots := make([]Slot, 30)
	for i := range slots {
		slots[i] = Slot{Position: "arg1", Type: SlotDomain}
	}
	_, dropped, _ := Normalize(`cmd example.com`, slots)
	overflow := 0
	for _, d := range dropped {
		if d.Reason == "exceeds MaxSlots cap" {
			overflow++
		}
	}
	if overflow != 10 {
		t.Errorf("expected 10 cap-exceeded drops; got %d", overflow)
	}
}

// --- Normalize: zero slots → nothing to do ---

func TestNormalize_NoSlots(t *testing.T) {
	canonical, _, err := Normalize(`ls`, nil)
	if err != nil || canonical != "" {
		t.Errorf("no slots should return empty canonical; got %q err=%v", canonical, err)
	}
}

// --- CanonicalMatches: lookup side ---

func TestCanonicalMatches_Dig(t *testing.T) {
	canonical := "dig {DOMAIN} {DNS_TYPE}"
	ok := []string{
		`dig example.com A`,
		`dig foo.bar.nl NS`,
		`dig felixportaal.nl MX`,
	}
	for _, cmd := range ok {
		if !CanonicalMatches(canonical, cmd) {
			t.Errorf("canonical should match %q", cmd)
		}
	}

	// Arg count / program / token mismatches must not match.
	bad := []string{
		`dig example.com`,         // fewer args
		`dig example.com A extra`, // more args
		`whois example.com A`,     // different program
		`dig /etc/passwd A`,       // first arg not a domain
		`dig example.com FOOBAR`,  // second arg not a DNS type
	}
	for _, cmd := range bad {
		if CanonicalMatches(canonical, cmd) {
			t.Errorf("canonical should NOT match %q", cmd)
		}
	}
}

func TestCanonicalMatches_UnsupportedShapes(t *testing.T) {
	// Pipes / subshells / etc. in either side → no match.
	if CanonicalMatches(`dig {DOMAIN} | head -20`, `dig example.com | head -20`) {
		t.Error("piped canonical should not match")
	}
	if CanonicalMatches(`dig {DOMAIN}`, `dig example.com | head -5`) {
		t.Error("simple canonical should not match a piped command")
	}
}

func TestFirstProgram(t *testing.T) {
	cases := map[string]string{
		`git status`:       "git",
		`/bin/rm -rf /tmp`: "/bin/rm",
		``:                 "",
		`echo hi | cat`:    "echo",
	}
	for input, want := range cases {
		if got := FirstProgram(input); got != want {
			t.Errorf("FirstProgram(%q) = %q, want %q", input, got, want)
		}
	}
}

// --- C2 regression: substitute by AST position, NOT string value ---

func TestNormalize_DoesNotReplaceTokenElsewhere(t *testing.T) {
	// If a token value ALSO appears outside its slot position (program
	// path, another arg, inside a flag name), only the slot-identified
	// position should be substituted. The pre-fix implementation used
	// strings.NewReplacer and corrupted all occurrences.
	canonical, dropped, _ := Normalize(`dig 42 foo 42 bar`, []Slot{
		{Position: "arg1", Type: SlotInteger},
	})
	if len(dropped) != 0 {
		t.Errorf("unexpected drops: %+v", dropped)
	}
	want := `dig {N} foo 42 bar`
	if canonical != want {
		t.Errorf("canonical = %q, want %q", canonical, want)
	}
}

func TestNormalize_PreservesProgramPath(t *testing.T) {
	// Program path is NEVER substituted, even if it matches a slot type.
	canonical, _, _ := Normalize(`dig example.com A`, []Slot{
		{Position: "arg1", Type: SlotDomain},
		{Position: "arg2", Type: SlotDNSRecordType},
	})
	if !strings.HasPrefix(canonical, "dig ") {
		t.Errorf("program should be preserved; canonical=%q", canonical)
	}
	if canonical != "dig {DOMAIN} {DNS_TYPE}" {
		t.Errorf("canonical = %q", canonical)
	}
}

func TestNormalize_DuplicateTokenOnlyHits_ExactPosition(t *testing.T) {
	// `foo example.com example.com` with arg1=domain → only FIRST is
	// replaced. The duplicate value at arg2 is preserved as a literal.
	canonical, _, _ := Normalize(`foo example.com example.com`, []Slot{
		{Position: "arg1", Type: SlotDomain},
	})
	want := `foo {DOMAIN} example.com`
	if canonical != want {
		t.Errorf("canonical = %q, want %q (second occurrence must NOT be substituted)", canonical, want)
	}
}

// --- Security canary: path traversal + shell metacharacter injection ---

func TestNormalize_PathTraversalInSlot_Rejected(t *testing.T) {
	// LLM claims /tmp/../etc/passwd is a valid SlotFilepathTmp.
	// Validator must reject.
	canonical, dropped, _ := Normalize(`cat /tmp/../etc/passwd`, []Slot{
		{Position: "arg1", Type: SlotFilepathTmp},
	})
	if canonical != "" {
		t.Errorf("traversal path must be rejected; canonical=%q", canonical)
	}
	if len(dropped) != 1 {
		t.Errorf("expected traversal to be dropped; got %+v", dropped)
	}
}
