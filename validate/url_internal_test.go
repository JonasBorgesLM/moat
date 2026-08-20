package validate

import (
	"net/url"
	"strings"
	"testing"
)

// TestHasControlOrSpace exercises the pre-check directly.
//
// It has to be tested on its own, because driving it through URL() proves
// nothing: net/url rejects most of these inputs before the pre-check's decision
// can matter, so a table test through the public rule passes identically whether
// the pre-check is present or deleted. That was true of the original test for
// this rule, and it is the reason this file exists.
func TestHasControlOrSpace(t *testing.T) {
	clean := []string{
		"https://example.com",
		"https://example.com/path?q=1#frag",
		"javascript:alert(1)", // dirty in meaning, clean in bytes
		"",
	}
	for _, s := range clean {
		if hasControlOrSpace(s) {
			t.Errorf("hasControlOrSpace(%q) = true, want false", s)
		}
	}

	// Every byte the check is meant to catch, in a position that would
	// otherwise parse.
	for b := 0; b <= 0x20; b++ {
		in := "https://example.com/x" + string(rune(b))
		if !hasControlOrSpace(in) {
			t.Errorf("hasControlOrSpace did not catch byte 0x%02x", b)
		}
	}
	if !hasControlOrSpace("https://example.com/\x7f") {
		t.Error("hasControlOrSpace did not catch DEL")
	}
}

// TestNetURLRejectsControlCharactersInScheme is a canary on the standard
// library, not a test of this package.
//
// The scheme-confusion bypass — "java\tscript:" navigating as javascript: while
// a parser sees something else — is closed today by net/url refusing to parse
// control characters in the scheme at all. This test pins that assumption. If a
// future Go loosens it, this fails, and the pre-check in URL() stops being
// defense in depth and becomes the only thing standing between a caller and the
// bypass.
func TestNetURLRejectsControlCharactersInScheme(t *testing.T) {
	for _, c := range []string{"\t", "\n", "\r", "\x00", "\x0b", "\x1f"} {
		in := "java" + c + "script:alert(1)"
		u, err := url.Parse(in)
		if err == nil {
			t.Errorf("net/url now parses %q as scheme %q; the pre-check in URL() is "+
				"now load-bearing and its doc comment must be corrected", in, u.Scheme)
		}
	}
}

// TestPreCheckRejectsWhatNetURLAccepts covers the cases where the pre-check is
// the only thing rejecting, so the guard is exercised rather than shadowed.
//
// These parse cleanly with an allowed scheme — net/url tolerates control
// characters in a fragment, and spaces in a path, query or trailing position —
// so without the pre-check URL() would accept them.
func TestPreCheckRejectsWhatNetURLAccepts(t *testing.T) {
	cases := []string{
		"https://example.com/x#frag\x00",
		"https://example.com/x#frag\n",
		"https://example.com/x#frag\x1f",
		"https://example.com/x#frag\x7f",
		"https://example.com/pa th",
		"https://example.com/x?a= 1",
		"https://example.com/x ",
	}

	rule := URL()
	for _, in := range cases {
		// Precondition: net/url really does accept it with an allowed scheme.
		u, err := url.Parse(in)
		if err != nil {
			t.Fatalf("precondition failed: net/url rejected %q (%v); pick another case", in, err)
		}
		if !strings.EqualFold(u.Scheme, "https") {
			t.Fatalf("precondition failed: %q parsed with scheme %q", in, u.Scheme)
		}
		// So the pre-check is the only thing that can reject it.
		if err := rule("website", in); err == nil {
			t.Errorf("URL() accepted %q; the control/space pre-check is not running", in)
		}
	}
}
