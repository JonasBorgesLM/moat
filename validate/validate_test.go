package validate_test

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/moat/validate"
)

func TestRules(t *testing.T) {
	tests := []struct {
		name    string
		rule    validate.Rule
		value   string
		wantErr bool
	}{
		// Required
		{"required accepts text", validate.Required(), "alice", false},
		{"required rejects empty", validate.Required(), "", true},
		{"required rejects spaces", validate.Required(), "   ", true},
		{"required rejects a tab", validate.Required(), "\t", true},
		{"required rejects a non-breaking space", validate.Required(), " ", true},
		{"required rejects an ideographic space", validate.Required(), "　", true},

		// MinLen / MaxLen, counted in runes
		{"minlen accepts an equal length", validate.MinLen(3), "abc", false},
		{"minlen rejects a shorter value", validate.MinLen(3), "ab", true},
		{"minlen rejects empty", validate.MinLen(1), "", true},
		{"minlen counts runes not bytes", validate.MinLen(3), "世界人", false},
		{"maxlen accepts an equal length", validate.MaxLen(3), "abc", false},
		{"maxlen rejects a longer value", validate.MaxLen(3), "abcd", true},
		{"maxlen counts runes not bytes", validate.MaxLen(3), "世界人", false},
		{"maxlen rejects by rune count", validate.MaxLen(2), "世界人", true},
		{"maxlen accepts empty", validate.MaxLen(3), "", false},
		{"maxlen counts each invalid byte as one rune", validate.MaxLen(3), "\xff\xff\xff\xff", true},

		// Email: accepted
		{"email accepts a plain address", validate.Email(), "ada@example.com", false},
		{"email accepts subdomains", validate.Email(), "ada@mail.example.co.uk", false},
		{"email accepts plus addressing", validate.Email(), "ada+tag@example.com", false},
		{"email accepts a hyphenated domain", validate.Email(), "ada@ex-ample.com", false},

		// Email: rejected
		{"email rejects empty", validate.Email(), "", true},
		{"email rejects a bare word", validate.Email(), "notanemail", true},
		{"email rejects a missing domain", validate.Email(), "ada@", true},
		{"email rejects a missing local part", validate.Email(), "@example.com", true},
		{"email rejects a display name", validate.Email(), "Ada <ada@example.com>", true},
		{"email rejects a list", validate.Email(), "a@example.com, b@example.com", true},
		{"email rejects a domain literal", validate.Email(), "ada@[203.0.113.9]", true},
		{"email rejects a dotless domain", validate.Email(), "ada@localhost", true},
		{"email rejects a leading dot in the domain", validate.Email(), "ada@.example.com", true},
		{"email rejects a trailing dot in the domain", validate.Email(), "ada@example.com.", true},
		{"email rejects consecutive dots in the domain", validate.Email(), "ada@example..com", true},
		{"email rejects surrounding whitespace", validate.Email(), " ada@example.com ", true},
		{"email rejects a comment", validate.Email(), "ada(work)@example.com", true},
		{"email rejects an overlong address", validate.Email(), strings.Repeat("a", 250) + "@example.com", true},
		{"email rejects an overlong local part", validate.Email(), strings.Repeat("a", 65) + "@example.com", true},
		// SMTP header injection: a newline in an address that reaches a mail
		// header lets the sender add headers of their own.
		{"email rejects an embedded newline", validate.Email(), "ada@example.com\nBcc: victim@example.org", true},
		{"email rejects an embedded carriage return", validate.Email(), "ada@example.com\r\nBcc: victim@example.org", true},
		{"email rejects a NUL byte", validate.Email(), "ada@example.com\x00", true},

		// OneOf: the allow-list rule
		{"oneof accepts a listed value", validate.OneOf("asc", "desc"), "asc", false},
		{"oneof rejects an unlisted value", validate.OneOf("asc", "desc"), "ASC", true},
		{"oneof rejects empty", validate.OneOf("asc", "desc"), "", true},
		{"oneof rejects an injection attempt", validate.OneOf("asc", "desc"), "asc; DROP TABLE users", true},
		{"an empty allow-list rejects everything", validate.OneOf(), "anything", true},

		// NoHTMLTags
		{"nohtmltags accepts plain text", validate.NoHTMLTags(), "Ada Lovelace", false},
		{"nohtmltags accepts an ampersand", validate.NoHTMLTags(), "Tom & Jerry", false},
		{"nohtmltags rejects a script tag", validate.NoHTMLTags(), "<script>alert(1)</script>", true},
		{"nohtmltags rejects a lone open bracket", validate.NoHTMLTags(), "a < b", true},
		{"nohtmltags rejects a lone close bracket", validate.NoHTMLTags(), "a > b", true},
		{"nohtmltags rejects a malformed tag", validate.NoHTMLTags(), "<img src=x onerror=alert(1)", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.rule("field", tc.value)
			if (err != nil) != tc.wantErr {
				t.Fatalf("rule(%q) error = %v, wantErr = %v", tc.value, err, tc.wantErr)
			}
			if err == nil {
				return
			}
			var ve *validate.Error
			if !errors.As(err, &ve) {
				t.Fatalf("error is %T, want *validate.Error", err)
			}
			if ve.Field != "field" {
				t.Errorf("Field = %q, want %q", ve.Field, "field")
			}
			// The rejected value must never be echoed back: an error carrying
			// attacker-controlled text is a reflection primitive.
			if tc.value != "" && strings.Contains(ve.Message, tc.value) {
				t.Errorf("message %q contains the rejected value; errors must not echo input", ve.Message)
			}
		})
	}
}

// TestMatches covers the anchoring trap that turns an allow-list pattern into
// an allow-everything pattern.
func TestMatches(t *testing.T) {
	anchored := regexp.MustCompile(`\A[a-z0-9-]+\z`)
	unanchored := regexp.MustCompile(`[a-z0-9-]+`)

	tests := []struct {
		name    string
		rule    validate.Rule
		value   string
		wantErr bool
	}{
		{"anchored accepts a matching value", validate.Matches(anchored, "must be a slug"), "my-post-1", false},
		{"anchored rejects a prefix match", validate.Matches(anchored, "must be a slug"), "my-post<script>", true},
		{"anchored rejects a leading newline", validate.Matches(anchored, "must be a slug"), "\nmy-post", true},
		{"anchored rejects empty", validate.Matches(anchored, "must be a slug"), "", true},
		// Documented failure mode, asserted so the warning in the doc is real.
		{"an unanchored pattern accepts anything containing a match", validate.Matches(unanchored, "must be a slug"), "<script>a</script>", false},
		{"a nil pattern rejects everything", validate.Matches(nil, "must be a slug"), "anything", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.rule("slug", tc.value); (err != nil) != tc.wantErr {
				t.Errorf("error = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

// TestMatchesUsesTheGivenMessage checks that the pattern itself is not leaked
// into the message, which would tell an attacker exactly what shape to aim for.
func TestMatchesMessage(t *testing.T) {
	re := regexp.MustCompile(`\A[a-z]+\z`)

	err := validate.Matches(re, "must contain only lowercase letters")("slug", "NOPE")
	if err == nil {
		t.Fatal("expected an error")
	}
	if got, want := err.Error(), "slug: must contain only lowercase letters"; got != want {
		t.Errorf("error = %q, want %q", got, want)
	}

	// An empty message falls back to something usable rather than an empty one.
	err = validate.Matches(re, "")("slug", "NOPE")
	if err == nil || !strings.Contains(err.Error(), "required format") {
		t.Errorf("error = %v, want a usable fallback message", err)
	}
}

func TestValidateShortCircuits(t *testing.T) {
	ran := 0
	counting := func(fail bool) validate.Rule {
		return func(field, value string) error {
			ran++
			if fail {
				return fmt.Errorf("boom")
			}
			return nil
		}
	}

	tests := []struct {
		name    string
		rules   []validate.Rule
		wantRan int
		wantErr bool
	}{
		{"no rules always passes", nil, 0, false},
		{"all rules run when all pass", []validate.Rule{counting(false), counting(false)}, 2, false},
		{"evaluation stops at the first failure", []validate.Rule{counting(false), counting(true), counting(false)}, 2, true},
		{"a nil rule is skipped", []validate.Rule{nil, counting(false)}, 1, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ran = 0
			err := validate.Validate("f", "v", tc.rules...)
			if (err != nil) != tc.wantErr {
				t.Errorf("error = %v, wantErr = %v", err, tc.wantErr)
			}
			if ran != tc.wantRan {
				t.Errorf("ran %d rules, want %d", ran, tc.wantRan)
			}
		})
	}
}

// TestValidateReportsTheFirstFailure confirms the message a user sees is the
// most fundamental one, which is why rule order is documented as significant.
func TestValidateReportsTheFirstFailure(t *testing.T) {
	err := validate.Validate("email", "",
		validate.Required(),
		validate.Email(),
	)
	if err == nil {
		t.Fatal("expected an error")
	}
	if got, want := err.Error(), "email: is required"; got != want {
		t.Errorf("error = %q, want %q", got, want)
	}
}

// TestRulesDoNotSkipEmptyValues pins the documented decision: an implicit skip
// on empty input is a validation bypass that looks like working code.
func TestRulesDoNotSkipEmptyValues(t *testing.T) {
	rules := map[string]validate.Rule{
		"MinLen":  validate.MinLen(1),
		"Email":   validate.Email(),
		"OneOf":   validate.OneOf("a"),
		"Matches": validate.Matches(regexp.MustCompile(`\Aa\z`), "must be a"),
	}
	for name, rule := range rules {
		if err := rule("f", ""); err == nil {
			t.Errorf("%s silently accepted an empty value", name)
		}
	}
}

func TestErrorType(t *testing.T) {
	tests := []struct {
		name string
		err  *validate.Error
		want string
	}{
		{"with a field", &validate.Error{Field: "email", Message: "is required"}, "email: is required"},
		{"without a field", &validate.Error{Message: "is required"}, "is required"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.want {
				t.Errorf("Error() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestRulesDoNotPanicOnHostileInput: rules run on data an attacker chose, so
// none of them may panic on any input, valid UTF-8 or not.
func TestRulesDoNotPanicOnHostileInput(t *testing.T) {
	values := []string{
		"", "\x00", "\xff\xfe\xfd", strings.Repeat("a", 1<<16),
		"\xed\xa0\x80", "\U0001F600", "@@@", "a@@b", "@", "<", ">",
	}
	rules := []validate.Rule{
		validate.Required(), validate.MinLen(3), validate.MaxLen(3),
		validate.Email(), validate.OneOf("x"), validate.NoHTMLTags(),
		validate.Matches(regexp.MustCompile(`\A.*\z`), "any"),
	}
	for _, v := range values {
		for i, rule := range rules {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("rule %d panicked on %q: %v", i, v, r)
					}
				}()
				_ = rule("f", v)
			}()
		}
	}
}

// FuzzRules asserts no rule panics and that the accept/reject decision is
// stable, for arbitrary input.
func FuzzRules(f *testing.F) {
	for _, seed := range []string{
		"", "ada@example.com", "<script>", "\xff", strings.Repeat("x", 300), "a@b.c",
		"https://example.com", "javascript:alert(1)", "java\tscript:alert(1)",
		"//evil.example.com", "data:text/html,x", "HTTPS://EXAMPLE.COM", "https:",
	} {
		f.Add(seed)
	}
	rules := []validate.Rule{
		validate.Required(), validate.MinLen(3), validate.MaxLen(64),
		validate.Email(), validate.OneOf("asc", "desc"), validate.NoHTMLTags(),
		validate.Matches(regexp.MustCompile(`\A[a-z]+\z`), "lowercase only"),
		validate.URL(),
	}
	f.Fuzz(func(t *testing.T, s string) {
		for i, rule := range rules {
			err := rule("field", s)
			if err == nil {
				continue
			}
			var ve *validate.Error
			if !errors.As(err, &ve) {
				t.Fatalf("rule %d returned %T, want *validate.Error", i, err)
			}
			if ve.Field != "field" {
				t.Fatalf("rule %d: Field = %q, want %q", i, ve.Field, "field")
			}
			if again := rule("field", s); (again == nil) != (err == nil) {
				t.Fatalf("rule %d is not deterministic for %q", i, s)
			}
		}
		// NoHTMLTags must never accept a value containing an angle bracket,
		// whatever encoding tricks the rest of the input uses.
		if strings.ContainsAny(s, "<>") && validate.NoHTMLTags()("f", s) == nil {
			t.Fatalf("NoHTMLTags accepted %q", s)
		}

		// URL must never accept a value a browser would treat as a
		// script-bearing scheme. The browser strips these characters before
		// parsing, so the comparison is made against the stripped form -- which
		// is exactly the transformation an allow-list on the parsed scheme
		// misses.
		if validate.URL()("f", s) == nil {
			stripped := strings.Map(func(r rune) rune {
				if r == '\t' || r == '\n' || r == '\r' {
					return -1
				}
				return r
			}, s)
			lower := strings.ToLower(stripped)
			for _, bad := range []string{"javascript:", "data:", "vbscript:", "file:"} {
				if strings.HasPrefix(lower, bad) {
					t.Fatalf("URL accepted %q, which a browser reads as %q", s, bad)
				}
			}
			if strings.HasPrefix(stripped, "//") {
				t.Fatalf("URL accepted the scheme-relative value %q", s)
			}
		}
	})
}

func ExampleValidate() {
	err := validate.Validate("email", "not-an-email",
		validate.Required(),
		validate.MaxLen(254),
		validate.Email(),
	)
	fmt.Println(err)
	// Output: email: must be a valid email address
}

func ExampleOneOf() {
	// An allow-list is the strongest rule available: there is nothing left to
	// bypass, whatever the value contains.
	err := validate.Validate("sort", "asc; DROP TABLE users", validate.OneOf("asc", "desc"))
	fmt.Println(err)
	// Output: sort: must be one of: asc, desc
}

func ExampleNoHTMLTags() {
	// An input-shape constraint, not an XSS defense: reject markup in a field
	// that should never contain any, and encode on output regardless.
	err := validate.Validate("name", "<script>alert(1)</script>", validate.NoHTMLTags())
	fmt.Println(err)
	// Output: name: must not contain < or >
}

func ExampleMatches() {
	// Anchor the pattern. Without \A and \z this would accept any value that
	// merely contains a slug somewhere inside it.
	slug := regexp.MustCompile(`\A[a-z0-9]+(-[a-z0-9]+)*\z`)

	fmt.Println(validate.Validate("slug", "hello-world", validate.Matches(slug, "must be a slug")))
	fmt.Println(validate.Validate("slug", "hello world!", validate.Matches(slug, "must be a slug")))
	// Output:
	// <nil>
	// slug: must be a slug
}

func TestURL(t *testing.T) {
	tests := []struct {
		name    string
		schemes []string
		value   string
		wantOK  bool
	}{
		{name: "https is allowed", value: "https://example.com/path?q=1#f", wantOK: true},
		{name: "http is allowed", value: "http://example.com", wantOK: true},
		{name: "a port and credentials still parse", value: "https://u:p@example.com:8443/x", wantOK: true}, // #nosec G101 -- fixture URL; the userinfo is the shape under test, not a credential.
		{name: "an IPv6 host parses", value: "https://[2001:db8::1]:8443/x", wantOK: true},
		{name: "uppercase scheme is allowed", value: "HTTPS://example.com", wantOK: true},

		// The two the rule exists for.
		{name: "javascript is rejected", value: "javascript:alert(1)"},
		{name: "javascript with mixed case is rejected", value: "JaVaScRiPt:alert(1)"},
		{name: "data is rejected", value: "data:text/html,<script>alert(1)</script>"},
		{name: "data base64 is rejected", value: "data:text/html;base64,PHNjcmlwdD4="},
		{name: "vbscript is rejected", value: "vbscript:msgbox(1)"},
		{name: "file is rejected", value: "file:///etc/passwd"},

		// The control-character bypass: a browser strips these and navigates as
		// javascript:, while net/url sees something else entirely.
		{name: "tab inside the scheme is rejected", value: "java\tscript:alert(1)"},
		{name: "newline inside the scheme is rejected", value: "java\nscript:alert(1)"},
		{name: "carriage return inside the scheme is rejected", value: "java\rscript:alert(1)"},
		{name: "NUL inside the scheme is rejected", value: "java\x00script:alert(1)"},
		{name: "a leading space is rejected", value: " https://example.com"},
		{name: "a leading newline is rejected", value: "\nhttps://example.com"},
		{name: "DEL is rejected", value: "https://example.com/\x7f"},

		// Open redirect shapes.
		{name: "scheme-relative is rejected", value: "//evil.example.com/path"},
		{name: "a backslash scheme-relative is rejected", value: "\\\\evil.example.com"},
		{name: "a relative path is rejected", value: "/dashboard"},
		{name: "a bare host is rejected", value: "example.com"},

		{name: "empty is rejected", value: ""},
		{name: "a hierarchical scheme with no host is rejected", value: "https:"},
		{name: "an empty host is rejected", value: "http:///path"},

		// Explicit allow-lists.
		{name: "a custom scheme can be allowed", schemes: []string{"ftp"}, value: "ftp://files.example.com/x", wantOK: true},
		{name: "the default is replaced, not extended", schemes: []string{"ftp"}, value: "https://example.com"},
		{name: "an empty allow-list rejects everything", schemes: []string{""}, value: "https://example.com"},
		{name: "the allow-list is matched case-insensitively", schemes: []string{"HTTPS"}, value: "https://example.com", wantOK: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rule := validate.URL(tc.schemes...)
			err := rule("website", tc.value)
			if tc.wantOK && err != nil {
				t.Errorf("URL(%q) = %v, want nil", tc.value, err)
			}
			if !tc.wantOK && err == nil {
				t.Errorf("URL(%q) = nil, want an error", tc.value)
			}
		})
	}
}

// TestURLErrorDoesNotEchoTheValue: the rejected value is attacker-authored and
// the error is shown to a user, so it must not become a reflection point.
func TestURLErrorDoesNotEchoTheValue(t *testing.T) {
	const payload = "javascript:alert(document.domain)"
	err := validate.URL()("website", payload)
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), payload) || strings.Contains(err.Error(), "alert") {
		t.Errorf("the error echoed the payload: %v", err)
	}
}

func ExampleURL() {
	err := validate.Validate("website", "javascript:alert(1)",
		validate.Required(),
		validate.MaxLen(2048),
		validate.URL(),
	)
	fmt.Println(err)
	// Output: website: must be a valid URL
}
