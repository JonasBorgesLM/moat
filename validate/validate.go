// Package validate provides composable input validation rules and HTTP request
// guards.
//
// # Reject, do not repair
//
// A rule answers one question — "is this acceptable?" — and, when the answer is
// no, returns an error naming the field. Nothing here mutates input. That
// separation is deliberate and follows OWASP's preference for allow-list
// validation over post-hoc sanitization, for two reasons:
//
//   - Silent repair hides attacks. If a filter strips something dangerous and
//     lets the request through, nothing is logged, nothing is alerted on, and
//     the attacker gets to iterate against your filter for free until they find
//     the encoding it misses. A rejection is a signal.
//   - Silent repair corrupts legitimate data. A user whose display name really
//     does contain an angle bracket deserves an error message, not a quietly
//     rewritten name they never notice.
//
// The companion sanitize package normalizes text that is *expected* to be
// plain; it is not a substitute for validation and is not an XSS defense.
//
// # Rules do not skip empty values
//
// Every rule validates exactly the value it is handed. [MinLen] fails on an
// empty string; [Email] fails on an empty string. Rules do not silently pass
// when the input is empty, because "my Email rule never actually ran" is a
// bypass that looks like working code. If a field is genuinely optional, decide
// that explicitly in your own code before calling [Validate].
//
// # Error messages
//
// Rule errors never include the offending value. An error that echoes
// attacker-controlled input back is a reflection primitive: it lands in logs,
// in error-tracking services, and often in a response body, where it becomes a
// vector for log injection or reflected XSS depending on where it is rendered.
// Messages describe the constraint, not the input.
package validate

import (
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Rule reports whether value is acceptable for the named field.
//
// A Rule returns nil when the value is acceptable and a non-nil error, normally
// an [*Error], when it is not. field is used only to build the error message;
// a Rule must not vary its decision based on it.
//
// Rules must be pure and must not panic on any input, including invalid UTF-8:
// they run on data an attacker chose.
type Rule func(field, value string) error

// Error reports that a field failed validation.
//
// It deliberately carries no copy of the rejected value. See the package
// documentation on why echoing attacker-controlled input into an error is a
// hazard rather than a convenience.
type Error struct {
	// Field is the name that was passed to [Validate].
	Field string

	// Message describes the constraint that was violated. It is safe to show to
	// the user: it is built from your own rule configuration, never from the
	// submitted value.
	Message string
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Field == "" {
		return e.Message
	}
	return e.Field + ": " + e.Message
}

// newError builds an [*Error] for the given field.
func newError(field, format string, args ...any) error {
	return &Error{Field: field, Message: fmt.Sprintf(format, args...)}
}

// Validate applies rules to value in order and returns the first error, or nil
// if every rule passes.
//
// Evaluation short-circuits, so order the rules from cheapest and most
// fundamental to most specific: [Required] first, then a length bound, then a
// format check. That also produces the most useful message, since "is required"
// beats "is not a valid email address" for an empty field.
//
// Bounding the length before running a pattern is worth doing on principle even
// though Go's regexp package is not vulnerable to catastrophic backtracking:
// it keeps the work proportional to a value you control rather than to one the
// client chose.
//
// A nil rule is skipped.
func Validate(field, value string, rules ...Rule) error {
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		if err := rule(field, value); err != nil {
			return err
		}
	}
	return nil
}

// Required rejects an empty value, and a value consisting only of whitespace.
//
// Whitespace-only counts as empty because a required field satisfied by a
// single space is satisfied in name only, and because the whitespace people use
// to do it is often not the space character — a non-breaking space or an
// ideographic space passes a naive value != "" check while looking blank.
func Required() Rule {
	return func(field, value string) error {
		if strings.TrimSpace(value) == "" {
			return newError(field, "is required")
		}
		return nil
	}
}

// MinLen rejects a value shorter than n runes.
//
// Length is counted in runes, not bytes, so a limit expressed as "at least 8
// characters" means what a user would expect for non-ASCII input. Invalid UTF-8
// bytes each count as one rune, so malformed input cannot be used to appear
// longer than it is.
func MinLen(n int) Rule {
	return func(field, value string) error {
		if utf8.RuneCountInString(value) < n {
			return newError(field, "must be at least %d characters", n)
		}
		return nil
	}
}

// MaxLen rejects a value longer than n runes.
//
// Length is counted in runes, not bytes. Counting bytes would make the limit
// depend on the alphabet, so a name in Japanese would be cut to a third of the
// length of the same limit in English — a correctness bug that reliably gets
// "fixed" by raising the limit until it stops complaining.
//
// An upper bound belongs on every free-text field that reaches storage, a log,
// or another service. It is the cheapest defense against the family of bugs
// where an unbounded value overflows a column, blows a downstream limit, or
// simply costs more to process than the request was worth.
func MaxLen(n int) Rule {
	return func(field, value string) error {
		if utf8.RuneCountInString(value) > n {
			return newError(field, "must be at most %d characters", n)
		}
		return nil
	}
}

// Email rejects a value that is not a single, plain email address.
//
// It is built on net/mail.ParseAddress — the standard library's RFC 5322
// parser — rather than a regular expression, because the grammar for an address
// is genuinely not regular and every regex people reach for is wrong in both
// directions. On top of parsing, this rule requires:
//
//   - Exactly one address. "a@example.com, b@example.com" is rejected.
//   - No display name. "Ada <ada@example.com>" is rejected; the value must be
//     the bare address, so that what you store is what you send to.
//   - Byte-for-byte agreement with the input, so a value that only becomes
//     valid after the parser normalizes it — quoted local parts, folded
//     whitespace, comments — does not slip through.
//   - No domain literal. "user@[203.0.113.9]" is rejected: it is valid RFC
//     5322, it is essentially never what a signup form meant, and it is a
//     standard way to steer mail at an address the application did not intend.
//   - A dot in the domain, so "user@localhost" is rejected.
//   - Length limits from RFC 5321: 64 bytes for the local part, 254 for the
//     whole address.
//
// This is stricter than the RFC. That is the intended trade: the cost of
// rejecting an exotic-but-legal address is an annoyed user, while the cost of
// accepting one is that it flows into a mail header, a database, and a log line.
//
// Note that ParseAddress already rejects embedded newlines, which is what stops
// this value from being used for SMTP header injection.
//
// Validating the shape of an address says nothing about whether it exists or
// belongs to whoever submitted it. Only a confirmation email establishes that.
func Email() Rule {
	return func(field, value string) error {
		const invalid = "must be a valid email address"

		if value == "" || len(value) > 254 {
			return newError(field, invalid)
		}
		addr, err := mail.ParseAddress(value)
		if err != nil || addr.Name != "" || addr.Address != value {
			return newError(field, invalid)
		}
		at := strings.LastIndexByte(value, '@')
		if at <= 0 || at > 64 || at == len(value)-1 {
			return newError(field, invalid)
		}
		domain := value[at+1:]
		if strings.HasPrefix(domain, "[") || !strings.Contains(domain, ".") {
			return newError(field, invalid)
		}
		if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") || strings.Contains(domain, "..") {
			return newError(field, invalid)
		}
		return nil
	}
}

// Matches rejects a value that does not match re, reporting message.
//
// Anchor your pattern. `regexp.MustCompile("[a-z]+")` matches any value that
// contains a lowercase run anywhere, which is almost never the constraint
// intended; `\A[a-z]+\z` is. Unanchored patterns are the single most common way
// an allow-list turns out to allow everything.
//
// Prefer describing what is allowed over describing what is forbidden. A
// block-list pattern has to anticipate every encoding of every dangerous
// construct; an allow-list only has to describe the shape you actually want.
//
// Go's regexp package uses RE2, which runs in time linear in the input and has
// no backtracking, so a pattern here cannot be turned into a CPU denial of
// service the way it can in most other languages. Bound the length anyway with
// [MaxLen], to keep the work proportional to a limit you chose.
//
// message is shown to the user, so phrase it as the requirement — "must contain
// only letters and digits" — rather than leaking the pattern, which tells an
// attacker exactly what shape to aim for.
//
// A nil re rejects every value: a rule that silently accepted everything
// because it was misconfigured would be a hole, not a convenience.
func Matches(re *regexp.Regexp, message string) Rule {
	return func(field, value string) error {
		if re == nil {
			return newError(field, "cannot be validated: no pattern configured")
		}
		if !re.MatchString(value) {
			if message == "" {
				message = "is not in the required format"
			}
			return newError(field, "%s", message)
		}
		return nil
	}
}

// OneOf rejects a value that is not exactly equal to one of allowed.
//
// This is the allow-list rule, and it is the right tool whenever the set of
// acceptable values is known: a sort direction, a status, a role, a currency.
// It is far stronger than any pattern, because there is nothing left to
// bypass — an unlisted value is rejected whatever it contains.
//
// Comparison is exact and case-sensitive. Fold the case yourself first if you
// mean to accept both, so the folding is visible rather than implied.
//
// The allowed values appear in the error message, so do not use this rule for
// secrets. Calling it with no allowed values rejects everything, which is the
// fail-closed reading of an empty allow-list.
func OneOf(allowed ...string) Rule {
	return func(field, value string) error {
		for _, a := range allowed {
			if value == a {
				return nil
			}
		}
		if len(allowed) == 0 {
			return newError(field, "has no permitted values")
		}
		return newError(field, "must be one of: %s", strings.Join(allowed, ", "))
	}
}

// NoHTMLTags rejects a value containing an angle bracket.
//
// Read the name literally and the scope narrowly. This is an input-shape
// constraint for fields that have no business containing markup — a person's
// name, a city, a product SKU — and nothing more. It is **not** an XSS defense
// and must not be treated as one:
//
//   - It does not make a value safe to render as HTML. A value with no angle
//     brackets is still dangerous inside an unquoted attribute, inside a
//     javascript: URL, or inside a <script> block.
//   - Passing this rule tells you nothing about other contexts: SQL, shell,
//     LDAP, and CSV formula injection are all unaffected.
//
// The real defense against XSS is contextual output encoding at the point of
// rendering, which html/template performs for you. Use it, and do not defeat it
// by wrapping values in template.HTML.
//
// The check is on the characters < and >, so it also rejects a value with a
// stray comparison operator. For a field where that is legitimate, this is the
// wrong rule; use [Matches] with an allow-list pattern instead.
func NoHTMLTags() Rule {
	return func(field, value string) error {
		if strings.ContainsAny(value, "<>") {
			return newError(field, "must not contain < or >")
		}
		return nil
	}
}

// DefaultURLSchemes is the allow-list [URL] uses when called with no arguments.
var DefaultURLSchemes = []string{"http", "https"}

// URL rejects a value that is not an absolute URL with a scheme in the
// allow-list. With no arguments the allow-list is [DefaultURLSchemes].
//
// # Threat
//
// A URL supplied by a user and later rendered into an href, a redirect, or an
// image source is a script-execution primitive if its scheme is not
// constrained. The two that matter:
//
//   - javascript: — clicking a link whose href is "javascript:fetch(...)" runs
//     that code in your origin, with the victim's session. html/template will
//     not save you here: it is contextual escaping, and inside an href a
//     javascript: URL is a *valid* URL, not a syntax error to escape.
//   - data: — "data:text/html,<script>..." renders attacker-authored HTML.
//     Modern browsers block top-level navigation to it, but it still reaches
//     iframes, and "should be blocked by the browser" is not an input policy.
//
// Constraining the scheme at the point of input is what makes the value safe
// for every later use, rather than relying on each rendering site to remember.
//
// # Control characters, and who actually rejects them
//
// A browser removes tab, newline and carriage return from a URL before parsing
// its scheme, so "java\tscript:alert(1)" navigates as javascript:. An
// allow-list that compares the *parsed* scheme is the standard place this gets
// through, because the parser and the browser disagree about what the scheme
// even is.
//
// On current Go that bypass is closed by net/url itself: it refuses to parse a
// URL containing an ASCII control character in the scheme, host or path, so the
// disagreement never arises and this rule rejects the value on the parse error.
// Verified exhaustively — see TestNetURLRejectsControlCharactersInScheme, which
// is a canary: if a future Go becomes lenient there, it fails and tells you the
// pre-check below has become load-bearing.
//
// The pre-check is kept anyway, for two reasons that are not hypothetical:
//
//   - It does not depend on net/url staying as strict as it is today. A
//     security rule whose guarantee is a side effect of another package's
//     current strictness is one upgrade away from not holding.
//   - It rejects cases net/url does accept. Control characters in a *fragment*,
//     and spaces in a path, query or trailing position, parse cleanly — they do
//     not confuse the scheme, but they are not something a well-formed
//     user-supplied URL contains, and accepting them means storing a value that
//     renders differently in different consumers.
//
// # Scheme-relative URLs are rejected
//
// "//evil.example.com/path" parses with an empty scheme and is treated by a
// browser as "same scheme as the current page", so it navigates off-site. It is
// the classic open-redirect payload. A scheme is therefore required, which
// rejects relative URLs generally — this rule is for absolute URLs, and a field
// that should hold a path wants [Matches] with an anchored pattern instead.
//
// # What this rule does not do
//
// It does not check that the host is one you trust. An allowed scheme still
// permits any host, so this is not sufficient on its own for a redirect target:
// for that, compare the parsed host against a registered allow-list, which is
// application knowledge this package does not have. It also does not perform
// DNS resolution, so it is not an SSRF defense — a hostname that resolves to a
// link-local address passes.
//
// Comparison is case-insensitive, as the URL grammar requires: "JaVaScRiPt:" is
// the same scheme to a browser.
//
// An empty allow-list rejects every value, which is the fail-closed reading of
// one, and matches how [OneOf] and [RequireContentType] treat the same mistake.
func URL(schemes ...string) Rule {
	allowed := DefaultURLSchemes
	if len(schemes) > 0 {
		allowed = make([]string, 0, len(schemes))
		for _, s := range schemes {
			allowed = append(allowed, strings.ToLower(strings.TrimSpace(s)))
		}
	}

	return func(field, value string) error {
		const invalid = "must be a valid URL"

		if value == "" {
			return newError(field, invalid)
		}
		if hasControlOrSpace(value) {
			return newError(field, invalid)
		}
		if !utf8.ValidString(value) {
			return newError(field, invalid)
		}

		u, err := url.Parse(value)
		if err != nil {
			return newError(field, invalid)
		}
		// An empty scheme is a relative or scheme-relative URL; see above.
		if u.Scheme == "" {
			return newError(field, invalid)
		}
		scheme := strings.ToLower(u.Scheme)
		for _, a := range allowed {
			if scheme == a {
				// A hierarchical scheme with no host is not a usable absolute
				// URL: "http:///path" and "https:" reach nothing, and letting
				// them through means storing a value no later use can resolve.
				if u.Host == "" {
					return newError(field, invalid)
				}
				return nil
			}
		}
		return newError(field, invalid)
	}
}

// hasControlOrSpace reports whether s contains any ASCII control character,
// space, or DEL.
//
// It runs before url.Parse deliberately. Browsers strip some of these before
// reading the scheme, so a value that parses one way here can navigate another
// way there; rejecting outright avoids having to model that divergence. It is a
// named function rather than an inline loop so that it can be tested directly,
// independently of what net/url happens to reject in any given Go release.
func hasControlOrSpace(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}
