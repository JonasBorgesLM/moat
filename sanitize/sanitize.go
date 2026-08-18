// Package sanitize normalizes text that is expected to be plain.
//
// # This package is not an HTML sanitizer, on purpose
//
// There is no StripTags here, and there never will be. A regex-based tag
// stripper is trivially bypassable — malformed tags, attribute-only injection,
// nested constructs and browser error recovery all defeat it — and its mere
// presence in a *security* library implies that running input through it makes
// the input safe to render as HTML. It does not, and that false confidence is
// more dangerous than having no function at all.
//
// The correct defense against XSS is contextual output encoding at the point of
// rendering. Go's html/template already does this: it understands whether an
// interpolation lands in an HTML body, an attribute, a URL, a style block, or a
// script block, and encodes accordingly. Use it, and do not defeat it by
// wrapping values in template.HTML.
//
// For fields that must never contain markup at all, reject rather than mangle:
// see validate.NoHTMLTags. Rejecting is honest about being an input-shape
// constraint; silently mangling input hides the attack and corrupts legitimate
// data — a user whose name really is "Ben <the> Third" deserves an error, not a
// quietly rewritten name.
//
// If you genuinely need to accept rich text from untrusted users, you need a
// real HTML parser with an allow-list policy, such as bluemonday. That is a
// different job with a much larger attack surface, and this package refuses to
// pretend it is the same job.
//
// # What this package is for
//
// Two narrow, well-defined normalizations:
//
//   - [StripControlChars] removes Unicode control characters (category Cc)
//     apart from tab, newline and carriage return.
//   - [CollapseWhitespace] reduces every run of whitespace to a single space and
//     trims the ends.
//
// [PlainText] composes them, which is what most callers want for a value that
// should be one line of ordinary text: a display name, a subject line, a label.
//
// # Threats these address
//
// Control characters are not cosmetic. Two concrete attacks:
//
//   - Terminal escape injection. ESC (U+001B) begins an ANSI escape sequence.
//     A value containing one, written to a log that an operator later cats or
//     tails, can reposition the cursor, recolor or blank out text, and on some
//     terminal emulators alter the window title or inject content. An attacker
//     uses this to hide the traces of what they did from the person reading the
//     log. StripControlChars removes ESC along with the rest of Cc.
//   - Log injection. Newline and carriage return let an attacker forge whole
//     log lines: a username of "alice\nJan 01 00:00:00 sshd: Accepted password
//     for root" produces a second line that looks authentic. Note carefully
//     that StripControlChars deliberately *keeps* \n, \r and \t, so it does not
//     stop this by itself. [CollapseWhitespace] and [PlainText] do, by folding
//     line breaks into a single space. If you are normalizing a value that will
//     be logged, use PlainText, not StripControlChars alone.
//
// # Known limits, stated rather than glossed over
//
// These functions operate on Unicode category Cc. They do not remove category
// Cf format characters, which include the bidirectional overrides used by the
// "Trojan Source" technique (U+202A–U+202E, U+2066–U+2069) and zero-width
// characters such as U+200B and U+FEFF. Those can make text render in an order
// that differs from its byte order, or hide characters entirely, which matters
// wherever a human eyeballs a value to make a decision — code review, an
// approvals queue, an audit trail.
//
// They are not stripped here because "control character" means Cc, and a
// function that quietly did more than its name says would be its own kind of
// hazard. If your text is displayed to humans who act on what they see, filter
// or reject Cf separately.
//
// Nor is any Unicode normalization performed (NFC, NFKC) or any confusable or
// homoglyph detection, both of which need golang.org/x/text and so cannot live
// in a stdlib-only module.
//
// # Encoding
//
// All functions in this package return valid UTF-8. Bytes that are not valid
// UTF-8 are replaced with U+FFFD rather than dropped, so that a truncated or
// deliberately malformed sequence is visible in the output instead of silently
// changing the string's length. Downstream code that assumes valid UTF-8 —
// which includes most of the standard library — is a common source of
// surprising behavior on hostile input.
package sanitize

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// StripControlChars removes Unicode control characters (category Cc) from s,
// keeping tab (U+0009), newline (U+000A) and carriage return (U+000D).
//
// This includes the C0 range apart from those three, DEL (U+007F), and the C1
// range U+0080–U+009F. Removing ESC is what neutralizes ANSI escape sequences
// aimed at whoever later reads the value in a terminal.
//
// It deliberately preserves line structure, so it is the right choice for text
// that is legitimately multi-line — a comment body, a description. Because it
// keeps \n and \r, it does **not** prevent log injection on its own; use
// [PlainText] for anything destined for a single-line context such as a log
// record.
//
// Invalid UTF-8 is replaced with U+FFFD. The result is always valid UTF-8, and
// the function is idempotent.
func StripControlChars(s string) string {
	if isClean(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	// Ranging over a string yields U+FFFD once per byte that is not part of a
	// valid UTF-8 sequence, which is what gives this function its "output is
	// always valid UTF-8" guarantee.
	for _, r := range s {
		if isStrippableControl(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// CollapseWhitespace replaces every run of whitespace in s with a single space
// (U+0020) and removes leading and trailing whitespace.
//
// Whitespace is Unicode's definition, so it covers not just space, tab and the
// line breaks but also the ones people forget: non-breaking space (U+00A0),
// the en/em spaces, ideographic space (U+3000), and NEL (U+0085). Folding all
// of them to a plain space is what makes two values that look identical to a
// human actually compare equal, and it is what removes the line breaks an
// attacker uses to forge extra log lines.
//
// Invalid UTF-8 is replaced with U+FFFD. U+FFFD is not whitespace, so it is
// preserved rather than collapsed. The result is always valid UTF-8, and the
// function is idempotent.
func CollapseWhitespace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	pendingSpace := false
	wrote := false
	// Ranging over a string yields U+FFFD once per invalid byte; U+FFFD is not
	// whitespace, so a malformed sequence survives as a visible replacement
	// character rather than being silently folded away.
	for _, r := range s {
		if unicode.IsSpace(r) {
			// Defer the space: a run at the end of the string must not be
			// written at all, which is how trailing whitespace is trimmed
			// without a second pass.
			pendingSpace = wrote
			continue
		}
		if pendingSpace {
			b.WriteByte(' ')
			pendingSpace = false
		}
		b.WriteRune(r)
		wrote = true
	}
	return b.String()
}

// PlainText normalizes s into a single line of ordinary text: it applies
// [StripControlChars] and then [CollapseWhitespace].
//
// This is the function to reach for when a value should be one line — a display
// name, a filename label, a subject, anything that will end up in a log record
// or a report. It removes terminal escape sequences and folds the line breaks
// that would otherwise let an attacker forge whole log lines.
//
// It does not make the result safe to interpolate into HTML. Nothing in this
// package does; see the package documentation.
//
// The result is always valid UTF-8, contains no control characters, has no
// leading or trailing whitespace, and never contains two adjacent spaces. The
// function is idempotent.
func PlainText(s string) string {
	return CollapseWhitespace(StripControlChars(s))
}

// isStrippableControl reports whether r is a control character that
// StripControlChars removes. Tab, newline and carriage return are kept so that
// legitimately multi-line text survives.
func isStrippableControl(r rune) bool {
	switch r {
	case '\t', '\n', '\r':
		return false
	}
	return unicode.IsControl(r)
}

// isClean reports whether s is already valid UTF-8 with nothing to strip, so
// that the common case returns the original string without allocating.
func isClean(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < utf8.RuneSelf {
			if isStrippableControl(rune(s[i])) {
				return false
			}
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			return false // invalid UTF-8 needs replacing
		}
		if isStrippableControl(r) {
			return false
		}
		i += size - 1
	}
	return true
}
