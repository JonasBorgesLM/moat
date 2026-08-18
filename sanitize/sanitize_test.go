package sanitize_test

import (
	"fmt"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/JonasBorgesLM/moat/sanitize"
)

func TestStripControlChars(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain text is untouched", "hello world", "hello world"},
		{"empty", "", ""},
		{"tab, newline and carriage return are kept", "a\tb\nc\rd", "a\tb\nc\rd"},
		{"NUL is removed", "a\x00b", "ab"},
		{"BEL is removed", "a\x07b", "ab"},
		{"DEL is removed", "a\u007fb", "ab"},
		{"vertical tab and form feed are removed", "a\vb\fc", "abc"},
		{"C1 controls are removed", "a\u0090b\u009fc", "abc"},
		{
			name: "ANSI escape sequence loses its introducer",
			in:   "alice\x1b[2Kadmin",
			want: "alice[2Kadmin",
		},
		{
			name: "terminal title injection loses its escape",
			in:   "user\x1b]0;pwned\x07",
			want: "user]0;pwned",
		},
		{"unicode is preserved", "héllo 世界", "héllo 世界"},
		{"non-breaking space is not a control char", "a\u00a0b", "a\u00a0b"},
		{"invalid utf-8 becomes the replacement character", "a\xffb", "a\ufffdb"},
		{"a truncated sequence becomes replacement characters", "a\xe4\xb8", "a\ufffd\ufffd"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitize.StripControlChars(tc.in); got != tc.want {
				t.Errorf("StripControlChars(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestCollapseWhitespace(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain text is untouched", "hello world", "hello world"},
		{"empty", "", ""},
		{"only whitespace becomes empty", " \t\n ", ""},
		{"runs collapse", "a    b", "a b"},
		{"leading and trailing are trimmed", "   a b   ", "a b"},
		{"mixed whitespace collapses", "a \t\n\r b", "a b"},
		{"newlines become spaces", "line1\nline2", "line1 line2"},
		{"CRLF becomes one space", "line1\r\nline2", "line1 line2"},
		{"non-breaking space is whitespace", "a\u00a0\u00a0b", "a b"},
		{"ideographic space is whitespace", "a\u3000b", "a b"},
		{"NEL is whitespace", "a\u0085b", "a b"},
		{"en and em spaces are whitespace", "a\u2002\u2003b", "a b"},
		{"replacement character is not whitespace", "a\ufffd b", "a\ufffd b"},
		{"invalid utf-8 survives as U+FFFD", "a\xffb", "a\ufffdb"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitize.CollapseWhitespace(tc.in); got != tc.want {
				t.Errorf("CollapseWhitespace(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestPlainText(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain text is untouched", "Ada Lovelace", "Ada Lovelace"},
		{"empty", "", ""},
		{
			// The whole point: a forged second log line is folded onto one line.
			name: "log injection is defused",
			in:   "alice\nJan 01 00:00:00 sshd: Accepted password for root",
			want: "alice Jan 01 00:00:00 sshd: Accepted password for root",
		},
		{
			// A lone CR repositions the cursor to the start of the line, so the
			// spaces overwrite what was already printed there.
			name: "carriage-return overwrite is defused",
			in:   "alice\r                    \rroot",
			want: "alice root",
		},
		{
			name: "terminal escapes are removed and spacing normalized",
			in:   "  \x1b[31mred\x1b[0m   name  ",
			want: "[31mred[0m name",
		},
		{"NUL truncation attempt", "safe\x00../../etc/passwd", "safe../../etc/passwd"},
		{"unicode text survives", "  José   да   世界  ", "José да 世界"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitize.PlainText(tc.in); got != tc.want {
				t.Errorf("PlainText(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestPlainTextIsComposition pins the documented relationship between the three
// functions, so that changing one without the other is caught.
func TestPlainTextIsComposition(t *testing.T) {
	inputs := []string{"", "a b", "  \x1b[2K a \n b \x00 ", "\xff\xfe", "a\u00a0b"}
	for _, in := range inputs {
		want := sanitize.CollapseWhitespace(sanitize.StripControlChars(in))
		if got := sanitize.PlainText(in); got != want {
			t.Errorf("PlainText(%q) = %q, want CollapseWhitespace(StripControlChars(...)) = %q", in, got, want)
		}
	}
}

// TestDocumentedLimit_BidiOverridesSurvive asserts the gap the package
// documentation admits to: Cf format characters, including the bidirectional
// overrides used by the "Trojan Source" technique, are not removed.
//
// The test exists so that the documentation and the behavior cannot drift
// apart. If it ever starts failing, the package doc is now wrong.
func TestDocumentedLimit_BidiOverridesSurvive(t *testing.T) {
	const rightToLeftOverride = '\u202e'
	trojan := "if (accessLevel != \"user" + string(rightToLeftOverride) + " admin\")"

	if got := sanitize.PlainText(trojan); !strings.ContainsRune(got, rightToLeftOverride) {
		t.Error("a bidi override was stripped; the package doc says Cf is not handled and must be corrected")
	}
}

func TestOutputInvariants(t *testing.T) {
	inputs := []string{
		"", "hello", "  ", "\x00\x1b\u007f", "a\xffb", "\xf0\x9f", "a  \t\n b",
		strings.Repeat("x \x00", 100),
	}
	for _, in := range inputs {
		checkPlainTextInvariants(t, in, sanitize.PlainText(in))
	}
}

// checkPlainTextInvariants asserts every property PlainText documents.
func checkPlainTextInvariants(t *testing.T, in, out string) {
	t.Helper()

	if !utf8.ValidString(out) {
		t.Errorf("PlainText(%q) = %q, which is not valid UTF-8", in, out)
	}
	for _, r := range out {
		if unicode.IsControl(r) {
			t.Errorf("PlainText(%q) = %q, which still contains control character %U", in, out, r)
			break
		}
	}
	if strings.Contains(out, "  ") {
		t.Errorf("PlainText(%q) = %q, which contains a double space", in, out)
	}
	if out != strings.TrimSpace(out) {
		t.Errorf("PlainText(%q) = %q, which is not trimmed", in, out)
	}
	if again := sanitize.PlainText(out); again != out {
		t.Errorf("PlainText is not idempotent: PlainText(%q) = %q, then %q", in, out, again)
	}
}

// FuzzStripControlChars asserts the invariants hold for arbitrary bytes: valid
// UTF-8 out, no strippable control characters left, and idempotence.
func FuzzStripControlChars(f *testing.F) {
	seeds := []string{"", "hello", "a\x00b", "\x1b[2K", "a\xffb", "héllo", "\t\n\r", "\u202e", "\xf0\x9f\x92"}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := sanitize.StripControlChars(s)

		if !utf8.ValidString(got) {
			t.Fatalf("StripControlChars(%q) = %q, not valid UTF-8", s, got)
		}
		for _, r := range got {
			if unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r' {
				t.Fatalf("StripControlChars(%q) = %q, still contains %U", s, got, r)
			}
		}
		if again := sanitize.StripControlChars(got); again != got {
			t.Fatalf("not idempotent: %q -> %q -> %q", s, got, again)
		}
		// An invalid byte is replaced by a three-byte U+FFFD; nothing may grow
		// faster than that, or the function is an amplification vector.
		if len(got) > 3*len(s) {
			t.Fatalf("StripControlChars(%q) grew from %d to %d bytes", s, len(s), len(got))
		}
	})
}

// FuzzCollapseWhitespace asserts the invariants hold for arbitrary bytes.
func FuzzCollapseWhitespace(f *testing.F) {
	seeds := []string{"", " ", "a  b", " \u3000", "a\xffb", "  a  ", "\u0085", "\u00a0x\u00a0"}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := sanitize.CollapseWhitespace(s)

		if !utf8.ValidString(got) {
			t.Fatalf("CollapseWhitespace(%q) = %q, not valid UTF-8", s, got)
		}
		if got != strings.TrimSpace(got) {
			t.Fatalf("CollapseWhitespace(%q) = %q, not trimmed", s, got)
		}
		for _, r := range got {
			if unicode.IsSpace(r) && r != ' ' {
				t.Fatalf("CollapseWhitespace(%q) = %q, contains non-space whitespace %U", s, got, r)
			}
		}
		if strings.Contains(got, "  ") {
			t.Fatalf("CollapseWhitespace(%q) = %q, contains a double space", s, got)
		}
		if again := sanitize.CollapseWhitespace(got); again != got {
			t.Fatalf("not idempotent: %q -> %q -> %q", s, got, again)
		}
	})
}

// FuzzPlainText asserts the composed invariants, and in particular that no
// input can produce output containing a line break -- the property that makes
// the result safe to write as a single log record.
func FuzzPlainText(f *testing.F) {
	seeds := []string{"", "alice\nfake log line", "\x1b]0;title\x07", "a\xffb", "  \t x \n ", "\u202e"}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := sanitize.PlainText(s)

		if !utf8.ValidString(got) {
			t.Fatalf("PlainText(%q) = %q, not valid UTF-8", s, got)
		}
		if strings.ContainsAny(got, "\n\r\t") {
			t.Fatalf("PlainText(%q) = %q, which can forge a log line", s, got)
		}
		for _, r := range got {
			if unicode.IsControl(r) {
				t.Fatalf("PlainText(%q) = %q, contains control character %U", s, got, r)
			}
		}
		if strings.Contains(got, "  ") || got != strings.TrimSpace(got) {
			t.Fatalf("PlainText(%q) = %q, not normalized", s, got)
		}
		if again := sanitize.PlainText(got); again != got {
			t.Fatalf("not idempotent: %q -> %q -> %q", s, got, again)
		}
	})
}

func ExamplePlainText() {
	// A display name straight from a signup form, carrying a forged log line
	// and an ANSI escape to hide it from whoever later reads the log.
	name := "  alice\x1b[2K\nJan 01 00:00:00 sshd: Accepted password for root  "

	fmt.Printf("%q\n", sanitize.PlainText(name))
	// Output: "alice[2K Jan 01 00:00:00 sshd: Accepted password for root"
}

func ExampleStripControlChars() {
	// Multi-line text keeps its line structure; only the escape introducer goes.
	comment := "First line\x1b[31m\nSecond line"

	fmt.Printf("%q\n", sanitize.StripControlChars(comment))
	// Output: "First line[31m\nSecond line"
}

func ExampleCollapseWhitespace() {
	fmt.Printf("%q\n", sanitize.CollapseWhitespace("  José   Ferreira \n"))
	// Output: "José Ferreira"
}
