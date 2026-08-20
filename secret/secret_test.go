package secret_test

import (
	"bytes"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/moat/secret"
)

// canary is the value that must never appear in any output. It is chosen to be
// distinctive and to contain no substring of the redaction placeholder.
const canary = "hunter2-swordfish-correct-horse"

// leaks reports whether s contains the secret, in whole or in a form a naive
// encoder might produce: raw, byte-slice syntax, hex, and base64.
func leaks(s string) bool {
	if strings.Contains(s, canary) {
		return true
	}
	// %d and %v against a []byte print decimal byte values. Look for the first
	// three bytes of the canary rendered that way.
	b := []byte(canary)
	if strings.Contains(s, fmt.Sprintf("%d %d %d", b[0], b[1], b[2])) {
		return true
	}
	if strings.Contains(s, fmt.Sprintf("%x", b)) {
		return true
	}
	return false
}

func value() secret.Value { return secret.New([]byte(canary)) }

// TestNoFormattingVerbLeaks drives every fmt verb, and the pointer as well as
// the value, because a method set mistake shows up only on one of them.
func TestNoFormattingVerbLeaks(t *testing.T) {
	v := value()
	p := &v

	verbs := []string{
		"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%b", "%o", "%c",
		"%U", "%e", "%f", "%g", "%p", "%t", "%8v", "%-8v", "%.3s", "%.1v",
		"%[1]v", "%T",
	}

	for _, verb := range verbs {
		for _, arg := range []any{v, p} {
			got := fmt.Sprintf(verb, arg)
			if leaks(got) {
				t.Errorf("Sprintf(%q, %T) leaked: %s", verb, arg, got)
			}
		}
	}
}

// TestNestedInStructsDoesNotLeak covers the shapes a secret actually travels
// in: a field of a config struct, a slice, a map value, and behind a pointer.
func TestNestedInStructsDoesNotLeak(t *testing.T) {
	type Config struct {
		Name  string
		Token secret.Value
	}
	type Outer struct {
		Inner  Config
		Extras map[string]secret.Value
		List   []secret.Value
		Ptr    *secret.Value
	}

	v := value()
	o := Outer{
		Inner:  Config{Name: "api", Token: v},
		Extras: map[string]secret.Value{"csrf": v},
		List:   []secret.Value{v},
		Ptr:    &v,
	}

	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x"} {
		got := fmt.Sprintf(verb, o)
		if leaks(got) {
			t.Errorf("Sprintf(%q, Outer) leaked: %s", verb, got)
		}
	}
}

// TestUnexportedFieldDoesNotLeak covers the first path that no method can
// reach: fmt walks struct fields with reflection and cannot call methods on a
// field it cannot interface, so an unexported field is printed structurally.
// Masking is what makes that harmless — what gets printed is the keystream
// output, not the secret.
func TestUnexportedFieldDoesNotLeak(t *testing.T) {
	type config struct{ token secret.Value }

	for _, verb := range []string{"%v", "%+v", "%#v", "%d", "%x", "%s"} {
		got := fmt.Sprintf(verb, config{token: value()})
		if leaks(got) {
			t.Errorf("unexported field with %s leaked: %s", verb, got)
		}
	}
}

// TestPercentPDoesNotLeak covers the second uncoverable path. fmt handles %p
// before consulting Formatter, and its bad-verb path suppresses Formatter and
// Stringer at every depth while dumping the value structurally. Masking is the
// only reason this is safe.
func TestPercentPDoesNotLeak(t *testing.T) {
	v := value()
	type Config struct{ Token secret.Value }

	for _, arg := range []any{v, &v, Config{Token: v}, []secret.Value{v}} {
		got := fmt.Sprintf("%p", arg)
		if leaks(got) {
			t.Errorf("%%p against %T leaked: %s", arg, got)
		}
	}
}

// TestMaskingKeepsPlaintextOutOfTheStruct is the property the two tests above
// depend on: a reflective walk of the struct must not encounter the secret.
func TestMaskingKeepsPlaintextOutOfTheStruct(t *testing.T) {
	v := value()

	// GoString on the raw struct via reflect-based printing, with methods
	// suppressed the same way fmt's error paths suppress them.
	rv := reflect.ValueOf(v)
	field := rv.Field(0) // the single unexported field
	raw := make([]byte, field.Len())
	for i := range raw {
		// #nosec G115 -- the field is a []byte, so every element is already 0-255.
		raw[i] = byte(field.Index(i).Uint())
	}
	if string(raw) == canary {
		t.Fatal("the plaintext is stored in the struct field; every reflective dump leaks it")
	}
	if leaks(fmt.Sprintf("%v %d %x %s", raw, raw, raw, raw)) {
		t.Error("the stored bytes render as the secret")
	}

	// And the masking must still be reversible.
	if string(v.Bytes()) != canary {
		t.Errorf("Bytes() = %q, want the original", v.Bytes())
	}
}

func TestJSONDoesNotLeak(t *testing.T) {
	type Config struct {
		Name  string       `json:"name"`
		Token secret.Value `json:"token"`
	}

	v := value()
	for name, in := range map[string]any{
		"bare value":   v,
		"pointer":      &v,
		"struct field": Config{Name: "api", Token: v},
		"slice":        []secret.Value{v},
		"map value":    map[string]secret.Value{"k": v},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := json.Marshal(in)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if leaks(string(out)) {
				t.Errorf("json.Marshal leaked: %s", out)
			}
			if !strings.Contains(string(out), secret.Redacted) {
				t.Errorf("json.Marshal = %s, want it to contain %q", out, secret.Redacted)
			}
		})
	}
}

// TestJSONEncoderDoesNotLeak covers the streaming encoder as well as Marshal,
// since they take different paths through the package.
func TestJSONEncoderDoesNotLeak(t *testing.T) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(value()); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if leaks(buf.String()) {
		t.Errorf("json.Encoder leaked: %s", buf.String())
	}
}

func TestSlogDoesNotLeak(t *testing.T) {
	type Config struct {
		Token secret.Value
	}
	v := value()

	handlers := map[string]func(*bytes.Buffer) slog.Handler{
		"json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
		"text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
	}

	for name, newHandler := range handlers {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			log := slog.New(newHandler(&buf))

			log.Info("direct", "secret", v)
			log.Info("any", slog.Any("secret", v))
			log.Info("pointer", "secret", &v)
			log.Info("group", slog.Group("cfg", slog.Any("secret", v)))
			log.Info("nested in struct", "cfg", Config{Token: v})
			log.With("secret", v).Info("with")

			if leaks(buf.String()) {
				t.Errorf("slog leaked: %s", buf.String())
			}
			if !strings.Contains(buf.String(), secret.Redacted) {
				t.Errorf("slog output does not contain %q: %s", secret.Redacted, buf.String())
			}
		})
	}
}

// TestStringAndGoStringDirectly exercises the two methods that fmt no longer
// reaches once Format exists. Code outside fmt still calls them, so they must
// redact on their own.
func TestStringAndGoStringDirectly(t *testing.T) {
	v := value()

	if got := v.String(); got != secret.Redacted {
		t.Errorf("String() = %q, want %q", got, secret.Redacted)
	}
	if got := (&v).String(); got != secret.Redacted {
		t.Errorf("(&v).String() = %q, want %q", got, secret.Redacted)
	}

	gs := v.GoString()
	if leaks(gs) {
		t.Errorf("GoString() leaked: %s", gs)
	}
	if !strings.Contains(gs, secret.Redacted) {
		t.Errorf("GoString() = %q, want it to contain %q", gs, secret.Redacted)
	}

	// Concatenation through the Stringer interface, the way a hand-written
	// error message would reach it.
	var s fmt.Stringer = v
	if leaks("secret is " + s.String()) {
		t.Error("Stringer interface leaked")
	}
}

// TestFormatPrecedence pins that Format wins over Stringer and GoStringer, and
// that %#v is the one verb routed to GoString.
func TestFormatPrecedence(t *testing.T) {
	v := value()

	if got := fmt.Sprintf("%v", v); got != secret.Redacted {
		t.Errorf("%%v = %q, want %q", got, secret.Redacted)
	}
	if got := fmt.Sprintf("%#v", v); got != v.GoString() {
		t.Errorf("%%#v = %q, want %q", got, v.GoString())
	}
	// A precision must not be honoured: doing so would let a caller walk the
	// value out one character at a time.
	if got := fmt.Sprintf("%.1v", v); got != secret.Redacted {
		t.Errorf("%%.1v = %q, want the full placeholder %q", got, secret.Redacted)
	}
}

func TestMarshalText(t *testing.T) {
	got, err := value().MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	if string(got) != secret.Redacted {
		t.Errorf("MarshalText = %q, want %q", got, secret.Redacted)
	}
}

func TestBytesRoundTripAndCopies(t *testing.T) {
	in := []byte(canary)
	v := secret.New(in)

	if got := string(v.Bytes()); got != canary {
		t.Errorf("Bytes() = %q, want the original", got)
	}

	// New copies, so mutating the caller's slice must not change the Value.
	in[0] = 'X'
	if got := string(v.Bytes()); got != canary {
		t.Errorf("mutating the input changed the Value: %q", got)
	}

	// Bytes copies, so mutating the result must not change the Value either.
	out := v.Bytes()
	out[0] = 'Y'
	if got := string(v.Bytes()); got != canary {
		t.Errorf("mutating the output changed the Value: %q", got)
	}
}

func TestLenAndIsZero(t *testing.T) {
	if v := (secret.Value{}); !v.IsZero() || v.Len() != 0 {
		t.Errorf("zero Value: IsZero=%v Len=%d, want true/0", v.IsZero(), v.Len())
	}
	if v := secret.New(nil); !v.IsZero() {
		t.Error("New(nil) should be zero")
	}
	if v := secret.New([]byte{}); !v.IsZero() {
		t.Error("New(empty) should be zero")
	}
	if v := value(); v.IsZero() || v.Len() != len(canary) {
		t.Errorf("IsZero=%v Len=%d, want false/%d", v.IsZero(), v.Len(), len(canary))
	}
}

func TestEqual(t *testing.T) {
	a := secret.New([]byte("abcdef"))
	b := secret.New([]byte("abcdef"))
	c := secret.New([]byte("abcdeg"))
	d := secret.New([]byte("abcde"))

	if !a.Equal(b) {
		t.Error("equal values reported unequal")
	}
	if a.Equal(c) {
		t.Error("values differing in the last byte reported equal")
	}
	if a.Equal(d) {
		t.Error("values of different length reported equal")
	}
	if !(secret.Value{}).Equal(secret.Value{}) {
		t.Error("two zero Values reported unequal")
	}
	if a.Equal(secret.Value{}) {
		t.Error("a value and the zero Value reported equal")
	}
}

func TestUnmarshal(t *testing.T) {
	t.Run("text", func(t *testing.T) {
		var v secret.Value
		if err := v.UnmarshalText([]byte(canary)); err != nil {
			t.Fatalf("UnmarshalText: %v", err)
		}
		if string(v.Bytes()) != canary {
			t.Errorf("Bytes() = %q, want the input", v.Bytes())
		}
	})

	t.Run("json string", func(t *testing.T) {
		type Config struct {
			Token secret.Value `json:"token"`
		}
		var c Config
		if err := json.Unmarshal([]byte(`{"token":"`+canary+`"}`), &c); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if string(c.Token.Bytes()) != canary {
			t.Errorf("Token = %q, want the input", c.Token.Bytes())
		}
	})

	t.Run("json null leaves it empty", func(t *testing.T) {
		var v secret.Value
		if err := json.Unmarshal([]byte("null"), &v); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if !v.IsZero() {
			t.Error("null should leave the Value empty")
		}
	})

	t.Run("json non-string is refused", func(t *testing.T) {
		var v secret.Value
		if err := json.Unmarshal([]byte("12345"), &v); err == nil {
			t.Error("a JSON number was accepted as a secret")
		}
	})
}

// TestUnmarshalRefusesThePlaceholder is the round-trip trap: marshalling is
// lossy, so reloading marshalled output must fail loudly instead of installing
// "[REDACTED]" as everyone's shared secret.
func TestUnmarshalRefusesThePlaceholder(t *testing.T) {
	t.Run("text", func(t *testing.T) {
		var v secret.Value
		if err := v.UnmarshalText([]byte(secret.Redacted)); !errors.Is(err, secret.ErrRedacted) {
			t.Errorf("UnmarshalText(placeholder) error = %v, want ErrRedacted", err)
		}
		if !v.IsZero() {
			t.Error("a refused unmarshal must leave the Value untouched")
		}
	})

	t.Run("json", func(t *testing.T) {
		var v secret.Value
		err := json.Unmarshal([]byte(`"`+secret.Redacted+`"`), &v)
		if !errors.Is(err, secret.ErrRedacted) {
			t.Errorf("UnmarshalJSON(placeholder) error = %v, want ErrRedacted", err)
		}
	})

	t.Run("full round trip fails", func(t *testing.T) {
		out, err := json.Marshal(value())
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		var back secret.Value
		if err := json.Unmarshal(out, &back); !errors.Is(err, secret.ErrRedacted) {
			t.Errorf("round trip error = %v, want ErrRedacted", err)
		}
	})
}

// TestUnmarshalErrorDoesNotLeak: an unmarshal error is exactly the sort of
// value that gets logged, so it must not quote the input back.
func TestUnmarshalErrorDoesNotLeak(t *testing.T) {
	var v secret.Value
	err := json.Unmarshal([]byte(`{"not":"a string"}`), &v)
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "a string") {
		t.Errorf("the error quoted the input: %v", err)
	}
}

func ExampleValue() {
	token := secret.New([]byte("s3cr3t-signing-key"))

	// Every ordinary way of printing it is redacted.
	fmt.Printf("%v\n", token)
	fmt.Printf("%s\n", token)
	fmt.Printf("%#v\n", token)

	type Config struct {
		Name  string       `json:"name"`
		Token secret.Value `json:"token"`
	}
	out, _ := json.Marshal(Config{Name: "api", Token: token})
	fmt.Println(string(out))

	// The real bytes come out only when asked for explicitly.
	fmt.Println(len(token.Bytes()), "bytes")

	// Output:
	// [REDACTED]
	// [REDACTED]
	// secret.Value("[REDACTED]")
	// {"name":"api","token":"[REDACTED]"}
	// 18 bytes
}

// TestValueIsNotComparable documents a deliberate consequence of holding a
// slice: Value cannot be used with == or as a map key, so every comparison has
// to go through Equal and therefore runs in constant time. A future change that
// made Value comparable would silently reopen the timing side channel, so this
// is asserted rather than left to chance.
//
// The property is checked with reflect rather than by writing `v == v`, which
// would not compile.
func TestValueIsNotComparable(t *testing.T) {
	if reflect.TypeOf(secret.Value{}).Comparable() {
		t.Error("secret.Value became comparable; == and map keys now bypass Equal's constant time")
	}
}

// Compile-time proof that Value satisfies every interface the redaction relies
// on, and that it does so on the **value** receiver.
//
// The receiver half is the part worth asserting. If any of these moved to a
// pointer receiver, fmt and encoding/json would silently stop consulting it for
// a non-pointer argument -- which is the single most common way a redacting
// type is written wrong, and it produces no compile error at the call site.
var (
	_ fmt.Stringer             = secret.Value{}
	_ fmt.GoStringer           = secret.Value{}
	_ fmt.Formatter            = secret.Value{}
	_ json.Marshaler           = secret.Value{}
	_ encoding.TextMarshaler   = secret.Value{}
	_ slog.LogValuer           = secret.Value{}
	_ json.Unmarshaler         = &secret.Value{}
	_ encoding.TextUnmarshaler = &secret.Value{}
)

// TestRedactionThroughEachInterface calls every interface method through the
// interface itself rather than through the concrete type.
//
// This is not the same test as driving fmt: a type can satisfy an interface and
// still be reached by a dispatcher that type-switches on it directly — a
// logging façade checking for encoding.TextMarshaler, a serializer checking for
// json.Marshaler. Those paths never touch Format, so they need their own proof.
func TestRedactionThroughEachInterface(t *testing.T) {
	v := value()

	t.Run("fmt.Stringer", func(t *testing.T) {
		var i fmt.Stringer = v
		if got := i.String(); got != secret.Redacted || leaks(got) {
			t.Errorf("String() = %q", got)
		}
	})

	t.Run("fmt.GoStringer", func(t *testing.T) {
		var i fmt.GoStringer = v
		if got := i.GoString(); leaks(got) || !strings.Contains(got, secret.Redacted) {
			t.Errorf("GoString() = %q", got)
		}
	})

	t.Run("encoding.TextMarshaler", func(t *testing.T) {
		var i encoding.TextMarshaler = v
		got, err := i.MarshalText()
		if err != nil {
			t.Fatalf("MarshalText: %v", err)
		}
		if string(got) != secret.Redacted || leaks(string(got)) {
			t.Errorf("MarshalText() = %q", got)
		}
	})

	t.Run("json.Marshaler", func(t *testing.T) {
		var i json.Marshaler = v
		got, err := i.MarshalJSON()
		if err != nil {
			t.Fatalf("MarshalJSON: %v", err)
		}
		if leaks(string(got)) || !strings.Contains(string(got), secret.Redacted) {
			t.Errorf("MarshalJSON() = %q", got)
		}
	})

	t.Run("slog.LogValuer", func(t *testing.T) {
		var i slog.LogValuer = v
		got := i.LogValue()
		if got.String() != secret.Redacted || leaks(got.String()) {
			t.Errorf("LogValue() = %v", got)
		}
	})

	t.Run("fmt.Formatter", func(t *testing.T) {
		var i fmt.Formatter = v
		// Drive it the way fmt would, including the verb that must route to
		// GoString.
		if got := fmt.Sprintf("%v", i); got != secret.Redacted {
			t.Errorf("%%v through fmt.Formatter = %q", got)
		}
		if got := fmt.Sprintf("%#v", i); !strings.Contains(got, secret.Redacted) || leaks(got) {
			t.Errorf("%%#v through fmt.Formatter = %q", got)
		}
	})
}

// TestUnknownVerbFallsBackToRedacted pins the default branch of Format: a verb
// nobody anticipated must write the placeholder, never the bytes.
//
// %w is excluded and covered by TestBadVerbPathsDoNotLeak instead. Outside
// fmt.Errorf it is not an unknown verb but a *bad* one, and fmt routes bad
// verbs past Formatter entirely -- see that test.
func TestUnknownVerbFallsBackToRedacted(t *testing.T) {
	v := value()
	for _, verb := range []string{"%h", "%j", "%k", "%l", "%m", "%r", "%y", "%z"} {
		got := fmt.Sprintf(verb, v)
		if leaks(got) {
			t.Errorf("unknown verb %s leaked: %s", verb, got)
		}
		if !strings.Contains(got, secret.Redacted) {
			t.Errorf("unknown verb %s = %q, want the placeholder", verb, got)
		}
	}
}

// TestBadVerbPathsDoNotLeak covers the exact set of verbs that never reach
// Formatter, measured rather than assumed: %T, %p and %w.
//
// %T prints only the type name and is harmless. %p and %w both route to fmt's
// bad-verb path, which sets an internal erroring flag that suppresses Formatter
// and Stringer at every nesting depth and then dumps the value structurally.
// No method can intercept them, so the only thing standing between these and
// the secret is that the struct holds masked bytes.
//
// If Go ever routes one of these through Formatter, the placeholder check below
// starts passing too and nothing breaks; if a new bad verb appears, the leak
// check catches it.
func TestBadVerbPathsDoNotLeak(t *testing.T) {
	v := value()
	for _, verb := range []string{"%T", "%p", "%w"} {
		for _, arg := range []any{v, &v, struct{ S secret.Value }{v}} {
			got := fmt.Sprintf(verb, arg)
			if leaks(got) {
				t.Errorf("%s against %T leaked: %s", verb, arg, got)
			}
		}
	}
}
