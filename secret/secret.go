// Package secret holds byte values that must not escape through formatting.
//
// # The problem
//
// A secret in a []byte or a string is one Printf away from a log aggregator. It
// is not usually a deliberate print that leaks it — it is a struct dumped with
// %+v while debugging, a config object marshalled into a startup log line, an
// error message that interpolates the value it failed to parse, or a
// slog.Any("config", cfg) that seemed harmless. The value then lives in CI
// output, in container logs, and in whatever indexes them, for as long as those
// are retained.
//
// [Value] closes those paths. It wraps the bytes so that every formatting and
// serialization route the standard library offers writes [Redacted] instead,
// and the real bytes come out only through an explicit [Value.Bytes] call that
// is visible in review.
//
// # What it does not do
//
// This is not encryption, and it is not memory protection. The bytes are held
// XOR-masked (see [Value]) so that a structural dump of the struct reveals
// nothing, but the key that derives the mask lives in the same address space as
// the masked bytes, so anything that can read process memory — a debugger, a
// core dump, another goroutine — unmasks them trivially. The mask raises the
// floor on *accidental output* and does nothing else.
//
// The threat this package addresses is therefore accidental disclosure through
// formatting, logging and serialization. It is not a defense against an
// attacker who is already inside the process, and treating it as one would be
// overestimating it.
//
// Two output paths cannot be closed by methods at all — see [Value] — so the
// bytes are additionally held masked, and the plaintext is never resident in a
// field that reflection can reach.
//
// # What the mask is worth, stated exactly
//
// The mask defends against one thing: masked bytes reaching an output sink. The
// guarantee is that such a leak reveals nothing about the secret — and that
// guarantee holds even when the adversary has leaked several of them, and even
// when they know the plaintext of one.
//
// Getting there took some care, because the obvious construction does not hold
// up. A single process-wide pad applied by position — which is what this package
// used before — fails in two ways that both sit *inside* the scenario the mask
// exists for:
//
//   - Keystream recovery. An adversary who obtains the masked bytes of a secret
//     whose plaintext they know or supplied — an attacker-chosen API key, a
//     value they wrote to the config themselves — recovers that much keystream
//     by XOR. Every other masked value leaked from the same process, at the same
//     offsets, then decrypts for free. One known plaintext unmasks all of them.
//   - Pad reuse. A pad shorter than the secret repeats. XOR two blocks of the
//     same masked value and the keystream cancels, leaving the XOR of two
//     plaintext blocks — structure, and often more, with no known plaintext
//     needed at all.
//
// So the keystream is per-[Value] instead: each one carries a nonce, and its
// keystream is HMAC-SHA-256 over that nonce under a process key, run as a
// counter mode so the stream is as long as the secret and never repeats.
// Recovering one Value's keystream yields the input to a one-way function, not
// the process key, so it says nothing about any other Value; and no block of the
// stream is ever reused, so two blocks of one secret no longer cancel.
//
// The process key is package state, never a field of a [Value]. That placement
// is the whole trick, and it is not an implementation detail: the paths the mask
// defends against dump a Value *structurally*, so a keystream stored next to the
// bytes it masks would be printed alongside them and the two would XOR back to
// the plaintext. A per-Value pad held in the struct would therefore be worse
// than no mask at all.
//
// What remains true, and is not a defect: anything that can read this process's
// memory holds the process key and can unmask everything. That is the line this
// package does not cross, and no arrangement of masking inside a process can.
package secret

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"sync/atomic"
)

// Redacted is written in place of the value by every formatting and marshalling
// method on [Value].
const Redacted = "[REDACTED]"

// ErrRedacted reports an attempt to load the redaction placeholder as if it
// were a secret.
//
// It exists because marshalling is deliberately lossy: a Value marshals to
// [Redacted], so a round trip through JSON or text would otherwise silently
// install the literal string "[REDACTED]" as the secret. Every instance would
// then agree on a well-known value, and CSRF tokens signed with it would verify
// against an attacker's forgeries. Failing the unmarshal turns a silent
// compromise into a startup error.
var ErrRedacted = errors.New("secret: refusing to load the redaction placeholder as a secret")

// Value is a byte secret that does not appear in formatted output.
//
// The zero Value is valid and empty. Value is not comparable with == because it
// holds a slice; use [Value.Equal], which is also the only comparison that runs
// in constant time.
//
// # Every output path is covered
//
// [Value.Format] intercepts every fmt verb, so %v, %s, %q, %x, %d and anything
// else all write [Redacted]. [Value.MarshalJSON] and [Value.MarshalText] cover
// encoding/json and every encoder built on encoding.TextMarshaler.
// [Value.LogValue] covers log/slog. The methods are on the value receiver, not
// the pointer, so a Value printed by value is covered too — a String method on
// a pointer receiver would be skipped for a non-pointer argument, which is the
// most common way this kind of type is written wrong.
//
// # Two paths that no method can cover, and why the bytes are masked
//
// Redaction by method has a floor. Two fmt paths never consult the method table
// at all:
//
//   - **fmt's bad-verb path: %p against a non-pointer, and %w outside
//     fmt.Errorf.** fmt handles %p before it looks for a Formatter, and a
//     struct is not a pointer, so it routes to the bad-verb path; %w reaches
//     the same place because it is only meaningful to fmt.Errorf. That path
//     sets an internal erroring flag which suppresses Formatter and Stringer at
//     *every* nesting depth, then dumps the value structurally. Note that
//     ordinary *unknown* verbs (%h, %z, ...) do reach Formatter and are handled
//     by its default branch; only these two escape it.
//   - **An unexported struct field.** fmt walks fields with reflection, and a
//     value it cannot convert back to an interface is one whose methods it
//     cannot call. So `struct{ token secret.Value }` prints the field's
//     contents; `struct{ Token secret.Value }` prints [Redacted].
//
// Neither is something a type can override — they are properties of fmt and
// reflect. So the defence is not another method: the bytes are stored XOR-masked
// under a keystream derived per Value, and the plaintext exists only inside
// [Value.Bytes]. Both paths above therefore print masked bytes and a nonce,
// neither of which carries information about the secret.
//
// What a structural dump exposes is exactly the two fields below. That is the
// reason the keystream is *derived* rather than stored: a pad held next to the
// bytes it masks would be dumped by the same paths and XOR straight back to the
// plaintext. See the package documentation for the full threat model, including
// why a single process-wide pad was not enough.
//
// This masking is obfuscation of accidental output, not memory protection. The
// process key is in the same address space as the masked bytes, so anything that
// can read process memory — a debugger, a core dump, another goroutine — can
// trivially recover the value. It raises the floor on *printing*, which is the
// threat this package addresses, and nothing else.
//
// TestBadVerbPathsDoNotLeak and TestUnexportedFieldDoesNotLeak pin both paths.
type Value struct {
	// masked holds the secret XOR this Value's keystream, never the plaintext,
	// so that a reflective dump of this struct reveals nothing.
	masked []byte

	// nonce selects this Value's keystream. It is not secret and not a key: on
	// its own it is a counter, and deriving anything from it needs processKey,
	// which no Value holds. Two Values never share one, which is what stops a
	// recovered keystream from unmasking anything but its own Value.
	nonce uint64
}

// blockLen is the width of one keystream block, one HMAC-SHA-256 output.
const blockLen = sha256.Size

// processKey derives every [Value]'s keystream. It is generated once per process
// and deliberately lives here rather than in a Value: the fmt paths the mask
// exists for dump a Value's fields, and a key sitting among those fields would
// be printed next to the bytes it masks.
//
// # A CSPRNG failure panics, and this is the one place that is right
//
// This package otherwise never panics, and a library that aborts its host's
// process is normally doing something indefensible. This is the exception, for
// the same reason the standard library made the same call: as of Go 1.24
// crypto/rand.Read is defined never to fail, and a system entropy source that
// cannot be read crashes the program irrecoverably rather than returning an
// error. Continuing past that point is worse than stopping.
//
// The alternative this replaced was worse than either. It fell back to a fixed
// byte pattern, on the reasoning that a predictable mask still beats no mask.
// It does not. The mask's whole job is to make the two uncoverable fmt paths
// harmless, and it does that only because an observer of the masked bytes cannot
// derive the keystream. Under a publicly derivable key every one of those leaks
// becomes plaintext, in every Value in the process, silently — the reader has no
// way to tell a degraded mask from a working one. That is a fail-open default in
// a library whose stated posture is fail-closed, and it is not defence in depth;
// it is the appearance of it.
//
// So: on the impossible branch, stop. A process that cannot obtain entropy
// cannot generate CSRF secrets or nonces either, and is not one that should be
// serving requests.
var processKey = newProcessKey()

func newProcessKey() []byte {
	k := make([]byte, blockLen)
	if _, err := rand.Read(k); err != nil {
		panic("secret: the system CSPRNG is unavailable: " + err.Error())
	}
	return k
}

// nonceCounter hands out one nonce per non-empty Value.
//
// A counter, not a random draw. Uniqueness is the only property required —
// unpredictability comes from processKey, which a nonce holder does not have —
// and a counter delivers it outright, where random draws only make collisions
// unlikely and can fail at the CSPRNG. Its start is randomized so that a Value
// dumped structurally does not advertise how many secrets the process has
// created.
//
// Unlike [processKey], this one keeps its fallback rather than panicking, and
// the difference is not inconsistency. A failed seed costs a cosmetic property:
// nonces start at zero instead of somewhere arbitrary. Uniqueness, the property
// the security argument rests on, comes from the counter and is unaffected. A
// fallback is fail-open only when it degrades the thing being relied on, and
// this one does not.
var nonceCounter = func() *atomic.Uint64 {
	var c atomic.Uint64
	var seed [8]byte
	if _, err := rand.Read(seed[:]); err == nil {
		c.Store(binary.BigEndian.Uint64(seed[:]))
	}
	return &c
}()

// stream generates the keystream for one nonce, a block at a time.
//
// It is HMAC-SHA-256 in counter mode: block i is HMAC(processKey, nonce || i).
// Counter mode is what removes the pad-reuse failure of a fixed-length mask —
// the stream extends to any length without a block ever recurring — and the HMAC
// is what keeps a recovered block from saying anything about processKey, and so
// about any other Value's stream.
type stream struct {
	mac   hash.Hash
	input [12]byte
	block [blockLen]byte
}

func newStream(nonce uint64) *stream {
	s := &stream{mac: hmac.New(sha256.New, processKey)}
	binary.BigEndian.PutUint64(s.input[:8], nonce)
	return s
}

// next returns the next block of keystream. The slice is reused across calls.
func (s *stream) next(counter uint32) []byte {
	binary.BigEndian.PutUint32(s.input[8:], counter)
	s.mac.Reset()
	s.mac.Write(s.input[:])
	return s.mac.Sum(s.block[:0])
}

// xorKeystream writes src XOR keystream(nonce) into dst, which must be at least
// as long as src. It is its own inverse, so it both masks and unmasks.
func xorKeystream(dst, src []byte, nonce uint64) {
	s := newStream(nonce)
	for off, ctr := 0, uint32(0); off < len(src); off, ctr = off+blockLen, ctr+1 {
		k := s.next(ctr)
		for i := 0; i < blockLen && off+i < len(src); i++ {
			dst[off+i] = src[off+i] ^ k[i]
		}
	}
}

// New returns a Value holding a copy of b.
//
// The copy means the caller may reuse or zero its own slice afterwards without
// affecting the Value, and that a slice retained by the caller cannot be
// mutated into the Value later.
func New(b []byte) Value {
	if len(b) == 0 {
		return Value{}
	}
	v := Value{masked: make([]byte, len(b)), nonce: nonceCounter.Add(1)}
	xorKeystream(v.masked, b, v.nonce)
	return v
}

// Bytes returns a copy of the secret.
//
// This is the only way the real value leaves, which makes every call site a
// place a reviewer can look at. Prefer passing the Value itself and calling
// this as late as possible — ideally at the boundary that genuinely needs raw
// bytes, such as an HMAC key or an encoder.
func (v Value) Bytes() []byte {
	if len(v.masked) == 0 {
		return nil
	}
	out := make([]byte, len(v.masked))
	xorKeystream(out, v.masked, v.nonce)
	return out
}

// Len returns the length of the secret in bytes.
//
// Length is not itself secret — it is already observable from ciphertext sizes
// and from validation errors — and exposing it lets callers enforce a minimum
// length without unwrapping the value.
func (v Value) Len() int { return len(v.masked) }

// IsZero reports whether the Value holds no bytes.
func (v Value) IsZero() bool { return len(v.masked) == 0 }

// Equal reports whether two Values hold the same bytes, in constant time with
// respect to their contents.
//
// Constant time matters wherever the comparison result is observable, which
// includes any comparison that decides an HTTP response: a byte-by-byte
// comparison that returns early leaks the length of the matching prefix, and a
// few thousand requests turn that into the value.
//
// The comparison does leak whether the lengths differ, which subtle's
// ConstantTimeCompare cannot avoid and which is not usefully secret.
//
// # Why it cannot just compare the masked bytes
//
// It used to. Under a single process-wide positional pad, two secrets of equal
// length masked to equal bytes exactly when their plaintexts matched, so
// ConstantTimeCompare over the stored bytes was both correct and free. That
// equivalence was a consequence of the pad being shared — the same property that
// made one known plaintext unmask every other Value in the process — and it went
// away with it. Two Values now carry different keystreams, so equal plaintexts
// mask to unrelated bytes and equal masked bytes would mean nothing.
//
// The replacement does not unmask anything. For each position the four bytes are
// folded together:
//
//	masked_a[i] ^ masked_b[i] ^ keystream_a[i] ^ keystream_b[i]
//
// which is plaintext_a[i] ^ plaintext_b[i] — zero exactly where the secrets
// agree — while neither plaintext is ever assembled. There is no unmasked copy
// to allocate, to leak into a heap dump, or to forget to wipe: the plaintext
// bytes exist only as intermediate values of that expression. That property was
// the reason to fold rather than to call [Value.Bytes] twice and compare.
//
// Constant time survives because nothing in the loop depends on the data. Every
// position is visited, the differences are accumulated with OR instead of being
// branched on, and the single decision is taken at the end over the accumulator.
// The keystreams are generated in the same order and quantity for any two inputs
// of a given length, so their cost carries no information either.
func (v Value) Equal(other Value) bool {
	if len(v.masked) != len(other.masked) {
		// Already leaked by construction, and not usefully secret. Returning
		// early on it is what lets the loop below assume equal lengths.
		return false
	}
	if len(v.masked) == 0 {
		return true
	}

	sa, sb := newStream(v.nonce), newStream(other.nonce)
	var diff byte
	for off, ctr := 0, uint32(0); off < len(v.masked); off, ctr = off+blockLen, ctr+1 {
		ka, kb := sa.next(ctr), sb.next(ctr)
		for i := 0; i < blockLen && off+i < len(v.masked); i++ {
			// The two plaintext bytes appear only inside this expression.
			diff |= v.masked[off+i] ^ ka[i] ^ other.masked[off+i] ^ kb[i]
		}
	}
	return subtle.ConstantTimeByteEq(diff, 0) == 1
}

// String implements fmt.Stringer, returning [Redacted].
//
// Note that the fmt package does not call this: [Value.Format] takes precedence
// over Stringer for every verb. It is kept because code outside fmt calls
// String directly — string concatenation in a hand-written error message, a
// logging façade that type-switches on fmt.Stringer — and those paths must be
// redacted too.
func (v Value) String() string { return Redacted }

// GoString implements fmt.GoStringer, returning a Go-syntax representation with
// the value redacted. It is what %#v prints.
func (v Value) GoString() string { return `secret.Value("` + Redacted + `")` }

// Format implements fmt.Formatter, which is what makes redaction total.
//
// Stringer alone is not enough. fmt consults Stringer only for %v, %s, %q, %x
// and %X; a %d against a struct holding a Value would descend into the fields
// and print the bytes as numbers. Formatter is consulted for every verb, so
// there is no verb left that reveals anything.
//
// %#v writes [Value.GoString]. Every other verb and flag combination, %v
// included, writes [Redacted] — width and precision are ignored, since honouring
// a precision would let a caller extract the value one character at a time.
func (v Value) Format(f fmt.State, verb rune) {
	// fmt.Formatter has no error return, and fmt records write errors on the
	// State itself, so there is nothing here to report or recover from.
	if verb == 'v' && f.Flag('#') {
		_, _ = io.WriteString(f, v.GoString())
		return
	}
	_, _ = io.WriteString(f, Redacted)
}

// LogValue implements slog.LogValuer, so a Value logged through log/slog is
// redacted under every handler, including slog.Any and nested groups.
func (v Value) LogValue() slog.Value { return slog.StringValue(Redacted) }

// MarshalText implements encoding.TextMarshaler, writing [Redacted].
//
// This covers every encoder that consults TextMarshaler rather than
// json.Marshaler, which is most of the ones outside encoding/json.
func (v Value) MarshalText() ([]byte, error) { return []byte(Redacted), nil }

// MarshalJSON implements json.Marshaler, writing [Redacted] as a JSON string.
//
// It is defined even though MarshalText would be enough, so that the redaction
// does not depend on encoding/json's preference order between the two
// interfaces.
func (v Value) MarshalJSON() ([]byte, error) { return json.Marshal(Redacted) }

// UnmarshalText implements encoding.TextUnmarshaler, taking the text as the raw
// bytes of the secret.
//
// Marshalling is lossy on purpose, so this is not its inverse. Text equal to
// [Redacted] returns [ErrRedacted] rather than installing the placeholder as a
// secret — see that error for why silence there would be dangerous.
//
// The text is used as-is. If your secret is binary rather than printable,
// decode it yourself and use [New]; guessing at base64 here would make a secret
// that happens to be valid base64 mean two different things.
func (v *Value) UnmarshalText(text []byte) error {
	if string(text) == Redacted {
		return ErrRedacted
	}
	*v = New(text)
	return nil
}

// UnmarshalJSON implements json.Unmarshaler, taking a JSON string as the raw
// bytes of the secret. A JSON null leaves the Value empty.
//
// As with [Value.UnmarshalText], a string equal to [Redacted] returns
// [ErrRedacted].
func (v *Value) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*v = Value{}
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		// The error deliberately does not quote the offending input: it may be
		// the secret itself, and an unmarshal error is exactly the kind of thing
		// that gets logged.
		return errors.New("secret: expected a JSON string")
	}
	return v.UnmarshalText([]byte(s))
}
