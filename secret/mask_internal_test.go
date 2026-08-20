package secret

import (
	"bytes"
	"runtime"
	"testing"
)

// The masking tests reach inside the package on purpose. The two properties
// below are statements about the bytes a Value stores — precisely the bytes the
// uncoverable fmt paths print — so they cannot be checked through an API whose
// entire job is to keep those bytes from being observable.

// TestKnownPlaintextDoesNotUnmaskAnotherValue pins the first of the two failures
// that a shared positional pad had.
//
// The scenario is inside the one the mask exists for, not beyond it: the
// adversary has leaked masked bytes, and for one of the leaked values they know
// the plaintext, because they chose it — an API key they registered, a field
// they wrote into the config. XOR of the two recovers that Value's keystream.
//
// Under the old process-wide pad, that keystream was everyone's, and applying it
// to any other leaked value at the same offsets returned that value's plaintext.
// Per-Value derivation is what breaks the transfer.
func TestKnownPlaintextDoesNotUnmaskAnotherValue(t *testing.T) {
	known := []byte("attacker-chosen-value-0123456789abcdef0123456789")
	target := []byte("the-real-signing-secret-do-not-disclose-abcdefgh")
	if len(known) != len(target) {
		t.Fatalf("the test needs equal lengths to line the offsets up: %d vs %d", len(known), len(target))
	}

	attackerValue := New(known)
	victim := New(target)

	// Step one of the attack, which still works and is meant to: the adversary
	// recovers the keystream of the value whose plaintext they hold.
	recovered := make([]byte, len(known))
	for i := range recovered {
		recovered[i] = attackerValue.masked[i] ^ known[i]
	}

	// Step two, which must now fail: reusing it on someone else's masked bytes.
	guess := make([]byte, len(target))
	for i := range guess {
		guess[i] = victim.masked[i] ^ recovered[i]
	}
	if bytes.Equal(guess, target) {
		t.Fatal("a keystream recovered from a known plaintext decrypted a different Value: the keystream is shared across the process")
	}
	// Not merely unequal by a byte or two: it must carry nothing across.
	if matching := countEqual(guess, target); matching > len(target)/4 {
		t.Errorf("the recovered keystream reproduced %d of %d bytes of an unrelated secret", matching, len(target))
	}
}

// TestKeystreamNeverRepeatsWithinAValue pins the second failure.
//
// A fixed-length pad applied by position repeats once the secret outruns it. XOR
// two blocks of such a masked value and the keystream cancels, leaving the XOR
// of two plaintext blocks — structure, with no known plaintext required. The
// sharpest instance is a secret whose blocks are identical: under a repeating
// pad it masks to identical blocks, and the repetition is visible in the dump
// itself.
//
// The secret here is deliberately much longer than one keystream block, and
// longer than the 64-byte pad this replaced, so a regression to either shape is
// caught.
func TestKeystreamNeverRepeatsWithinAValue(t *testing.T) {
	const period = 16
	block := bytes.Repeat([]byte("A"), period)
	plaintext := bytes.Repeat(block, 256/period) // 256 bytes of one repeated block

	v := New(plaintext)
	if !bytes.Equal(v.Bytes(), plaintext) {
		t.Fatal("round trip failed")
	}

	// Every pair of blocks must differ. Equal blocks mean the keystream repeated
	// with that period, and the repetition is what leaks.
	blocks := len(plaintext) / period
	for i := range blocks {
		for j := i + 1; j < blocks; j++ {
			a := v.masked[i*period : (i+1)*period]
			b := v.masked[j*period : (j+1)*period]
			if bytes.Equal(a, b) {
				t.Fatalf("masked blocks %d and %d are identical: the keystream repeats every %d bytes, so XORing two blocks cancels it", i, j, (j-i)*period)
			}
		}
	}
}

// TestEqualPlaintextsMaskDifferently is the other side of per-Value keystreams,
// and the reason [Value.Equal] had to be rewritten: identical secrets no longer
// produce identical stored bytes, so comparing the stored bytes would be wrong.
func TestEqualPlaintextsMaskDifferently(t *testing.T) {
	plaintext := []byte("the-same-secret-in-two-values")
	a, b := New(plaintext), New(plaintext)

	if bytes.Equal(a.masked, b.masked) {
		t.Error("two Values holding the same secret masked to the same bytes: they share a keystream")
	}
	if a.nonce == b.nonce {
		t.Errorf("two Values were issued the same nonce (%d)", a.nonce)
	}
	if !a.Equal(b) {
		t.Error("Equal reported two identical secrets as different")
	}
}

// TestEqualComparesPlaintextNotStoredBytes is the negative control for the
// rewrite of Equal.
//
// The old implementation was subtle.ConstantTimeCompare(v.masked, other.masked),
// which was correct only while every Value shared one positional keystream.
// Restore that line and this test fails on the first assertion, because equal
// secrets under different keystreams have different masked bytes. A version of
// Equal that passes both is one that is not actually reading the plaintext.
func TestEqualComparesPlaintextNotStoredBytes(t *testing.T) {
	same := []byte("identical-secret-material-long-enough-to-span-blocks-0123456789")
	if !New(same).Equal(New(same)) {
		t.Error("Equal is comparing stored bytes: two Values with the same secret compared unequal")
	}

	// And it must still separate secrets that differ in exactly one bit, at a
	// position past the first keystream block so the block loop is exercised.
	other := append([]byte(nil), same...)
	other[blockLen+5] ^= 0x01
	if New(same).Equal(New(other)) {
		t.Error("Equal accepted two secrets differing by one bit")
	}

	// A prefix relationship must not compare equal either.
	if New(same).Equal(New(same[:len(same)-1])) {
		t.Error("Equal accepted a truncated secret")
	}
}

// countEqual reports how many positions hold the same byte in both slices.
func countEqual(a, b []byte) int {
	n := 0
	for i := range a {
		if i < len(b) && a[i] == b[i] {
			n++
		}
	}
	return n
}

// TestEqualDoesNotAllocatePlaintext pins the constraint that shaped the
// implementation of [Value.Equal].
//
// The easy way to compare two Values under per-Value keystreams is
// bytes.Equal(v.Bytes(), other.Bytes()) — but that puts two copies of the
// plaintext on the heap on every call, where a heap dump, a core file or a GC
// that has not yet zeroed the pages can find them. Folding the keystreams into
// the comparison avoids it, and this test is what stops the easy version from
// being reintroduced.
//
// The signal is deterministic rather than timing-based: the folding version
// allocates the same amount for any length, while any version that unmasks into
// buffers allocates in proportion to the secret. Comparing a small secret with a
// large one separates the two by orders of magnitude.
func TestEqualDoesNotAllocatePlaintext(t *testing.T) {
	measure := func(size int) uint64 {
		a, b := New(bytes.Repeat([]byte("x"), size)), New(bytes.Repeat([]byte("x"), size))

		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		for range 1000 {
			if !a.Equal(b) {
				t.Fatal("Equal reported identical secrets as different")
			}
		}
		runtime.ReadMemStats(&after)
		return (after.TotalAlloc - before.TotalAlloc) / 1000
	}

	const small, large = 32, 8192
	smallCost, largeCost := measure(small), measure(large)

	// Any per-call cost that tracks the secret's length means the plaintext (or
	// a buffer the size of it) is being materialized. Allow generous slack for
	// the keystream blocks and the two HMAC states, which are fixed-size.
	if largeCost > smallCost && largeCost-smallCost > large/4 {
		t.Errorf("Equal allocated %d bytes per call at %d bytes of secret against %d at %d: the cost scales with the secret, so a plaintext-sized buffer is reaching the heap",
			largeCost, large, smallCost, small)
	}
}

// TestEqualSeparatesSecretsDifferingAtAnyPosition checks correctness at the
// positions a block-wise fold is most likely to get wrong: the first byte, the
// last byte, and the seams between keystream blocks.
func TestEqualSeparatesSecretsDifferingAtAnyPosition(t *testing.T) {
	base := bytes.Repeat([]byte("secret-material-"), 8) // 128 bytes, four blocks

	positions := []int{0, 1, blockLen - 1, blockLen, blockLen + 1, 2*blockLen - 1, 2 * blockLen, len(base) - 1}
	for _, pos := range positions {
		differing := append([]byte(nil), base...)
		differing[pos] ^= 0x80
		if New(base).Equal(New(differing)) {
			t.Errorf("Equal missed a difference at byte %d of %d", pos, len(base))
		}
	}
	// The unmodified control, so the test above cannot pass by always reporting
	// inequality.
	if !New(base).Equal(New(base)) {
		t.Error("Equal reported identical secrets as different")
	}
}

// TestKeystreamCounterAdvancesPerBlock pins the detail the whole fix for pad
// reuse rests on: the counter fed to the HMAC advances once per keystream block,
// not once per Value.
//
// If it advanced per Value, every block of a Value's stream would be the same 32
// bytes, and any secret longer than one block would be masked under a repeating
// pad — which is consequence (2) of the original finding, restored in full. The
// distinction is one token in the loop header of xorKeystream, so it is worth a
// test that names it rather than leaving it to be inferred.
//
// Masking an all-zero plaintext yields the raw keystream, which is what makes it
// observable here at all.
func TestKeystreamCounterAdvancesPerBlock(t *testing.T) {
	const blocks = 64
	ks := make([]byte, blocks*blockLen)
	xorKeystream(ks, make([]byte, blocks*blockLen), 0xA5A5A5A5)

	seen := make(map[string]int, blocks)
	for i := range blocks {
		block := string(ks[i*blockLen : (i+1)*blockLen])
		if first, dup := seen[block]; dup {
			t.Fatalf("keystream block %d repeats block %d: the counter is not advancing per block, so any secret over %d bytes is masked under a repeating pad",
				i, first, blockLen)
		}
		seen[block] = i
		if bytes.Equal(ks[i*blockLen:(i+1)*blockLen], make([]byte, blockLen)) {
			t.Fatalf("keystream block %d is all zeroes", i)
		}
	}

	// A different nonce must move the whole stream, not just its first block.
	other := make([]byte, blocks*blockLen)
	xorKeystream(other, make([]byte, blocks*blockLen), 0xA5A5A5A6)
	for i := range blocks {
		if bytes.Equal(ks[i*blockLen:(i+1)*blockLen], other[i*blockLen:(i+1)*blockLen]) {
			t.Errorf("block %d is identical under two different nonces", i)
		}
	}
}

// TestEqualLeaksLengthExactlyAsBefore pins the one side channel [Value.Equal]
// documents as accepted, and pins it as *unchanged*.
//
// The previous implementation was subtle.ConstantTimeCompare, whose first act is
// `if len(x) != len(y) { return 0 }` — an immediate, content-independent return.
// That length leak was documented and accepted. The rewrite had to preserve it
// exactly: not narrow it (which would be a behaviour change callers cannot see),
// and above all not widen it into some second decision that depends on length.
//
// The table below is the whole contract. Every equal-length pair is decided by
// content and every unequal-length pair is rejected on length alone, including
// the empty cases, which the old code reached through the same zero-iteration
// loop the new code short-circuits to the same answer.
func TestEqualLeaksLengthExactlyAsBefore(t *testing.T) {
	tests := []struct {
		name string
		a, b []byte
		want bool
	}{
		{"both empty", nil, nil, true},
		{"empty against non-empty", nil, []byte("x"), false},
		{"non-empty against empty", []byte("x"), nil, false},
		{"equal length, equal content", []byte("abcd"), []byte("abcd"), true},
		{"equal length, differing content", []byte("abcd"), []byte("abce"), false},
		{"prefix is not equal", []byte("abcd"), []byte("abc"), false},
		{"superset is not equal", []byte("abc"), []byte("abcd"), false},
		{"same content across a block boundary", bytes.Repeat([]byte("z"), 100), bytes.Repeat([]byte("z"), 100), true},
		{"lengths differ by one past a block boundary", bytes.Repeat([]byte("z"), 100), bytes.Repeat([]byte("z"), 99), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := New(tc.a).Equal(New(tc.b)); got != tc.want {
				t.Errorf("Equal = %v, want %v", got, tc.want)
			}
			// Equality is symmetric, and the length short-circuit must not make
			// it depend on which side is the receiver.
			if got := New(tc.b).Equal(New(tc.a)); got != tc.want {
				t.Errorf("reversed: Equal = %v, want %v", got, tc.want)
			}
		})
	}

	// The zero Value is the case the old code decided inside ConstantTimeCompare
	// rather than before it; it must still compare equal to another zero Value
	// and unequal to anything holding bytes.
	if !(Value{}).Equal(Value{}) {
		t.Error("two zero Values compared unequal")
	}
	if (Value{}).Equal(New([]byte("x"))) {
		t.Error("a zero Value compared equal to a non-empty secret")
	}
}
