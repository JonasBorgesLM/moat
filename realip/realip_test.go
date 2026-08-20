package realip_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/moat/ratelimit"
	"github.com/JonasBorgesLM/moat/realip"
)

// proxies is the trusted set used by most tests: a private range plus one
// specific IPv6 load balancer.
var proxies = []string{"10.0.0.0/8", "2001:db8::1"}

func mustNew(t *testing.T, opts ...realip.Option) *realip.Extractor {
	t.Helper()
	e, err := realip.New(proxies, opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

// request builds a request with the given peer and headers. Headers are given
// as name/value pairs; a repeated name adds a repeated header rather than
// replacing, so the flattening rules can be tested.
func request(remoteAddr string, headers ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remoteAddr
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Add(headers[i], headers[i+1])
	}
	return r
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name    string
		opts    []realip.Option
		peer    string
		headers []string
		want    string
	}{
		{
			name: "no headers falls back to the peer",
			peer: "203.0.113.7:1234",
			want: "203.0.113.7",
		},
		{
			// The property the whole package exists for.
			name:    "an untrusted peer has its headers ignored entirely",
			peer:    "203.0.113.7:1234",
			headers: []string{"X-Forwarded-For", "1.2.3.4"},
			want:    "203.0.113.7",
		},
		{
			name:    "an untrusted peer cannot forge through any header",
			peer:    "203.0.113.7:1234",
			headers: []string{"X-Forwarded-For", "1.2.3.4", "X-Real-IP", "5.6.7.8", "Forwarded", "for=9.9.9.9"},
			want:    "203.0.113.7",
		},
		{
			name:    "a trusted peer with one hop yields the client",
			peer:    "10.0.0.1:1234",
			headers: []string{"X-Forwarded-For", "203.0.113.9"},
			want:    "203.0.113.9",
		},
		{
			// The bypass this package is built to refuse: the client prepended
			// a value of its own, and the proxy appended the truth to the right.
			name:    "a client-prepended entry is skipped in favour of the rightmost untrusted one",
			peer:    "10.0.0.1:1234",
			headers: []string{"X-Forwarded-For", "1.2.3.4, 203.0.113.9"},
			want:    "203.0.113.9",
		},
		{
			name:    "trusted proxies at the right are walked past",
			peer:    "10.0.0.1:1234",
			headers: []string{"X-Forwarded-For", "1.2.3.4, 203.0.113.9, 10.0.0.5, 10.0.0.6"},
			want:    "203.0.113.9",
		},
		{
			name:    "repeated headers flatten into one chain",
			peer:    "10.0.0.1:1234",
			headers: []string{"X-Forwarded-For", "1.2.3.4", "X-Forwarded-For", "203.0.113.9, 10.0.0.5"},
			want:    "203.0.113.9",
		},
		{
			name:    "a chain of only trusted proxies yields the leftmost",
			peer:    "10.0.0.1:1234",
			headers: []string{"X-Forwarded-For", "10.0.0.9, 10.0.0.5"},
			want:    "10.0.0.9",
		},
		{
			// Chain of custody is broken, so the peer is the honest answer.
			name:    "an unparsable rightmost entry falls back to the peer",
			peer:    "10.0.0.1:1234",
			headers: []string{"X-Forwarded-For", "203.0.113.9, garbage"},
			want:    "10.0.0.1",
		},
		{
			name:    "an unparsable entry mid-chain stops the walk",
			peer:    "10.0.0.1:1234",
			headers: []string{"X-Forwarded-For", "203.0.113.9, garbage, 10.0.0.5"},
			want:    "10.0.0.1",
		},
		{
			name:    "ports on chain entries are tolerated",
			peer:    "10.0.0.1:1234",
			headers: []string{"X-Forwarded-For", "1.2.3.4, 203.0.113.9:9999"},
			want:    "203.0.113.9",
		},
		{
			name:    "IPv4-in-IPv6 is unmapped so one client is one key",
			peer:    "10.0.0.1:1234",
			headers: []string{"X-Forwarded-For", "::ffff:203.0.113.9"},
			want:    "203.0.113.9",
		},
		{
			name:    "a bracketed IPv6 entry parses",
			peer:    "10.0.0.1:1234",
			headers: []string{"X-Forwarded-For", "[2001:db8::99]"},
			want:    "2001:db8::99",
		},
		{
			name:    "a bare trusted address is a single-host prefix",
			peer:    "[2001:db8::1]:1234",
			headers: []string{"X-Forwarded-For", "203.0.113.9"},
			want:    "203.0.113.9",
		},
		{
			name:    "a neighbour of a bare trusted address is not trusted",
			peer:    "[2001:db8::2]:1234",
			headers: []string{"X-Forwarded-For", "203.0.113.9"},
			want:    "2001:db8::2",
		},
		{
			name:    "an unconfigured source is not consulted",
			peer:    "10.0.0.1:1234",
			headers: []string{"Forwarded", "for=203.0.113.9"},
			want:    "10.0.0.1",
		},
		{
			name:    "Forwarded is walked right to left when enabled",
			opts:    []realip.Option{realip.WithSources(realip.Forwarded)},
			peer:    "10.0.0.1:1234",
			headers: []string{"Forwarded", "for=1.2.3.4, for=203.0.113.9;proto=https, for=10.0.0.5"},
			want:    "203.0.113.9",
		},
		{
			name:    "a quoted bracketed IPv6 Forwarded node parses",
			opts:    []realip.Option{realip.WithSources(realip.Forwarded)},
			peer:    "10.0.0.1:1234",
			headers: []string{"Forwarded", `for="[2001:db8::99]:8080"`},
			want:    "2001:db8::99",
		},
		{
			name:    "an obfuscated Forwarded node is not an address",
			opts:    []realip.Option{realip.WithSources(realip.Forwarded)},
			peer:    "10.0.0.1:1234",
			headers: []string{"Forwarded", "for=203.0.113.9, for=_hidden"},
			want:    "10.0.0.1",
		},
		{
			name:    "the for parameter is found regardless of position and case",
			opts:    []realip.Option{realip.WithSources(realip.Forwarded)},
			peer:    "10.0.0.1:1234",
			headers: []string{"Forwarded", "proto=https;FOR=203.0.113.9;by=10.0.0.1"},
			want:    "203.0.113.9",
		},
		{
			name:    "X-Real-IP is taken at face value from a trusted peer",
			opts:    []realip.Option{realip.WithSources(realip.XRealIP)},
			peer:    "10.0.0.1:1234",
			headers: []string{"X-Real-IP", "203.0.113.9"},
			want:    "203.0.113.9",
		},
		{
			name:    "a repeated X-Real-IP is refused rather than guessed between",
			opts:    []realip.Option{realip.WithSources(realip.XRealIP)},
			peer:    "10.0.0.1:1234",
			headers: []string{"X-Real-IP", "203.0.113.9", "X-Real-IP", "1.2.3.4"},
			want:    "10.0.0.1",
		},
		{
			name:    "the first present source wins",
			opts:    []realip.Option{realip.WithSources(realip.Forwarded, realip.XForwardedFor)},
			peer:    "10.0.0.1:1234",
			headers: []string{"Forwarded", "for=203.0.113.9", "X-Forwarded-For", "1.2.3.4"},
			want:    "203.0.113.9",
		},
		{
			name:    "an absent higher-precedence source falls through",
			opts:    []realip.Option{realip.WithSources(realip.Forwarded, realip.XForwardedFor)},
			peer:    "10.0.0.1:1234",
			headers: []string{"X-Forwarded-For", "203.0.113.9"},
			want:    "203.0.113.9",
		},
		{
			// The no-fallback rule: a present-but-broken source does not hand
			// the decision to a header the attacker may control instead.
			name:    "a present but unusable source does not fall through",
			opts:    []realip.Option{realip.WithSources(realip.Forwarded, realip.XForwardedFor)},
			peer:    "10.0.0.1:1234",
			headers: []string{"Forwarded", "for=_hidden", "X-Forwarded-For", "1.2.3.4"},
			want:    "10.0.0.1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := mustNew(t, tc.opts...)
			got, err := e.ClientIP(request(tc.peer, tc.headers...))
			if err != nil {
				t.Fatalf("ClientIP: %v", err)
			}
			if got.String() != tc.want {
				t.Errorf("ClientIP = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestNewRejectsAnEmptyTrustedSet(t *testing.T) {
	for _, in := range [][]string{nil, {}, {"", "   "}} {
		if _, err := realip.New(in); !errors.Is(err, realip.ErrNoTrustedProxies) {
			t.Errorf("New(%q) error = %v, want ErrNoTrustedProxies", in, err)
		}
	}
}

func TestNewRejectsAMalformedCIDR(t *testing.T) {
	if _, err := realip.New([]string{"10.0.0.0/8", "not-a-cidr"}); err == nil {
		t.Fatal("New accepted a malformed CIDR")
	}
}

func TestClientIPReportsAnUnusablePeer(t *testing.T) {
	e := mustNew(t)
	for _, peer := range []string{"", "   ", "@", "not-an-ip:80"} {
		_, err := e.ClientIP(request(peer))
		if !errors.Is(err, realip.ErrNoRemoteAddr) {
			t.Errorf("ClientIP(peer=%q) error = %v, want ErrNoRemoteAddr", peer, err)
		}
	}
}

func TestIsTrusted(t *testing.T) {
	e := mustNew(t)
	tests := map[string]bool{
		"10.1.2.3":        true,
		"::ffff:10.1.2.3": true, // the same host, seen as IPv4-in-IPv6
		"2001:db8::1":     true,
		"2001:db8::2":     false,
		"203.0.113.9":     false,
	}
	for in, want := range tests {
		addr := netip.MustParseAddr(in)
		if got := e.IsTrusted(addr); got != want {
			t.Errorf("IsTrusted(%s) = %v, want %v", in, got, want)
		}
	}
}

// TestKeyFuncIsAssignableToRateLimit pins the interop that is the point of the
// adapter: the returned function must satisfy ratelimit.KeyFunc without this
// package importing ratelimit.
func TestKeyFuncIsAssignableToRateLimit(t *testing.T) {
	e := mustNew(t)

	var kf ratelimit.KeyFunc = e.KeyFunc()
	limiter := ratelimit.New(1, 0, ratelimit.WithKeyFunc(kf))
	defer limiter.Close()

	key, err := kf(request("10.0.0.1:1234", "X-Forwarded-For", "1.2.3.4, 203.0.113.9"))
	if err != nil {
		t.Fatalf("KeyFunc: %v", err)
	}
	if key != "203.0.113.9" {
		t.Errorf("key = %q, want %q", key, "203.0.113.9")
	}

	// And the limiter really does bucket by it: one request from this client
	// exhausts a burst of one, while a different client still gets through.
	first := httptest.NewRecorder()
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	limiter.Middleware(ok).ServeHTTP(first, request("10.0.0.1:1234", "X-Forwarded-For", "203.0.113.9"))
	if first.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", first.Code)
	}

	second := httptest.NewRecorder()
	limiter.Middleware(ok).ServeHTTP(second, request("10.0.0.1:1234", "X-Forwarded-For", "203.0.113.9"))
	if second.Code != http.StatusTooManyRequests {
		t.Errorf("second request from the same client status = %d, want 429", second.Code)
	}

	other := httptest.NewRecorder()
	limiter.Middleware(ok).ServeHTTP(other, request("10.0.0.1:1234", "X-Forwarded-For", "198.51.100.4"))
	if other.Code != http.StatusOK {
		t.Errorf("request from a different client status = %d, want 200", other.Code)
	}
}

// TestKeyFuncCannotBeSteeredByAnUntrustedPeer is the tabletop version of the
// fuzz property below: whatever headers an untrusted peer sends, the key is its
// own address, so it cannot mint a fresh bucket per request.
func TestKeyFuncCannotBeSteeredByAnUntrustedPeer(t *testing.T) {
	kf := mustNew(t, realip.WithSources(realip.XForwardedFor, realip.Forwarded, realip.XRealIP)).KeyFunc()

	forged := []string{"1.2.3.4", "9.9.9.9, 8.8.8.8", "203.0.113.1", "10.0.0.1", ""}
	for _, v := range forged {
		key, err := kf(request("198.51.100.23:4444",
			"X-Forwarded-For", v,
			"X-Real-IP", v,
			"Forwarded", "for="+v,
		))
		if err != nil {
			t.Fatalf("KeyFunc: %v", err)
		}
		if key != "198.51.100.23" {
			t.Errorf("forged %q produced key %q, want the peer address", v, key)
		}
	}
}

// FuzzForgedHeaders asserts the two properties that make this package worth
// having. They are separate on purpose: only the second one distinguishes a
// right-to-left walk from a left-to-right one.
//
// Property 1 -- an untrusted peer never steers the result. Whatever it sends,
// the answer is its own address. Note that this property alone does NOT test
// the walk direction: when the peer is untrusted the headers are never read at
// all, so a left-to-right implementation satisfies it just as well.
//
// Property 2 -- a trusted proxy's appended entry wins. The chain is built the
// way a real proxy builds it: arbitrary client-supplied junk, then the address
// the proxy observed appended on the right. The result must be the appended
// address. A left-to-right implementation returns the client's junk instead and
// fails here, which is what makes this property the real test.
func FuzzForgedHeaders(f *testing.F) {
	seeds := []string{
		"",
		"1.2.3.4",
		"1.2.3.4, 5.6.7.8",
		"10.0.0.1",
		"10.0.0.1, 10.0.0.2",
		"::ffff:1.2.3.4",
		"[2001:db8::99]:443",
		"for=1.2.3.4",
		"garbage",
		"unknown",
		"_hidden",
		",,,",
		"1.2.3.4,",
		strings.Repeat("10.0.0.1, ", 40) + "1.2.3.4",
		"1.2.3.4:80, 5.6.7.8:90",
		"  1.2.3.4  ,  5.6.7.8  ",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	e, err := realip.New([]string{"10.0.0.0/8"}, realip.WithSources(
		realip.XForwardedFor, realip.Forwarded, realip.XRealIP,
	))
	if err != nil {
		f.Fatalf("New: %v", err)
	}

	// The address a real proxy would append: outside the trusted range, so it
	// is a legitimate stopping point for the walk.
	const observed = "203.0.113.77"

	f.Fuzz(func(t *testing.T, forged string) {
		// Header values cannot carry newlines; net/http would reject them at
		// the wire and Header.Add would produce something unrepresentative.
		if strings.ContainsAny(forged, "\r\n\x00") {
			t.Skip()
		}

		// Property 1: untrusted peer, arbitrary forged headers.
		untrusted := request("198.51.100.23:4444",
			"X-Forwarded-For", forged,
			"Forwarded", forged,
			"X-Real-IP", forged,
		)
		got, err := e.ClientIP(untrusted)
		if err != nil {
			t.Fatalf("ClientIP(untrusted peer): %v", err)
		}
		if got.String() != "198.51.100.23" {
			t.Fatalf("an untrusted peer steered the result to %s with headers %q", got, forged)
		}

		// Property 2: trusted peer, forged prefix, proxy-appended suffix.
		// This is the one that pins the walk direction.
		chain := observed
		if forged != "" {
			chain = forged + ", " + observed
		}
		trusted := request("10.0.0.1:1234", "X-Forwarded-For", chain)
		got, err = e.ClientIP(trusted)
		if err != nil {
			t.Fatalf("ClientIP(trusted peer): %v", err)
		}
		// The forged prefix may itself be unparsable, which legitimately breaks
		// the chain of custody and yields the peer. What must never happen is
		// the result being an address the client chose.
		if got.String() != observed && got.String() != "10.0.0.1" {
			t.Fatalf("client-controlled value won: ClientIP = %s with chain %q, want %s or the peer",
				got, chain, observed)
		}
	})
}

// TestNewRejectsTheDefaultRoute pins M-2: a trusted set containing 0.0.0.0/0 or
// ::/0 makes every client a trusted proxy, which is the failure the package
// exists to prevent. It is refused rather than accepted in silence.
func TestNewRejectsTheDefaultRoute(t *testing.T) {
	// Every spelling that normalizes to a zero-bit prefix, alone and mixed in
	// with a legitimate range so that a set which "looks configured" is not a
	// way past the check.
	cases := [][]string{
		{"0.0.0.0/0"},
		{"::/0"},
		{"10.0.0.0/8", "0.0.0.0/0"},
		{"::/0", "2001:db8::1"},
		{"::ffff:0:0/96"}, // the IPv4-in-IPv6 spelling of 0.0.0.0/0
	}
	for _, in := range cases {
		t.Run(strings.Join(in, ","), func(t *testing.T) {
			e, err := realip.New(in)
			if !errors.Is(err, realip.ErrDefaultRouteTrusted) {
				t.Fatalf("New(%q) error = %v, want ErrDefaultRouteTrusted", in, err)
			}
			if e != nil {
				t.Errorf("New(%q) returned a non-nil Extractor alongside its error", in)
			}
		})
	}
}

// TestInsecureTrustEveryPeerIsTheOnlyWayIn pins the opt-out: the dangerous
// configuration remains reachable, but only by naming it.
func TestInsecureTrustEveryPeerIsTheOnlyWayIn(t *testing.T) {
	// netip.Prefix.Contains is family-matched, so each default route covers
	// only its own family; the peer is chosen to match.
	for _, tc := range []struct{ cidr, peer string }{
		{"0.0.0.0/0", "203.0.113.7:1234"},
		{"::/0", "[2001:db8:dead::7]:1234"},
	} {
		e, err := realip.New([]string{tc.cidr}, realip.InsecureTrustEveryPeer())
		if err != nil {
			t.Fatalf("New(%q, InsecureTrustEveryPeer): %v", tc.cidr, err)
		}
		// And it really does what it says: an arbitrary internet peer is now a
		// trusted proxy, so its header is believed.
		got, err := e.ClientIP(request(tc.peer, "X-Forwarded-For", "1.2.3.4"))
		if err != nil {
			t.Fatalf("ClientIP: %v", err)
		}
		if got.String() != "1.2.3.4" {
			t.Errorf("with %q trusted, ClientIP(peer=%s) = %s, want the header value 1.2.3.4", tc.cidr, tc.peer, got)
		}
	}
}

// TestNewAcceptsRealBalancerRangesWithoutOptions is the false-positive guard:
// the check must cost an ordinary operator nothing. These are the prefixes that
// actually appear in trusted-proxy configuration, including the widest ones
// (a /8 for RFC1918 space, a /7 for IPv6 ULA) that a bit-count floor would have
// had to reject to be worth having.
func TestNewAcceptsRealBalancerRangesWithoutOptions(t *testing.T) {
	for _, in := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"172.31.0.0/16", // an AWS VPC CIDR
		"103.21.244.0/22",
		"fc00::/7", // IPv6 unique local
		"2001:db8::/32",
		"2001:db8::1", // a single balancer, bare
	} {
		e, err := realip.New([]string{in})
		if err != nil {
			t.Errorf("New(%q) = %v, want no error", in, err)
			continue
		}
		if len(e.TrustedPrefixes()) != 1 {
			t.Errorf("New(%q) tracked %d prefixes, want 1", in, len(e.TrustedPrefixes()))
		}
	}
}
