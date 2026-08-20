// Package realip derives a client IP address from a request that arrived
// through one or more reverse proxies.
//
// # Why this package exists
//
// Every forwarding header is written by whoever sent the request. A client can
// put anything it likes in X-Forwarded-For, X-Real-IP or Forwarded, so reading
// one of them without first establishing who the peer is does not identify the
// client — it lets the client choose its own identity. For a rate limiter that
// is total defeat: a fresh header value per request means a fresh bucket per
// request. For an audit log it means attributable actions can be attributed to
// anyone.
//
// The only fact the server actually knows is r.RemoteAddr, the peer of the TCP
// connection. A forwarded header becomes usable exactly when that peer is a
// proxy you operate, because then the header's rightmost entry was appended by
// your own infrastructure rather than supplied by the client.
//
// That reasoning is short to state and easy to get wrong in code, which is why
// it lives here instead of in every consumer's middleware file.
//
// # Right to left, not left to right
//
// A proxy appends the address it received from to the right-hand end of the
// chain. So in
//
//	X-Forwarded-For: 203.0.113.9, 198.51.100.4
//
// the rightmost entry was written by the proxy closest to you and is the most
// trustworthy; the leftmost was written by whoever was furthest away, and if
// the original client sent a value of its own, that value sits at the far left
// untouched.
//
// Reading the leftmost entry is the classic bug, and it hands the client full
// control of the result. A client that sends
//
//	X-Forwarded-For: 1.2.3.4
//
// through one proxy produces the header
//
//	X-Forwarded-For: 1.2.3.4, <real client IP>
//
// because the proxy appended rather than replaced. Left to right yields
// 1.2.3.4 — a value the attacker picked, and can vary per request. Right to
// left skips trusted proxy addresses and stops at <real client IP>, which is
// the first entry the client could not have written.
//
// See doc/DESIGN.md §4.7 for the longer version with a worked bypass.
//
// # What this package will not do
//
// There is no per-request permissive mode. When the peer is not inside the
// trusted set the headers are ignored in full and RemoteAddr is returned, with
// no option to relax that. A configuration flag that says "trust the header
// anyway" is a flag that says "let clients pick their own identity", and
// shipping it would make every other precaution in here decorative.
//
// The one way to reach that outcome is to declare the entire internet your
// proxy set — a trusted range of 0.0.0.0/0 or ::/0. That is not a mode, it is a
// trust configuration, and it means every client is a proxy: X-Forwarded-For is
// then honoured from any peer and a rate-limit key becomes whatever the client
// types. [New] therefore rejects the default route by default with
// [ErrDefaultRouteTrusted]. It can be accepted, but only through
// [InsecureTrustEveryPeer], whose name is the point — see that option.
package realip

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ErrNoTrustedProxies reports that [New] was given no usable CIDR.
//
// An empty trusted set is refused rather than accepted as "trust nothing",
// because the overwhelmingly likely cause is an unset environment variable
// rather than a deliberate choice. Silently degrading to RemoteAddr would leave
// an operator believing their proxy configuration is in effect when it is not.
// If you really want RemoteAddr and nothing else, do not use this package —
// that is what ratelimit.RemoteAddrKey already is.
var ErrNoTrustedProxies = errors.New("realip: no trusted proxy CIDRs configured")

// ErrDefaultRouteTrusted reports that [New] was given the default route,
// 0.0.0.0/0 or ::/0, in its trusted proxy set.
//
// A trusted set is a statement about which peers are *your* infrastructure. The
// default route says every peer is, which makes X-Forwarded-For readable from
// any client and hands each one the ability to choose its own rate-limit key —
// a new identity per request, and the limiter is gone. It is the exact failure
// this package exists to prevent, and it is one line of configuration away from
// an operator who does not know their balancer's range and writes the default
// route to make things work.
//
// Refusing it is the counterpart to [ErrNoTrustedProxies]. It would be
// incoherent to fail loudly on the harmless misconfiguration — an empty set,
// which trusts nobody — while silently accepting the maximally dangerous one.
//
// Only the default route is refused, not merely wide prefixes. A bit-count
// floor would be a guess about topology this package does not have: 10.0.0.0/8
// and fc00::/7 are legitimate proxy ranges and already sit at the wide end, so
// a floor tight enough to add anything over /0 would reject real
// configurations. 0.0.0.0/0 has no legitimate reading.
//
// # What this check does not cover
//
// It is a guard against one accident, not a proof that the trusted set is
// bounded. A set that covers the whole address space in pieces — 0.0.0.0/1 plus
// 128.0.0.0/1 is the obvious spelling, and ::/1 plus 8000::/1 the IPv6 one —
// passes, and trusts exactly as many peers as 0.0.0.0/0 would.
//
// That is deliberate and it is not a gap being papered over. The failure this
// check exists to catch is an operator who does not know their balancer's range
// writing the default route to make things work; splitting it across two lines
// is not something that happens by accident, and anyone who does it has already
// decided to trust everyone. Refusing it would mean deciding how much aggregate
// address space is too much, which is the bit-count floor rejected above, now
// summed over the whole set — the same guess with more arithmetic. So: read a
// passing New as "this set is not the default route", never as "this set has
// been checked for breadth".
//
// If your proxies really are unbounded — a mesh sidecar that has already
// authenticated the peer, a test harness — use [InsecureTrustEveryPeer], which
// says so where a reviewer will see it.
var ErrDefaultRouteTrusted = errors.New("realip: refusing to trust the default route (0.0.0.0/0 or ::/0), which makes every client a trusted proxy; pass realip.InsecureTrustEveryPeer if that is genuinely intended")

// ErrNoRemoteAddr reports that r.RemoteAddr was absent or unparsable, so not
// even the peer could be identified.
var ErrNoRemoteAddr = errors.New("realip: request has no usable RemoteAddr")

// Source names a header that a proxy may use to report the client address.
type Source int

// The supported sources.
const (
	// XForwardedFor is the de facto standard comma-separated chain. It is the
	// default because it is what nearly every proxy actually writes.
	XForwardedFor Source = iota + 1

	// Forwarded is the standardized header from RFC 7239, carrying
	// semicolon-separated parameters per element, of which "for" is read.
	Forwarded

	// XRealIP is a single address, not a chain, written by nginx-style
	// configurations. Because it carries no chain there is nothing to walk:
	// it is taken at face value when the peer is trusted, which makes it only
	// as good as the proxy's willingness to overwrite a client-supplied value.
	XRealIP
)

// String implements fmt.Stringer, naming the header the Source reads.
func (s Source) String() string {
	switch s {
	case XForwardedFor:
		return "X-Forwarded-For"
	case Forwarded:
		return "Forwarded"
	case XRealIP:
		return "X-Real-IP"
	}
	return fmt.Sprintf("realip.Source(%d)", int(s))
}

// header returns the canonical header name a Source reads.
func (s Source) header() string {
	switch s {
	case XForwardedFor:
		return "X-Forwarded-For"
	case Forwarded:
		return "Forwarded"
	case XRealIP:
		return "X-Real-IP"
	}
	return ""
}

// Extractor derives client addresses under a fixed trust configuration.
//
// It is immutable after construction and safe for concurrent use. Create one at
// startup with [New] and share it; the zero Extractor is not usable.
type Extractor struct {
	trusted []netip.Prefix
	sources []Source

	// allowDefaultRoute records an explicit [InsecureTrustEveryPeer]. It is
	// consulted during construction only; nothing at request time reads it.
	allowDefaultRoute bool
}

// Option configures an [Extractor].
type Option func(*Extractor)

// New returns an Extractor that trusts the given CIDRs as proxies.
//
// Each entry is a CIDR in the form accepted by netip.ParsePrefix
// ("10.0.0.0/8", "2001:db8::/32"). A bare address is also accepted and is
// treated as a single-host prefix, since "trust this one load balancer" is a
// common and otherwise awkward-to-spell case.
//
// The trusted set must describe *your proxies*, not your clients. Putting a
// client range in here lets requests from that range choose their own identity.
//
// With no options the Extractor reads [XForwardedFor] only. See [WithSources]
// for why that is a deliberately narrow default.
//
// An empty or entirely unparsable list returns [ErrNoTrustedProxies]. The
// default route, 0.0.0.0/0 or ::/0, returns [ErrDefaultRouteTrusted] unless
// [InsecureTrustEveryPeer] is passed.
func New(trustedCIDRs []string, opts ...Option) (*Extractor, error) {
	e := &Extractor{sources: []Source{XForwardedFor}}

	// Options are applied before the CIDRs are validated, because one of them
	// decides what counts as valid.
	for _, opt := range opts {
		if opt != nil {
			opt(e)
		}
	}

	for _, raw := range trustedCIDRs {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			p = normalizePrefix(p)
			if err := e.checkPrefix(p, raw); err != nil {
				return nil, err
			}
			e.trusted = append(e.trusted, p)
			continue
		}
		// A bare address is a single-host prefix. Accepting it here avoids
		// making an operator write "/32" and "/128" by hand and get the family
		// wrong. A single host can never be the default route, so it needs no
		// check.
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("realip: parsing trusted CIDR %q: %w", raw, err)
		}
		addr = addr.Unmap()
		e.trusted = append(e.trusted, netip.PrefixFrom(addr, addr.BitLen()))
	}

	if len(e.trusted) == 0 {
		return nil, ErrNoTrustedProxies
	}
	return e, nil
}

// checkPrefix refuses a trusted range that is not a trust boundary at all.
//
// Only the default route qualifies: a zero-bit prefix contains every address,
// so trusting it trusts every peer. Normalization has already folded the
// IPv4-in-IPv6 spelling (::ffff:0:0/96) down to 0.0.0.0/0, so both ways of
// writing it land here.
func (e *Extractor) checkPrefix(p netip.Prefix, raw string) error {
	if p.Bits() != 0 || e.allowDefaultRoute {
		return nil
	}
	return fmt.Errorf("%w (from %q)", ErrDefaultRouteTrusted, raw)
}

// InsecureTrustEveryPeer permits the default route, 0.0.0.0/0 or ::/0, in the
// trusted set passed to [New].
//
// Read the name literally: it does not loosen a check, it declares that every
// host that can open a connection to this server is a reverse proxy you
// operate. Forwarding headers are then honoured from every client, so any
// client can name itself anything — including a different identity on every
// request, which reduces a rate limiter keyed on [Extractor.KeyFunc] to
// counting nothing. See [ErrDefaultRouteTrusted].
//
// It exists because a blanket refusal would be a lie about the one deployment
// where it is defensible: a service reachable only through a mesh sidecar or a
// unix socket, where the peer has already been authenticated by something else
// and the address space genuinely is closed. If that is not exactly your
// situation, the option you want is the balancer's real range.
//
// It is deliberately not spelled With... and deliberately not a bool field. It
// should be impossible to read a call site containing it and not notice.
func InsecureTrustEveryPeer() Option {
	return func(e *Extractor) { e.allowDefaultRoute = true }
}

// WithSources sets which headers are consulted, in order of precedence.
//
// # Precedence is "first one present wins", with no fallback
//
// The sources are tried in the order given. The first one that is present on
// the request decides the answer, even if it turns out to yield nothing usable
// — in which case the peer address is returned rather than the next source
// being tried.
//
// The no-fallback rule matters. If an unusable header fell through to the next
// source, an attacker who cannot forge the header your proxy writes could send
// a deliberately broken one of higher precedence and steer the lookup onto a
// header your proxy does not sanitize.
//
// # Why the default is one source
//
// Listing several sources is only safe if your proxy writes *or strips* every
// one of them. Consider a proxy that appends to X-Forwarded-For and ignores
// Forwarded. With both sources enabled and Forwarded taking precedence, a
// client sending
//
//	Forwarded: for=1.2.3.4
//
// gets that header delivered untouched, and it is the only element in its
// chain, so walking right to left stops immediately on an entry the client
// wrote. Right-to-left parsing does not save you here: the protection comes
// from the chain having a trusted suffix, and a header your proxy never touches
// has none.
//
// So enable a source when your proxy owns that header, and not otherwise.
//
// Unknown or duplicated sources are dropped. A call that leaves no valid
// source is ignored, keeping the previous configuration rather than producing
// an Extractor that silently consults nothing.
func WithSources(sources ...Source) Option {
	return func(e *Extractor) {
		seen := make(map[Source]bool, len(sources))
		out := make([]Source, 0, len(sources))
		for _, s := range sources {
			if s.header() == "" || seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
		if len(out) > 0 {
			e.sources = out
		}
	}
}

// Sources returns the configured sources in precedence order.
func (e *Extractor) Sources() []Source {
	return append([]Source(nil), e.sources...)
}

// TrustedPrefixes returns the configured trusted proxy ranges.
func (e *Extractor) TrustedPrefixes() []netip.Prefix {
	return append([]netip.Prefix(nil), e.trusted...)
}

// IsTrusted reports whether addr falls inside the trusted proxy set.
func (e *Extractor) IsTrusted(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return false
	}
	for _, p := range e.trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// ClientIP returns the client address for r.
//
// When the peer is not a trusted proxy, every forwarding header is ignored and
// the peer address is returned. When the peer is trusted, the first configured
// source that is present on the request is walked from right to left and the
// first entry that is not itself a trusted proxy is returned.
//
// The peer address is returned, with a nil error, whenever the headers cannot
// produce a better answer: no source present, an unparsable entry, or a chain
// consisting entirely of untrusted junk. That is not a silent failure — it is
// the true peer, and it is the most specific fact available. Note that a
// trusted proxy which strips the forwarding header entirely will therefore
// collapse all of its clients into its own address; that is a proxy
// misconfiguration, and it shows up as one bucket rather than as a bypass.
//
// The returned address is unmapped, so an IPv4-in-IPv6 peer compares equal to
// the same address seen natively.
//
// It returns [ErrNoRemoteAddr] only when the peer itself cannot be determined.
func (e *Extractor) ClientIP(r *http.Request) (netip.Addr, error) {
	if r == nil {
		return netip.Addr{}, ErrNoRemoteAddr
	}
	peer, err := peerAddr(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, err
	}
	if !e.IsTrusted(peer) {
		// The whole contract of the package. No exception, no override.
		return peer, nil
	}

	for _, src := range e.sources {
		values := r.Header.Values(src.header())
		if len(values) == 0 {
			continue
		}
		// Present: this source decides. Falling through to the next one on
		// failure is what WithSources documents as exploitable.
		if addr, ok := e.fromSource(src, values); ok {
			return addr, nil
		}
		return peer, nil
	}
	return peer, nil
}

// fromSource applies the parsing rule for one source to its raw header values.
func (e *Extractor) fromSource(src Source, values []string) (netip.Addr, bool) {
	switch src {
	case XRealIP:
		// A single address with no chain: there is nothing to walk. Repeated
		// headers are refused rather than guessed between — two proxies
		// disagreeing about the client is not something to pick a winner from.
		if len(values) != 1 {
			return netip.Addr{}, false
		}
		return parseNode(strings.TrimSpace(values[0]))

	case XForwardedFor:
		return e.walkRight(splitList(values), parseNode)

	case Forwarded:
		return e.walkRight(splitList(values), parseForwardedElement)
	}
	return netip.Addr{}, false
}

// walkRight scans a forwarding chain from the rightmost entry to the leftmost
// and returns the first address that is not a trusted proxy.
//
// This is the heart of the package. Iterating the other way returns whatever
// the client put at the head of the chain.
func (e *Extractor) walkRight(entries []string, parse func(string) (netip.Addr, bool)) (netip.Addr, bool) {
	var leftmostTrusted netip.Addr

	for i := len(entries) - 1; i >= 0; i-- {
		addr, ok := parse(entries[i])
		if !ok {
			// An entry that does not parse breaks the chain of custody. Every
			// entry further left is separated from the trusted suffix by
			// something unattributable, so continuing past it would promote a
			// client-written value to "the client". Stop instead.
			return netip.Addr{}, false
		}
		if e.IsTrusted(addr) {
			leftmostTrusted = addr
			continue
		}
		return addr, true
	}

	// Every entry was a proxy we trust, which happens when a trusted host makes
	// the request itself. The leftmost of them is the originator.
	if leftmostTrusted.IsValid() {
		return leftmostTrusted, true
	}
	return netip.Addr{}, false
}

// KeyFunc returns a rate-limit key function backed by this Extractor.
//
// The result is assignable to ratelimit.KeyFunc, so it can be passed straight
// to ratelimit.WithKeyFunc:
//
//	ex, err := realip.New([]string{"10.0.0.0/8"})
//	// ...
//	limiter := ratelimit.New(20, 5, ratelimit.WithKeyFunc(ex.KeyFunc()))
//
// The return type is the bare function type rather than ratelimit.KeyFunc so
// that this package imports nothing outside the standard library.
//
// The key is the unmapped textual address, so one client gets one bucket
// regardless of whether it reached you over IPv4 or as IPv4-in-IPv6. An
// unidentifiable peer produces an error, which the limiter's failure mode then
// handles — deliberately, rather than merging those requests into a shared
// bucket that one attacker could drain for everybody.
func (e *Extractor) KeyFunc() func(*http.Request) (string, error) {
	return func(r *http.Request) (string, error) {
		addr, err := e.ClientIP(r)
		if err != nil {
			return "", err
		}
		return addr.String(), nil
	}
}

// splitList flattens repeated headers and their comma-separated elements into
// one ordered chain.
//
// Repeated headers are equivalent to one header with the values joined by
// commas, and proxies use both spellings, so the two must flatten identically
// or the same chain would parse differently depending on how it was written.
func splitList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

// parseNode parses one X-Forwarded-For entry, which may carry a port.
func parseNode(s string) (netip.Addr, bool) {
	if s == "" {
		return netip.Addr{}, false
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Unmap(), true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap(), true
	}
	// "[2001:db8::1]" with no port is legal in the wild but not to ParseAddr.
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		if addr, err := netip.ParseAddr(s[1 : len(s)-1]); err == nil {
			return addr.Unmap(), true
		}
	}
	return netip.Addr{}, false
}

// parseForwardedElement extracts the "for" node from one RFC 7239 element.
//
// An element looks like `for=192.0.2.60;proto=http;by=203.0.113.43`, and the
// node may be quoted, bracketed, ported, or an obfuscated identifier such as
// `_hidden` or `unknown`. An obfuscated node is not an address and is reported
// as unparsable, which stops the walk rather than skipping over it.
func parseForwardedElement(s string) (netip.Addr, bool) {
	for _, param := range strings.Split(s, ";") {
		key, value, found := strings.Cut(param, "=")
		if !found {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(key), "for") {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
			value = value[1 : len(value)-1]
		}
		return parseNode(strings.TrimSpace(value))
	}
	return netip.Addr{}, false
}

// peerAddr extracts the address from r.RemoteAddr, which the net/http server
// writes as "ip:port" and which a test or a Unix socket may write otherwise.
func peerAddr(remoteAddr string) (netip.Addr, error) {
	s := strings.TrimSpace(remoteAddr)
	if s == "" {
		return netip.Addr{}, ErrNoRemoteAddr
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	addr, err := netip.ParseAddr(strings.Trim(s, "[]"))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%w: %q", ErrNoRemoteAddr, remoteAddr)
	}
	return addr.Unmap(), nil
}

// normalizePrefix rewrites an IPv4-in-IPv6 prefix to its IPv4 form so that
// Contains compares against unmapped addresses consistently.
func normalizePrefix(p netip.Prefix) netip.Prefix {
	addr := p.Addr()
	if !addr.Is4In6() {
		return p.Masked()
	}
	bits := p.Bits() - 96
	if bits < 0 {
		bits = 0
	}
	return netip.PrefixFrom(addr.Unmap(), bits).Masked()
}
