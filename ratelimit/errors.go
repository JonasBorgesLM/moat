package ratelimit

import (
	"errors"
	"fmt"
)

// ErrNoKey reports that the client could not be identified, so no bucket could
// be selected.
//
// A custom [KeyFunc] should wrap it when it declines to trust a request — for
// example when a forwarded header arrives from a peer that is not the expected
// proxy. The middleware also reports it to [WithOnError] when a KeyFunc returns
// an empty key. Test for it with errors.Is, so that an unidentifiable client
// can be told apart from a store outage in your own error handling.
var ErrNoKey = errors.New("ratelimit: cannot derive a rate-limit key for the request")

// ErrClosed is returned by store operations attempted after Close. It exists so
// that a shutdown race is reported as such rather than as a silent denial.
var ErrClosed = errors.New("ratelimit: store is closed")

// Internal wrappers of ErrNoKey, so that the middleware reports a specific
// reason to OnError while callers can still match on the sentinel.
var (
	errNoRemoteAddr = fmt.Errorf("%w: request has no usable RemoteAddr", ErrNoKey)
	errEmptyKey     = fmt.Errorf("%w: key function returned an empty key", ErrNoKey)
)
