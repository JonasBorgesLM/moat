//go:build integration

package integration

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// newTLSServer starts an HTTPS test server and registers its shutdown.
//
// It is a separate helper so that the reason for TLS is stated in one place:
// the CSRF cookie is Secure and __Host--prefixed, so a plaintext server would
// make a real cookie jar drop it and every assertion downstream would be
// testing the wrong thing.
func newTLSServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	return srv
}
