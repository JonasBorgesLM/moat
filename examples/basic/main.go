// Command basic is a runnable net/http server with every middleware in this
// library wired up explicitly.
//
// It exists as compiled, tested code rather than as a snippet in a README,
// because a snippet rots silently and stale advice in a security library is
// worse than no advice. If this stops being correct, CI says so.
//
// Run it:
//
//	CSRF_SECRET=$(go run github.com/JonasBorgesLM/moat/cmd/moat-secret) \
//	  go run ./basic
package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/JonasBorgesLM/moat/csrf"
	"github.com/JonasBorgesLM/moat/middleware"
	"github.com/JonasBorgesLM/moat/pathguard"
	"github.com/JonasBorgesLM/moat/ratelimit"
	"github.com/JonasBorgesLM/moat/sanitize"
	"github.com/JonasBorgesLM/moat/secret"
	"github.com/JonasBorgesLM/moat/secureheaders"
	"github.com/JonasBorgesLM/moat/validate"
)

func main() {
	// Named key, not secret: naming a local after an imported package shadows
	// it for the rest of the scope. See CONTRIBUTING.md's review checklist.
	key, err := loadSecret()
	if err != nil {
		log.Fatal(err)
	}

	handler, cleanup, err := newServer(key, "./public")
	if err != nil {
		log.Fatal(err)
	}
	defer cleanup()

	srv := &http.Server{
		Addr:    ":8080",
		Handler: handler,
		// Timeouts are not this library's job, and net/http has none by
		// default: without them a slow client can hold a connection open
		// indefinitely, which is a denial of service that no middleware here
		// can see, let alone prevent.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Println("listening on", srv.Addr)
	log.Fatal(srv.ListenAndServe())
}

// loadSecret reads the CSRF secret from the environment.
//
// It fails rather than generating one, because a per-process secret means every
// token issued by one instance is rejected by every other, and the resulting
// intermittent 403s look exactly like a bug in the CSRF library.
func loadSecret() (secret.Value, error) {
	raw := os.Getenv("CSRF_SECRET")
	if raw == "" {
		return secret.Value{}, errors.New("CSRF_SECRET is not set; generate one with `go run github.com/JonasBorgesLM/moat/cmd/moat-secret`")
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		// The error deliberately does not echo the offending value back: it is
		// the secret, and a startup error is the first thing to reach a log.
		return secret.Value{}, fmt.Errorf("CSRF_SECRET is not valid base64: %w", err)
	}
	// Wrap at the boundary, so the raw bytes exist only inside this function
	// and everything downstream holds something that cannot be printed.
	return secret.New(decoded), nil
}

// newServer builds the whole handler. It is separate from main so that the
// smoke test can drive it without binding a port.
func newServer(key secret.Value, publicDir string) (http.Handler, func(), error) {
	protector, err := csrf.New(key)
	if err != nil {
		return nil, nil, err
	}

	limiter := ratelimit.New(20, 5,
		ratelimit.WithOnError(func(err error) {
			// The library never logs. This hook is the only way a rate-limit
			// store failure reaches your observability -- without it, a
			// fail-closed limiter in front of a dead store rejects everything
			// with no signal at all.
			log.Printf("ratelimit: %v", err)
		}),
	)

	guard, err := pathguard.New(publicDir)
	if err != nil {
		return nil, nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", showForm)
	mux.HandleFunc("POST /subscribe", subscribe)
	mux.Handle("GET /files/", http.StripPrefix("/files/", guard.FileServer()))

	// Read this top to bottom: it is the order requests traverse the pipeline.
	// Every line's position is load-bearing.
	chain := middleware.New(
		// 1. Response headers, outermost. Cheap, and set on the way in so
		//    that every response carries them -- including the rejections
		//    written by the middleware below. An error response is still a
		//    response: it can be framed, sniffed as a different content
		//    type, or rendered without a CSP exactly as easily as a 200 can,
		//    so there is no ordering reason to put anything ahead of this.
		secureheaders.Middleware(),

		// 2. Reject abusive clients before spending anything else on them.
		limiter.Middleware,

		// 3. Bound the body BEFORE anything can read or parse it. Reversing
		//    this line and the next is a real vulnerability, not a style
		//    preference: CSRF parses form-encoded bodies, and with no bound in
		//    place it would parse one of any size an attacker cared to send.
		validate.MaxBodyBytes(1<<20),

		// 4. CSRF, which may now parse only a bounded body.
		protector.Middleware,
	)

	cleanup := func() {
		_ = limiter.Close()
		_ = guard.Close()
	}
	return chain.Then(mux), cleanup, nil
}

var formTemplate = template.Must(template.New("form").Parse(`<!doctype html>
<title>Subscribe</title>
<form method="POST" action="/subscribe">
  <input type="hidden" name="{{.FieldName}}" value="{{.Token}}">
  <input name="email" type="email" required>
  <input name="name" required>
  <button>Subscribe</button>
</form>`))

func showForm(w http.ResponseWriter, r *http.Request) {
	token, ok := csrf.Token(r)
	if !ok {
		// The two-value form is what makes this detectable. A bare string would
		// render an empty hidden field here, every POST would start failing,
		// and the quickest apparent fix would be to disable CSRF entirely.
		http.Error(w, "csrf middleware is not installed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// html/template escapes contextually. That -- not any sanitizer -- is the
	// actual defense against XSS.
	_ = formTemplate.Execute(w, struct{ FieldName, Token string }{csrf.DefaultFieldName, token})
}

func subscribe(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		// The body limit is enforced during the read, so the error surfaces
		// here rather than in the middleware. Handlers have to check it; that
		// is the one part the middleware cannot do for you.
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}

	email := r.PostFormValue("email")
	name := r.PostFormValue("name")

	// Validate: reject what does not match a known-good shape.
	if err := validate.Validate("email", email,
		validate.Required(),
		validate.MaxLen(254),
		validate.Email(),
	); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := validate.Validate("name", name,
		validate.Required(),
		validate.MaxLen(100),
		validate.NoHTMLTags(),
	); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Sanitize only what is about to be written somewhere line-oriented. This
	// removes terminal escapes and folds the line breaks that would otherwise
	// let the value forge a whole log record. It does not make anything safe
	// to render as HTML; html/template does that.
	//
	// #nosec G706 -- these values are attacker-controlled, which is precisely
	// why they go through sanitize.PlainText first. It removes the control
	// characters and folds the line breaks that a log-injection payload needs;
	// FuzzPlainText asserts that no input can produce output containing one.
	// gosec's taint analysis does not model that.
	log.Printf("subscribed name=%q email=%q", sanitize.PlainText(name), sanitize.PlainText(email))

	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "subscribed\n")
}
