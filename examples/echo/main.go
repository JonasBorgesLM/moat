// Command echo shows how to use this library with the Echo framework.
//
// Echo has its own handler and middleware types, so it needs a small piece of
// glue. That glue lives here as compiled, CI-tested code rather than as prose
// in a README, because an adapter that has quietly stopped being correct is
// worse than no adapter at all — people copy it and believe it works.
//
// The core library deliberately does not import Echo. Its middleware are plain
// func(http.Handler) http.Handler decorators, and everything framework-specific
// stays in this module, so Echo never appears in the core's go.sum.
package main

import (
	"log"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/JonasBorgesLM/gosecure/csrf"
	"github.com/JonasBorgesLM/gosecure/middleware"
	"github.com/JonasBorgesLM/gosecure/preset"
)

// Adapt converts a standard func(http.Handler) http.Handler into an
// echo.MiddlewareFunc.
//
// The details that matter, each of which is easy to get wrong:
//
//   - **The request is written back into the context** with c.SetRequest.
//     Middleware here attaches values to the request context — the CSRF token,
//     for one — by returning a new *http.Request. Drop that and csrf.Token
//     reports no token in every handler.
//   - **The handler's error is carried back out.** Echo handlers return an
//     error that its error handler renders; swallowing it would turn every
//     handler failure into a silent 200.
//   - **A short-circuiting middleware skips the handler entirely**, so no error
//     is produced and the response the middleware already wrote is the final
//     one. Returning nil in that case is correct: there is nothing left to
//     report.
func Adapt(mw func(http.Handler) http.Handler) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			var handlerErr error

			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Carry context values (such as the CSRF token) into Echo, and
				// point Echo's response at the writer the middleware handed us,
				// so that anything it wrapped stays in the path.
				c.SetRequest(r)
				c.SetResponse(echo.NewResponse(w, c.Echo()))
				handlerErr = next(c)
			})

			mw(h).ServeHTTP(c.Response(), c.Request())
			return handlerErr
		}
	}
}

// AdaptChain converts a whole middleware.Chain into a single
// echo.MiddlewareFunc, preserving the chain's order.
func AdaptChain(chain middleware.Chain) echo.MiddlewareFunc {
	return Adapt(chain.Middleware())
}

func main() {
	secret, err := csrf.GenerateSecret()
	if err != nil {
		log.Fatal(err)
	}

	e, err := newRouter(secret)
	if err != nil {
		log.Fatal(err)
	}

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           e,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	log.Println("listening on", srv.Addr)
	log.Fatal(srv.ListenAndServe())
}

// newRouter is separate from main so the smoke test can drive it.
func newRouter(secret []byte) (*echo.Echo, error) {
	chain, err := preset.API(preset.Config{
		CSRFSecret:      secret,
		RateLimitBurst:  20,
		RateLimitPerSec: 5,
	})
	if err != nil {
		return nil, err
	}

	e := echo.New()
	e.HideBanner = true
	e.HidePort = true

	// One Use call for the whole chain keeps the preset's ordering intact.
	e.Use(AdaptChain(chain))

	e.GET("/token", func(c echo.Context) error {
		token, ok := csrf.Token(c.Request())
		if !ok {
			// If the adapter dropped the request-context assignment, this is
			// where it shows up.
			return c.String(http.StatusInternalServerError, "csrf middleware not reachable")
		}
		return c.String(http.StatusOK, token)
	})

	e.POST("/submit", func(c echo.Context) error {
		return c.String(http.StatusOK, "accepted")
	})

	return e, nil
}
