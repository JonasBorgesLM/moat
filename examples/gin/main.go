// Command gin shows how to use this library with the Gin framework.
//
// Gin has its own handler type, so it needs a small piece of glue. That glue
// lives here as compiled, CI-tested code rather than as prose in a README,
// because an adapter that has quietly stopped being correct is worse than no
// adapter at all — people copy it and believe it works.
//
// The core library deliberately does not import Gin. Its middleware are plain
// func(http.Handler) http.Handler decorators, and everything framework-specific
// stays in this module, so Gin never appears in the core's go.sum.
package main

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/JonasBorgesLM/moat/csrf"
	"github.com/JonasBorgesLM/moat/middleware"
	"github.com/JonasBorgesLM/moat/preset"
	"github.com/JonasBorgesLM/moat/secret"
)

// Adapt converts a standard func(http.Handler) http.Handler into a
// gin.HandlerFunc.
//
// Three details make this correct, and all three are easy to get wrong:
//
//   - **The request is written back into the context.** Middleware in this
//     library attaches values to the request context — the CSRF token, for
//     one — by returning a new *http.Request. Without c.Request = r, that
//     request is discarded and csrf.Token reports no token in every handler,
//     which is the exact failure the two-value return exists to make visible.
//   - **A short-circuiting middleware must abort the Gin chain.** When the
//     middleware rejects a request it never calls next, so c.Next never runs.
//     Without the explicit Abort, Gin would carry on to the remaining handlers
//     after this one returns, and the rejection would have decided nothing.
//   - **The middleware writes through Gin's ResponseWriter**, so status codes
//     and headers it sets are the ones Gin reports.
func Adapt(mw func(http.Handler) http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		reached := false

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			// Carry context values (such as the CSRF token) into Gin.
			c.Request = r
			c.Next()
		})

		mw(next).ServeHTTP(c.Writer, c.Request)

		if !reached {
			// The middleware rejected the request and has already written the
			// response. Stop Gin from running anything else.
			c.Abort()
		}
	}
}

// AdaptChain converts a whole middleware.Chain into a single gin.HandlerFunc,
// preserving the chain's order.
func AdaptChain(chain middleware.Chain) gin.HandlerFunc {
	return Adapt(chain.Middleware())
}

func main() {
	key, err := csrf.GenerateSecret()
	if err != nil {
		log.Fatal(err)
	}

	router, err := newRouter(key)
	if err != nil {
		log.Fatal(err)
	}

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Println("listening on", srv.Addr)
	log.Fatal(srv.ListenAndServe())
}

// newRouter is separate from main so the smoke test can drive it.
func newRouter(key secret.Value) (*gin.Engine, error) {
	chain, err := preset.API(preset.Config{
		DirectlyExposed: true,
		CSRFSecret:      key,
		RateLimitBurst:  20,
		RateLimitPerSec: 5,
	})
	if err != nil {
		return nil, err
	}

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	// One Use call for the whole chain keeps the preset's ordering intact.
	// Registering the middleware individually would work too, but it puts the
	// order back in the hands of whoever edits this file.
	router.Use(AdaptChain(chain))

	router.GET("/token", func(c *gin.Context) {
		token, ok := csrf.Token(c.Request)
		if !ok {
			// If the adapter dropped the request-context assignment, this is
			// where it shows up.
			c.String(http.StatusInternalServerError, "csrf middleware not reachable")
			return
		}
		c.String(http.StatusOK, token)
	})

	router.POST("/submit", func(c *gin.Context) {
		c.String(http.StatusOK, "accepted")
	})

	return router, nil
}
