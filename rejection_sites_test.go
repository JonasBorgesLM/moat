package moat_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestEveryResponseWritingSiteIsClassified enforces DESIGN.md §3.4 across the
// whole core module: any middleware in this library that can refuse a request
// must let the application replace the response it writes.
//
// # Why this test is at the module root
//
// §3.4 was verified by a manual sweep, recorded as a table, plus one instance
// test per hook. That is the same guard that failed for the 429 (§10.6): it
// proves the state at the moment someone looked, and nothing makes it fail when
// the library grows a new rejection point.
//
// The guard built in response to that, in secureheaders, walked the syntax tree
// — but called parser.ParseDir on one directory, so it proved the property for
// one package. The remedy for "the class was closed at the instance" had itself
// been applied at the instance. Adding an unhooked http.Error to csrf,
// ratelimit, validate or pathguard failed nothing.
//
// So the walk lives here, over every package in the core module. A new site
// fails this test until it is classified below, and classifying a rejection
// point means pointing at the hook that lets a caller replace it.
func TestEveryResponseWritingSiteIsClassified(t *testing.T) {
	// Every call that receives a response writer, keyed as
	// "<package>.<enclosing function> -> <callee>", with what it is.
	//
	// A REJECTION entry must name the option that replaces its response. Any
	// other entry must say why it is not a rejection.
	accounted := map[string]string{
		// csrf
		"csrf.Middleware -> p.reject":             "REJECTION: origin/token failure, and CSPRNG failure. Hook: WithErrorHandler",
		"csrf.Middleware -> p.setCookie":          "issues the cookie; not a rejection",
		"csrf.Middleware -> next.ServeHTTP":       "pass-through",
		"csrf.reject -> http.Error":               "REJECTION default response. Hook: WithErrorHandler",
		"csrf.reject -> p.errorHandler.ServeHTTP": "REJECTION via the caller's handler. Hook: WithErrorHandler",
		"csrf.setCookie -> http.SetCookie":        "header write; not a rejection",
		"csrf.Rotate -> findRecorder":             "inspects whether the response began; writes nothing",
		"csrf.Rotate -> p.setCookie":              "header write; not a rejection",

		// ratelimit
		"ratelimit.Middleware -> l.writeDenied":                 "REJECTION: 429. Hook: WithDeniedHandler",
		"ratelimit.Middleware -> l.writeStoreError":             "REJECTION: 503 store outage / underivable key. Hook: WithStoreErrorHandler",
		"ratelimit.Middleware -> l.writeHeaders":                "publishes limit state; not a rejection",
		"ratelimit.Middleware -> next.ServeHTTP":                "pass-through",
		"ratelimit.Middleware -> w.Header":                      "header write; not a rejection",
		"ratelimit.writeDenied -> http.Error":                   "REJECTION default response. Hook: WithDeniedHandler",
		"ratelimit.writeDenied -> l.denied.ServeHTTP":           "REJECTION via the caller's handler. Hook: WithDeniedHandler",
		"ratelimit.writeStoreError -> http.Error":               "REJECTION default response. Hook: WithStoreErrorHandler",
		"ratelimit.writeStoreError -> l.storeErrored.ServeHTTP": "REJECTION via the caller's handler. Hook: WithStoreErrorHandler",
		"ratelimit.writeHeaders -> w.Header":                    "header write; not a rejection",

		// validate
		"validate.MaxBodyBytes -> cfg.writeTooLarge":           "REJECTION: 413 on a declared over-limit length. Hook: WithMaxBodyErrorHandler",
		"validate.MaxBodyBytes -> http.MaxBytesReader":         "bounds the body; the reader path surfaces in the handler, documented on WithMaxBodyErrorHandler",
		"validate.MaxBodyBytes -> next.ServeHTTP":              "pass-through",
		"validate.RequireContentType -> cfg.writeUnsupported":  "REJECTION: 415. Hook: WithContentTypeErrorHandler",
		"validate.RequireContentType -> next.ServeHTTP":        "pass-through",
		"validate.writeTooLarge -> http.Error":                 "REJECTION default response. Hook: WithMaxBodyErrorHandler",
		"validate.writeTooLarge -> c.tooLarge.ServeHTTP":       "REJECTION via the caller's handler. Hook: WithMaxBodyErrorHandler",
		"validate.writeUnsupported -> http.Error":              "REJECTION default response. Hook: WithContentTypeErrorHandler",
		"validate.writeUnsupported -> c.unsupported.ServeHTTP": "REJECTION via the caller's handler. Hook: WithContentTypeErrorHandler",

		// pathguard
		"pathguard.FileServer -> cfg.writeNotFound":                       "REJECTION: 404, identical for every cause. Hook: WithNotFoundHandler",
		"pathguard.FileServer -> cfg.writeMethodNotAllowed":               "REJECTION: 405. Hook: WithMethodNotAllowedHandler",
		"pathguard.FileServer -> http.ServeContent":                       "serves the file; not a rejection",
		"pathguard.FileServer -> w.Header":                                "header write; not a rejection",
		"pathguard.writeNotFound -> http.Error":                           "REJECTION default response. Hook: WithNotFoundHandler",
		"pathguard.writeNotFound -> c.notFound.ServeHTTP":                 "REJECTION via the caller's handler. Hook: WithNotFoundHandler",
		"pathguard.writeMethodNotAllowed -> http.Error":                   "REJECTION default response. Hook: WithMethodNotAllowedHandler",
		"pathguard.writeMethodNotAllowed -> c.methodNotAllowed.ServeHTTP": "REJECTION via the caller's handler. Hook: WithMethodNotAllowedHandler",

		// secureheaders
		"secureheaders.Middleware -> cfg.writeNonceError":           "REJECTION: CSPRNG failure. Hook: WithNonceErrorHandler",
		"secureheaders.Middleware -> next.ServeHTTP":                "pass-through",
		"secureheaders.Middleware -> w.Header":                      "header write; not a rejection",
		"secureheaders.writeNonceError -> http.Error":               "REJECTION default response. Hook: WithNonceErrorHandler",
		"secureheaders.writeNonceError -> c.nonceErrored.ServeHTTP": "REJECTION via the caller's handler. Hook: WithNonceErrorHandler",
		"secureheaders.NoStore -> w.Header":                         "sets Cache-Control; not a rejection",
		"secureheaders.NoStore -> next.ServeHTTP":                   "pass-through",
		"secureheaders.ClearSiteData -> w.Header":                   "sets Clear-Site-Data; not a rejection",
		"secureheaders.ClearSiteData -> next.ServeHTTP":             "pass-through",
		"csrf.findRecorder -> u.Unwrap":                             "walks the Unwrap chain looking for the recorder; writes nothing",
		"ratelimit.writeHeaders -> h.Set":                           "header write through the header map; not a rejection",
		"secureheaders.Middleware -> h.Set":                         "header write through the header map, on the success path and on the nonce rejection; not a rejection itself",
		"secureheaders.NoStore -> h.Set":                            "header write through the header map; not a rejection",
	}

	found := responseWritingSites(t)
	if len(found) == 0 {
		t.Fatal("the walk found no sites at all; it is not looking where it thinks it is")
	}

	for _, site := range found {
		if _, ok := accounted[site]; !ok {
			t.Errorf("unclassified response-writing site %q.\n"+
				"  If it can refuse a request, DESIGN.md §3.4 requires an option that replaces its response: "+
				"add one, cover it in that package's tests, and list it here naming the hook.\n"+
				"  If it cannot, list it here saying why.", site)
		}
	}
	for site := range accounted {
		if !contains(found, site) {
			t.Errorf("classified site %q no longer exists; drop it so this list keeps meaning something", site)
		}
	}
}

// responseWritingSites parses every package in the core module and returns each
// call that receives an http.ResponseWriter, as an argument or as a receiver.
//
// It tracks aliases, not just the parameter. csrf.Middleware immediately wraps
// its writer (`w := &responseRecorder{ResponseWriter: rw}`) and then uses the
// wrapper, so a walk that followed only the parameter name would report nothing
// for the package with the most rejection points in the library — a blind spot
// exactly where wrapping happens.
func responseWritingSites(t *testing.T) []string {
	t.Helper()

	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	seen := map[string]bool{}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		switch d.Name() {
		case ".git", "doc", "testdata":
			return filepath.SkipDir
		case "examples", "redisstore":
			return filepath.SkipDir // separate modules
		}
		fset := token.NewFileSet()
		pkgs, perr := parser.ParseDir(fset, path, func(fi fs.FileInfo) bool {
			return !strings.HasSuffix(fi.Name(), "_test.go")
		}, 0)
		if perr != nil {
			t.Fatalf("parsing %s: %v", path, perr)
		}
		for name, pkg := range pkgs {
			for _, file := range pkg.Files {
				collectSites(name, file, seen)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func collectSites(pkgName string, file *ast.File, seen map[string]bool) {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			var ft *ast.FuncType
			var body *ast.BlockStmt
			switch v := n.(type) {
			case *ast.FuncDecl:
				ft, body = v.Type, v.Body
			case *ast.FuncLit:
				ft, body = v.Type, v.Body
			default:
				return true
			}
			writers := writerNames(ft, body)
			if len(writers) == 0 || body == nil {
				return true
			}
			ast.Inspect(body, func(c ast.Node) bool {
				call, ok := c.(*ast.CallExpr)
				if !ok {
					return true
				}
				if callTouches(call, writers) {
					seen[pkgName+"."+fn.Name.Name+" -> "+exprName(call.Fun)] = true
				}
				return true
			})
			return true
		})
	}
}

// writerNames returns the identifiers in this scope that hold a response
// writer: the parameter, plus anything assigned from an expression mentioning
// one.
func writerNames(ft *ast.FuncType, body *ast.BlockStmt) map[string]bool {
	names := map[string]bool{}
	if ft == nil || ft.Params == nil {
		return names
	}
	for _, p := range ft.Params.List {
		if exprName(p.Type) == "http.ResponseWriter" {
			for _, n := range p.Names {
				names[n.Name] = true
			}
		}
	}
	if len(names) == 0 || body == nil {
		return names
	}
	// One pass is enough for the shapes that occur here; repeat until stable so
	// a chain of wrappers is followed too.
	for changed := true; changed; {
		changed = false
		ast.Inspect(body, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for i, rhs := range as.Rhs {
				if i >= len(as.Lhs) || !mentions(rhs, names) {
					continue
				}
				if id, ok := as.Lhs[i].(*ast.Ident); ok && !names[id.Name] {
					names[id.Name] = true
					changed = true
				}
			}
			return true
		})
	}
	return names
}

func mentions(e ast.Expr, names map[string]bool) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && names[id.Name] {
			found = true
		}
		return !found
	})
	return found
}

func callTouches(call *ast.CallExpr, writers map[string]bool) bool {
	for _, arg := range call.Args {
		if id, ok := arg.(*ast.Ident); ok && writers[id.Name] {
			return true
		}
	}
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if id, ok := sel.X.(*ast.Ident); ok && writers[id.Name] {
			return true
		}
	}
	return false
}

func exprName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprName(v.X) + "." + v.Sel.Name
	case *ast.CallExpr:
		return exprName(v.Fun) + "()"
	case *ast.StarExpr:
		return "*" + exprName(v.X)
	}
	return "?"
}

func contains(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}
