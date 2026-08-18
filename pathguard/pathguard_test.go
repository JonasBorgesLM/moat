package pathguard_test

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/moat/pathguard"
)

// fixture builds a tree that contains every shape the guard has to defend
// against, and returns the root that a Guard is opened on.
//
//	base/
//	  secret.txt              <- outside the root
//	  www-evil/secret.txt     <- sibling sharing the root's string prefix
//	  www/                    <- the root
//	    index.txt
//	    sub/nested.txt
//	    sub/                  <- a directory, for directory-request cases
//	    .env                  <- a dotfile
//	    .git/config           <- a dot directory
//	    escape -> ../secret.txt          (symlink out of the root)
//	    escape-dir -> ../www-evil        (symlink to the sibling)
//	    inside -> sub/nested.txt         (relative symlink within the root)
//	    inside-abs -> <abs>/sub/nested.txt  (absolute symlink within the root)
func fixture(t *testing.T) (root string) {
	t.Helper()
	base := t.TempDir()

	root = filepath.Join(base, "www")
	mkdirAll(t, filepath.Join(root, "sub"))
	mkdirAll(t, filepath.Join(root, ".git"))
	mkdirAll(t, filepath.Join(base, "www-evil"))

	writeFile(t, filepath.Join(base, "secret.txt"), "root-level secret")
	writeFile(t, filepath.Join(base, "www-evil", "secret.txt"), "sibling secret")
	writeFile(t, filepath.Join(root, "index.txt"), "index")
	writeFile(t, filepath.Join(root, "sub", "nested.txt"), "nested")
	writeFile(t, filepath.Join(root, ".env"), "SECRET_KEY=hunter2")
	writeFile(t, filepath.Join(root, ".git", "config"), "[core]")

	symlink(t, filepath.Join(base, "secret.txt"), filepath.Join(root, "escape"))
	symlink(t, filepath.Join(base, "www-evil"), filepath.Join(root, "escape-dir"))
	// A relative symlink that stays inside the root is legitimate and is
	// followed. An absolute one is refused by os.Root even though its target is
	// inside -- see the case below.
	symlink(t, filepath.Join("sub", "nested.txt"), filepath.Join(root, "inside"))
	symlink(t, filepath.Join(root, "sub", "nested.txt"), filepath.Join(root, "inside-abs"))

	return root
}

func mkdirAll(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// symlink creates a symlink, skipping the test where the platform will not
// allow one (unprivileged Windows) rather than reporting a spurious failure.
func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}
}

func newGuard(t *testing.T) *pathguard.Guard {
	t.Helper()
	g, err := pathguard.New(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	return g
}

func TestNew(t *testing.T) {
	base := t.TempDir()
	writeFile(t, filepath.Join(base, "file.txt"), "x")

	tests := []struct {
		name    string
		dir     string
		wantErr bool
	}{
		{"an existing directory", base, false},
		{"a missing directory is an error, not created on demand", filepath.Join(base, "nope"), true},
		{"a file is not a directory", filepath.Join(base, "file.txt"), true},
		{"an empty path", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g, err := pathguard.New(tc.dir)
			if (err != nil) != tc.wantErr {
				t.Fatalf("New(%q) error = %v, wantErr = %v", tc.dir, err, tc.wantErr)
			}
			if err == nil {
				defer g.Close()
				if !filepath.IsAbs(g.Root()) {
					t.Errorf("Root() = %q, want an absolute path", g.Root())
				}
			}
		})
	}
}

// TestNewDoesNotCreateTheRoot pins the documented decision: a typo in a config
// file must surface as an error, not as a silently created empty tree.
func TestNewDoesNotCreateTheRoot(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "not-there")
	if _, err := pathguard.New(missing); err == nil {
		t.Fatal("New succeeded for a missing directory")
	}
	if _, err := os.Stat(missing); !errors.Is(err, fs.ErrNotExist) {
		t.Error("New created the missing root directory")
	}
}

func TestOpenAndResolve(t *testing.T) {
	g := newGuard(t)
	base := filepath.Dir(g.Root())

	tests := []struct {
		name string
		path string
		// want is the file content when the path is expected to resolve.
		want string
		// wantErr is the sentinel expected on rejection, or nil to accept any.
		wantErr error
		ok      bool
	}{
		// Legitimate access
		{name: "a file at the root", path: "index.txt", want: "index", ok: true},
		{name: "a nested file", path: "sub/nested.txt", want: "nested", ok: true},
		{name: "a redundant current-directory element", path: "./index.txt", want: "index", ok: true},
		{name: "an interior traversal that stays inside", path: "sub/../index.txt", want: "index", ok: true},
		{name: "a relative symlink pointing within the root is followed", path: "inside", want: "nested", ok: true},
		{name: "an absolute path genuinely inside the root", path: filepath.Join(base, "www", "index.txt"), want: "index", ok: true},

		// Traversal
		{name: "a parent traversal", path: "../secret.txt", wantErr: pathguard.ErrOutsideRoot},
		{name: "a deep parent traversal", path: "../../../../etc/passwd", wantErr: pathguard.ErrOutsideRoot},
		{name: "traversal buried mid-path", path: "sub/../../secret.txt", wantErr: pathguard.ErrOutsideRoot},
		{name: "a bare parent reference", path: "..", wantErr: pathguard.ErrOutsideRoot},

		// Absolute paths outside
		{name: "an absolute path outside the root", path: filepath.Join(base, "secret.txt"), wantErr: pathguard.ErrOutsideRoot},
		{name: "an absolute system path", path: "/etc/passwd", wantErr: pathguard.ErrOutsideRoot},

		// The prefix trap: /base/www-evil shares a string prefix with /base/www.
		{name: "a sibling directory sharing the root's prefix", path: filepath.Join(base, "www-evil", "secret.txt"), wantErr: pathguard.ErrOutsideRoot},
		{name: "reaching the prefix-sharing sibling by traversal", path: "../www-evil/secret.txt", wantErr: pathguard.ErrOutsideRoot},

		// Symlinks out of the root
		{name: "a symlink pointing outside the root", path: "escape"},
		{name: "a file under a symlinked directory outside the root", path: "escape-dir/secret.txt"},

		// Malformed
		{name: "an empty path", path: "", wantErr: pathguard.ErrInvalidPath},
		{name: "a NUL byte", path: "index.txt\x00.png", wantErr: pathguard.ErrInvalidPath},

		// os.Root refuses every absolute symlink, including one whose target is
		// inside the root. Asserted so the documented behavior stays true.
		{name: "an absolute symlink is refused even pointing inside the root", path: "inside-abs"},

		// Missing
		{name: "a file that does not exist", path: "nope.txt"},
	}

	for _, tc := range tests {
		t.Run("Open/"+tc.name, func(t *testing.T) {
			f, err := g.Open(tc.path)
			if tc.ok {
				if err != nil {
					t.Fatalf("Open(%q) error = %v, want success", tc.path, err)
				}
				defer f.Close()
				got := make([]byte, 64)
				n, _ := f.Read(got)
				if string(got[:n]) != tc.want {
					t.Errorf("content = %q, want %q", got[:n], tc.want)
				}
				return
			}
			if err == nil {
				_ = f.Close()
				t.Fatalf("Open(%q) succeeded; it must be rejected", tc.path)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("Open(%q) error = %v, want one wrapping %v", tc.path, err, tc.wantErr)
			}
		})

		t.Run("Resolve/"+tc.name, func(t *testing.T) {
			got, err := g.Resolve(tc.path)
			if tc.ok {
				if err != nil {
					t.Fatalf("Resolve(%q) error = %v, want success", tc.path, err)
				}
				assertInsideRoot(t, g.Root(), got)
				return
			}
			if err == nil {
				t.Fatalf("Resolve(%q) = %q, want an error", tc.path, got)
			}
			if got != "" {
				t.Errorf("Resolve(%q) returned %q alongside an error; it must return an empty path", tc.path, got)
			}
		})
	}
}

// assertInsideRoot checks containment the way the package documents it: with
// filepath.Rel, never a string prefix.
func assertInsideRoot(t *testing.T, root, p string) {
	t.Helper()
	if !filepath.IsAbs(p) {
		t.Fatalf("%q is not absolute", p)
	}
	rel, err := filepath.Rel(root, p)
	if err != nil {
		t.Fatalf("Rel(%q, %q) failed: %v", root, p, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		t.Fatalf("%q escaped the root %q (relative path %q)", p, root, rel)
	}
}

// TestSymlinkEscapeIsRejected is the case a resolve-then-open implementation
// gets wrong, called out on its own because it is the reason this package is
// built on os.Root.
func TestSymlinkEscapeIsRejected(t *testing.T) {
	g := newGuard(t)

	// The symlink target really does exist and really does hold the secret, so
	// a failure here is containment working, not a missing file.
	outside := filepath.Join(filepath.Dir(g.Root()), "secret.txt")
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("fixture is wrong: %v", err)
	}

	for _, name := range []string{"escape", "escape-dir/secret.txt"} {
		if f, err := g.Open(name); err == nil {
			_ = f.Close()
			t.Errorf("Open(%q) followed a symlink out of the root", name)
		}
		if p, err := g.Resolve(name); err == nil {
			t.Errorf("Resolve(%q) = %q, want an error", name, p)
		}
	}
}

func TestResolveNew(t *testing.T) {
	g := newGuard(t)
	base := filepath.Dir(g.Root())

	tests := []struct {
		name string
		path string
		ok   bool
	}{
		{"a new file at the root", "upload.bin", true},
		{"a new file in an existing subdirectory", "sub/upload.bin", true},
		{"an existing file is also accepted", "index.txt", true},
		{"an absolute path inside the root", filepath.Join(base, "www", "sub", "u.bin"), true},

		{"a missing parent directory", "nope/upload.bin", false},
		{"a parent that is a file, not a directory", "index.txt/upload.bin", false},
		{"traversal out of the root", "../upload.bin", false},
		{"an absolute path outside the root", filepath.Join(base, "upload.bin"), false},
		{"the prefix-sharing sibling", filepath.Join(base, "www-evil", "upload.bin"), false},
		{"a parent reached through an escaping symlink", "escape-dir/upload.bin", false},
		{"the root itself", ".", false},
		{"an empty path", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := g.ResolveNew(tc.path)
			if tc.ok {
				if err != nil {
					t.Fatalf("ResolveNew(%q) error = %v, want success", tc.path, err)
				}
				assertInsideRoot(t, g.Root(), got)
				return
			}
			if err == nil {
				t.Fatalf("ResolveNew(%q) = %q, want an error", tc.path, got)
			}
		})
	}
}

// TestCreateStaysInsideTheRoot covers the upload path: a destination that is a
// symlink out of the root must not redirect the write.
func TestCreateStaysInsideTheRoot(t *testing.T) {
	g := newGuard(t)
	outside := filepath.Join(filepath.Dir(g.Root()), "secret.txt")

	if f, err := g.Create("escape"); err == nil {
		_ = f.Close()
		t.Error("Create followed a symlink out of the root")
	}
	// #nosec G304 -- outside is a path this test built itself, and
	// reading it back is how the test proves the write was contained.
	if content, err := os.ReadFile(outside); err != nil || string(content) != "root-level secret" {
		t.Errorf("the file outside the root was modified: %q, %v", content, err)
	}

	// A legitimate create still works, and lands where it should.
	f, err := g.Create("sub/upload.bin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := f.WriteString("payload"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	if content, err := os.ReadFile(filepath.Join(g.Root(), "sub", "upload.bin")); err != nil || string(content) != "payload" {
		t.Errorf("created file = %q, %v", content, err)
	}
}

func TestStat(t *testing.T) {
	g := newGuard(t)

	fi, err := g.Stat("index.txt")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.IsDir() || fi.Size() != int64(len("index")) {
		t.Errorf("Stat returned %+v", fi)
	}
	if _, err := g.Stat("../secret.txt"); !errors.Is(err, pathguard.ErrOutsideRoot) {
		t.Errorf("Stat traversal error = %v, want ErrOutsideRoot", err)
	}
}

func TestClosedGuard(t *testing.T) {
	g, err := pathguard.New(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	if err := g.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if f, err := g.Open("index.txt"); err == nil {
		_ = f.Close()
		t.Error("Open succeeded on a closed guard")
	}
}

func TestFileServer(t *testing.T) {
	g := newGuard(t)
	srv := g.FileServer()

	tests := []struct {
		name       string
		method     string
		target     string
		wantStatus int
		wantBody   string
	}{
		{"a file at the root", http.MethodGet, "/index.txt", http.StatusOK, "index"},
		{"a nested file", http.MethodGet, "/sub/nested.txt", http.StatusOK, "nested"},
		{"a relative symlink within the root", http.MethodGet, "/inside", http.StatusOK, "nested"},
		{"an absolute symlink is refused", http.MethodGet, "/inside-abs", http.StatusNotFound, ""},
		{"HEAD is allowed", http.MethodHead, "/index.txt", http.StatusOK, ""},

		// Traversal, in the encodings a client can actually send.
		{"a parent traversal", http.MethodGet, "/../secret.txt", http.StatusNotFound, ""},
		{"a deep traversal", http.MethodGet, "/../../../../etc/passwd", http.StatusNotFound, ""},
		{"traversal buried mid-path", http.MethodGet, "/sub/../../secret.txt", http.StatusNotFound, ""},
		{"percent-encoded traversal", http.MethodGet, "/%2e%2e/secret.txt", http.StatusNotFound, ""},
		{"double percent-encoded traversal", http.MethodGet, "/%252e%252e/secret.txt", http.StatusNotFound, ""},
		{"the prefix-sharing sibling", http.MethodGet, "/../www-evil/secret.txt", http.StatusNotFound, ""},

		// Symlinks out of the root.
		{"a symlink out of the root", http.MethodGet, "/escape", http.StatusNotFound, ""},
		{"a file under an escaping symlinked directory", http.MethodGet, "/escape-dir/secret.txt", http.StatusNotFound, ""},

		// Directories are never listed.
		{"the root directory", http.MethodGet, "/", http.StatusNotFound, ""},
		{"a subdirectory", http.MethodGet, "/sub", http.StatusNotFound, ""},
		{"a subdirectory with a trailing slash", http.MethodGet, "/sub/", http.StatusNotFound, ""},

		// Dot paths are refused outright.
		{"a dotfile", http.MethodGet, "/.env", http.StatusNotFound, ""},
		{"a file inside a dot directory", http.MethodGet, "/.git/config", http.StatusNotFound, ""},

		// Missing.
		{"a file that does not exist", http.MethodGet, "/nope.txt", http.StatusNotFound, ""},

		// Methods.
		{"POST is not allowed", http.MethodPost, "/index.txt", http.StatusMethodNotAllowed, ""},
		{"DELETE is not allowed", http.MethodDelete, "/index.txt", http.StatusMethodNotAllowed, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.target, nil))

			if rec.Code != tc.wantStatus {
				t.Fatalf("%s %s: status = %d, want %d (body %q)", tc.method, tc.target, rec.Code, tc.wantStatus, rec.Body)
			}
			if tc.wantBody != "" && rec.Body.String() != tc.wantBody {
				t.Errorf("body = %q, want %q", rec.Body, tc.wantBody)
			}
		})
	}
}

// TestFileServerRejectionsAreIndistinguishable is the information-leak test: an
// attacker must not be able to tell a missing file from a forbidden one, or the
// handler becomes an oracle for mapping the filesystem.
func TestFileServerRejectionsAreIndistinguishable(t *testing.T) {
	g := newGuard(t)
	srv := g.FileServer()

	targets := []string{
		"/nope.txt",              // does not exist
		"/.env",                  // exists, hidden
		"/.git/config",           // exists, inside a dot directory
		"/sub",                   // exists, is a directory
		"/escape",                // exists, escapes the root
		"/escape-dir/secret.txt", // exists, reached through an escaping symlink
		"/../secret.txt",         // exists, outside the root
	}

	type response struct {
		code int
		body string
		ct   string
	}
	var seen []response
	for _, target := range targets {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		seen = append(seen, response{rec.Code, rec.Body.String(), rec.Header().Get("Content-Type")})
	}

	for i, got := range seen {
		if got != seen[0] {
			t.Errorf("response for %q (%+v) differs from %q (%+v); rejections must be indistinguishable",
				targets[i], got, targets[0], seen[0])
		}
		// The response must not echo the requested path back.
		if strings.Contains(got.body, "secret") || strings.Contains(got.body, ".env") {
			t.Errorf("response for %q echoes the request: %q", targets[i], got.body)
		}
	}
}

// TestFileServerUnderStripPrefix covers the documented mounting pattern.
func TestFileServerUnderStripPrefix(t *testing.T) {
	g := newGuard(t)
	h := http.StripPrefix("/files/", g.FileServer())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/files/sub/nested.txt", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "nested" {
		t.Errorf("status = %d, body = %q", rec.Code, rec.Body)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/files/../../secret.txt", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("traversal under a prefix: status = %d, want 404", rec.Code)
	}
}

func TestFileServerSetsContentType(t *testing.T) {
	base := t.TempDir()
	writeFile(t, filepath.Join(base, "page.html"), "<h1>hi</h1>")
	g, err := pathguard.New(base)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	rec := httptest.NewRecorder()
	g.FileServer().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/page.html", nil))

	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
}

// FuzzResolve is the strongest statement this package can make: for arbitrary
// input, Resolve either fails or returns a path inside the root. A handful of
// "../" cases proves much less.
func FuzzResolve(f *testing.F) {
	base := f.TempDir()
	root := filepath.Join(base, "www")
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o750); err != nil {
		f.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(base, "www-evil"), 0o750); err != nil {
		f.Fatal(err)
	}
	for _, spec := range [][2]string{
		{filepath.Join(base, "secret.txt"), "secret"},
		{filepath.Join(base, "www-evil", "secret.txt"), "sibling"},
		{filepath.Join(root, "index.txt"), "index"},
		{filepath.Join(root, "sub", "nested.txt"), "nested"},
	} {
		if err := os.WriteFile(spec[0], []byte(spec[1]), 0o600); err != nil {
			f.Fatal(err)
		}
	}
	// A symlink out of the root, so the fuzzer can try to reach it. Its absence
	// on a platform without symlinks does not invalidate the rest.
	_ = os.Symlink(filepath.Join(base, "secret.txt"), filepath.Join(root, "escape"))
	_ = os.Symlink(filepath.Join(base, "www-evil"), filepath.Join(root, "escape-dir"))

	g, err := pathguard.New(root)
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { _ = g.Close() })
	guardRoot := g.Root()

	seeds := []string{
		"index.txt", "sub/nested.txt", "../secret.txt", "..", ".", "",
		"/etc/passwd", "escape", "escape-dir/secret.txt", "sub/../../secret.txt",
		"./././index.txt", "sub//nested.txt", "a\x00b", "../www-evil/secret.txt",
		strings.Repeat("../", 40) + "etc/passwd", "\\..\\secret.txt",
		filepath.Join(base, "secret.txt"), filepath.Join(base, "www-evil", "secret.txt"),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, name string) {
		// The invariant: every entry point either errors or stays inside.
		check := func(op string, got string, err error) {
			if err != nil {
				if got != "" {
					t.Fatalf("%s(%q) returned %q alongside error %v", op, name, got, err)
				}
				return
			}
			rel, relErr := filepath.Rel(guardRoot, got)
			if relErr != nil {
				t.Fatalf("%s(%q) = %q, which is not relative to the root: %v", op, name, got, relErr)
			}
			if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				t.Fatalf("%s(%q) = %q, which escapes the root %q", op, name, got, guardRoot)
			}
			if !filepath.IsAbs(got) {
				t.Fatalf("%s(%q) = %q, which is not absolute", op, name, got)
			}
		}

		got, err := g.Resolve(name)
		check("Resolve", got, err)

		got, err = g.ResolveNew(name)
		check("ResolveNew", got, err)

		// Open must never hand back a file outside the root either. Comparing
		// the opened file's identity to the outside secret catches an escape
		// that a path comparison alone might miss.
		if f, err := g.Open(name); err == nil {
			content := make([]byte, 32)
			n, _ := f.Read(content)
			_ = f.Close()
			if string(content[:n]) == "secret" || string(content[:n]) == "sibling" {
				t.Fatalf("Open(%q) read a file from outside the root", name)
			}
		}
	})
}

func ExampleNew() {
	dir, _ := os.MkdirTemp("", "pathguard-example")
	defer func() { _ = os.RemoveAll(dir) }()
	_ = os.WriteFile(filepath.Join(dir, "report.txt"), []byte("quarterly figures"), 0o600)

	guard, err := pathguard.New(dir)
	if err != nil {
		fmt.Println("open root:", err)
		return
	}
	defer guard.Close()

	// A legitimate request.
	f, err := guard.Open("report.txt")
	if err == nil {
		_ = f.Close()
		fmt.Println("report.txt: ok")
	}

	// A traversal attempt, whatever it is dressed up as.
	for _, attempt := range []string{"../../etc/passwd", "/etc/passwd", "sub/../../../etc/passwd"} {
		if _, err := guard.Open(attempt); errors.Is(err, pathguard.ErrOutsideRoot) {
			fmt.Println(attempt, "-> rejected")
		}
	}
	// Output:
	// report.txt: ok
	// ../../etc/passwd -> rejected
	// /etc/passwd -> rejected
	// sub/../../../etc/passwd -> rejected
}

// ExampleGuard_FileServer serves a directory over HTTP with listings off and
// every rejection answered identically.
func ExampleGuard_FileServer() {
	dir, _ := os.MkdirTemp("", "pathguard-fileserver")
	defer func() { _ = os.RemoveAll(dir) }()
	_ = os.WriteFile(filepath.Join(dir, "style.css"), []byte("body{}"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, ".env"), []byte("SECRET=1"), 0o600)

	guard, _ := pathguard.New(dir)
	defer guard.Close()

	handler := http.StripPrefix("/static/", guard.FileServer())

	for _, target := range []string{"/static/style.css", "/static/.env", "/static/../../etc/passwd"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		fmt.Println(target, rec.Code)
	}
	// Output:
	// /static/style.css 200
	// /static/.env 404
	// /static/../../etc/passwd 404
}

// ExampleGuard_ResolveNew validates an upload destination that does not exist
// yet, then creates it through the guard so the write cannot be redirected.
func ExampleGuard_ResolveNew() {
	dir, _ := os.MkdirTemp("", "pathguard-upload")
	defer func() { _ = os.RemoveAll(dir) }()
	_ = os.MkdirAll(filepath.Join(dir, "uploads"), 0o750)

	guard, _ := pathguard.New(dir)
	defer guard.Close()

	if _, err := guard.ResolveNew("uploads/photo.jpg"); err == nil {
		// Create, not os.Create: the returned path is a string, and opening it
		// directly would reintroduce the symlink race.
		f, err := guard.Create("uploads/photo.jpg")
		if err == nil {
			_ = f.Close()
			fmt.Println("upload destination accepted")
		}
	}

	if _, err := guard.ResolveNew("../../tmp/evil.jpg"); err != nil {
		fmt.Println("traversal rejected")
	}
	// Output:
	// upload destination accepted
	// traversal rejected
}
