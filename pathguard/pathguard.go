// Package pathguard resolves user-supplied paths under a fixed root directory
// without letting them escape it.
//
// # The problem
//
// Any endpoint that turns part of a request into a filesystem path is one
// mistake away from serving /etc/passwd or the application's own private key.
// The obvious defenses are all incomplete on their own:
//
//   - Rejecting ".." misses an absolute path, a URL-encoded "%2e%2e", a
//     backslash on Windows, and a symlink that points wherever it likes.
//   - Cleaning the path and comparing prefixes misses that "/var/www-evil" has
//     "/var/www" as a string prefix while being an entirely different directory
//     (see [Guard.Resolve] and the note on filepath.Rel below).
//   - Resolving symlinks and then opening the result is racy, which is the
//     subtle one and the reason this package is built the way it is.
//
// # Why os.Root, and what TOCTOU means here
//
// Consider the careful-looking approach: call filepath.EvalSymlinks, check the
// result is under the root, then os.Open it. Between the check and the open
// there is a window. An attacker who can write into the tree — through an
// upload endpoint, a shared volume, an unpacked archive, a compromised
// neighbouring service — replaces a directory component with a symlink to /etc
// inside that window. The check passed against the old path; the open follows
// the new one. This is a time-of-check-to-time-of-use race, and no amount of
// validation in user space can close it: the whole problem is that the name is
// re-resolved by the kernel after you finished looking at it.
//
// The fix is to stop resolving names twice. [os.Root], added in Go 1.24, holds
// an open handle to the root directory and performs every operation relative to
// that handle, with each path component checked as it is traversed. A symlink
// that leaves the root fails at the syscall layer, whether it was planted
// before the call or during it. There is no window because there is no second
// resolution.
//
// This package is therefore a thin, well-documented layer over os.Root, plus a
// filepath.Rel-based pre-check for the cases that do not open a file at all.
// The pre-check is defense in depth and a source of clearer errors; the
// containment guarantee comes from os.Root.
//
// # Symlinks: what is and is not followed
//
// A symlink inside the root whose target is also inside the root is followed
// normally. Two cases are refused, and the second one surprises people:
//
//   - A symlink whose target lies outside the root. This is the attack case,
//     and refusing it is the whole point.
//   - **Any absolute symlink, even one pointing inside the root.** os.Root
//     resolves names relative to its directory handle, and an absolute target
//     cannot be interpreted that way without re-entering the very
//     re-resolution this design removes. So /srv/www/current -> /srv/www/v3
//     fails here even though both paths are inside the root. Use a relative
//     link (current -> v3) instead, which is better practice for a movable tree
//     anyway.
//
// # Limits, stated plainly
//
// os.Root itself documents platform caveats, and they are this package's
// caveats too. On GOOS=js containment cannot be guaranteed against a symlink
// race. On plan9 and js a Root tracks a directory name rather than a handle, so
// it does not follow a renamed directory. os.Root does not stop traversal of
// bind mounts, /proc, or device files that live inside the root — if the tree
// you point a Guard at contains a path to somewhere else, containment in the
// path sense is not containment in the "what can be read" sense.
//
// This package constrains filesystem paths. It does not sandbox the process, it
// does not enforce permissions, and it has nothing to say about what your
// handler does with a file once it is legitimately open.
package pathguard

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Errors reported by this package. Test for them with errors.Is.
//
// They exist so that a caller can distinguish a containment failure from an
// ordinary I/O error in its own logging and metrics. They are deliberately not
// suitable for returning to a client: see [Guard.FileServer] on why a response
// must not reveal which of these occurred.
var (
	// ErrOutsideRoot reports that a path resolved, or would resolve, outside the
	// guard's root. This is the error a traversal attempt produces.
	ErrOutsideRoot = errors.New("pathguard: path escapes the root directory")

	// ErrInvalidPath reports that a path is malformed in a way that makes it
	// unusable: empty, or containing a NUL byte.
	ErrInvalidPath = errors.New("pathguard: invalid path")

	// ErrClosed reports an operation on a Guard that has been closed.
	ErrClosed = errors.New("pathguard: guard is closed")
)

// Guard resolves paths beneath a single root directory.
//
// A Guard holds an open handle to its root, so it must be closed when no longer
// needed. It is safe for concurrent use, and is intended to be created once at
// startup and shared.
//
// Because the handle refers to the directory rather than to its name, a Guard
// keeps working if the root is renamed, and keeps pointing at the original
// directory rather than at whatever later takes its place. On plan9 and js,
// where os.Root tracks a name instead, that is not true.
//
// The zero Guard is not usable; create one with [New].
type Guard struct {
	root *os.Root
	// dir is the cleaned absolute path of the root, kept for the
	// filepath.Rel pre-check and for building the paths Resolve returns.
	dir string
}

// New opens dir as a guarded root.
//
// dir must exist and be a directory; a missing root is an error rather than
// something created on demand, because silently creating a directory is how a
// typo in a configuration file turns into an empty tree that serves nothing and
// nobody notices.
//
// The path is resolved to an absolute path with symlinks evaluated once, at
// startup. That is safe to do here — it happens before any request is served
// and is not part of any per-request decision — and it means a root given as a
// symlink behaves the way the operator expects.
//
// The returned Guard holds an open file descriptor. Close it when done.
func New(dir string) (*Guard, error) {
	if dir == "" {
		return nil, fmt.Errorf("%w: root directory is empty", ErrInvalidPath)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("pathguard: resolving root %q: %w", dir, err)
	}
	// Evaluate symlinks in the root itself once, at construction, so that the
	// Rel pre-check compares like with like. This is not a TOCTOU risk: it
	// happens before the Guard serves anything, and containment for every later
	// operation comes from the os.Root handle, not from this string.
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}

	root, err := os.OpenRoot(abs)
	if err != nil {
		return nil, fmt.Errorf("pathguard: opening root %q: %w", dir, err)
	}
	return &Guard{root: root, dir: filepath.Clean(abs)}, nil
}

// Root returns the cleaned absolute path of the guarded directory.
//
// It is safe to log and to show in configuration output. It must not be joined
// with user input to build a path — that is exactly the pattern this package
// exists to replace.
func (g *Guard) Root() string { return g.dir }

// Close releases the guard's handle on the root directory. It is safe to call
// more than once.
func (g *Guard) Close() error {
	if g == nil || g.root == nil {
		return nil
	}
	err := g.root.Close()
	if errors.Is(err, os.ErrClosed) {
		return nil
	}
	return err
}

// Open opens name for reading, relative to the root.
//
// This is the safe way to read a user-supplied path, and it is the one to reach
// for by default. Every path component is checked by the kernel as it is
// traversed, so a symlink pointing outside the root fails even if it is planted
// between this call and the read — there is no window in which a swapped
// component can be followed.
//
// name may be relative to the root, or absolute if it is genuinely inside the
// root. "..", absolute paths outside the root, and symlinks leaving the root
// are rejected with an error wrapping [ErrOutsideRoot].
//
// The caller owns the returned file and must close it.
func (g *Guard) Open(name string) (*os.File, error) {
	rel, err := g.rel(name)
	if err != nil {
		return nil, err
	}
	f, err := g.root.Open(rel)
	if err != nil {
		return nil, g.wrap(name, err)
	}
	return f, nil
}

// Create creates or truncates name relative to the root and opens it for
// writing.
//
// It is the counterpart to [Guard.ResolveNew] and exists because an upload
// destination is the most common reason to need a path that does not exist
// yet. Containment is enforced by the kernel on every component, so a symlink
// planted at the destination cannot redirect the write outside the root.
//
// Note that this truncates an existing file. Whether a caller is allowed to
// overwrite an existing name is an application decision — for uploads it is
// usually not, and the usual answer is a server-generated name rather than a
// check-then-create, which has a race of its own.
//
// The caller owns the returned file and must close it.
func (g *Guard) Create(name string) (*os.File, error) {
	rel, err := g.rel(name)
	if err != nil {
		return nil, err
	}
	f, err := g.root.Create(rel)
	if err != nil {
		return nil, g.wrap(name, err)
	}
	return f, nil
}

// Stat returns file information for name, relative to the root, following
// symlinks within the root.
func (g *Guard) Stat(name string) (fs.FileInfo, error) {
	rel, err := g.rel(name)
	if err != nil {
		return nil, err
	}
	fi, err := g.root.Stat(rel)
	if err != nil {
		return nil, g.wrap(name, err)
	}
	return fi, nil
}

// Resolve validates that name refers to an existing path inside the root and
// returns its cleaned absolute path.
//
// Use it when you need the path itself rather than the file: to record which
// file was requested, to hand a name to a subprocess, to compare against a
// manifest. It performs the filepath.Rel-based containment pre-check and then
// confirms containment and existence through the root handle, so a symlink
// leaving the root is rejected.
//
// **The returned path is not a TOCTOU-safe handle.** Passing it to os.Open
// re-resolves every component from scratch and reopens exactly the race this
// package exists to close. If you intend to read the file, call [Guard.Open]
// and use the returned *os.File. Resolve is for the cases where you genuinely
// need a string.
//
// A path that does not exist is an error; use [Guard.ResolveNew] for a
// destination that has yet to be created.
func (g *Guard) Resolve(name string) (string, error) {
	rel, err := g.rel(name)
	if err != nil {
		return "", err
	}
	if _, err := g.root.Stat(rel); err != nil {
		return "", g.wrap(name, err)
	}
	return filepath.Join(g.dir, rel), nil
}

// ResolveNew validates a path that does not need to exist yet and returns its
// cleaned absolute path.
//
// The parent directory must exist and be a directory inside the root, which is
// what makes this useful for an upload destination: the target file is absent
// by definition, so [Guard.Resolve] would reject it, but the directory it will
// land in can still be checked.
//
// The final component is validated as a name — it must not be empty, ".", "..",
// or contain a separator after cleaning — but it is not resolved, because there
// may be nothing there to resolve.
//
// The same warning as [Guard.Resolve] applies, and more strongly: the returned
// path is a string, not a handle, and creating a file at it with os.Create
// reintroduces the symlink race. Use [Guard.Create], which enforces containment
// at the syscall layer even if something is planted at the destination between
// this call and the write.
func (g *Guard) ResolveNew(name string) (string, error) {
	rel, err := g.rel(name)
	if err != nil {
		return "", err
	}
	if rel == "." {
		return "", fmt.Errorf("%w: %q refers to the root itself", ErrInvalidPath, name)
	}

	parent := filepath.Dir(rel)
	fi, err := g.root.Stat(parent)
	if err != nil {
		return "", g.wrap(name, err)
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("%w: parent of %q is not a directory", ErrInvalidPath, name)
	}
	return filepath.Join(g.dir, rel), nil
}

// rel converts a caller-supplied name into a path relative to the root,
// rejecting anything that escapes.
//
// This is the defense-in-depth pre-check. It is not what makes the package
// safe — os.Root is — but it catches the obvious cases early, produces a
// clearer error than a syscall would, and covers the operations that never open
// a file.
//
// The containment test uses filepath.Rel rather than a string prefix. A prefix
// test is wrong in a way that looks right:
//
//	strings.HasPrefix("/var/www-evil/secret", "/var/www")  // true, and wrong
//
// "/var/www-evil" is a different directory that merely shares a prefix with the
// root. filepath.Rel answers the question actually being asked — "how do I get
// from the root to this path?" — and an answer that starts with ".." means the
// path is outside.
func (g *Guard) rel(name string) (string, error) {
	if g == nil || g.root == nil {
		return "", ErrClosed
	}
	if name == "" {
		return "", fmt.Errorf("%w: path is empty", ErrInvalidPath)
	}
	// A NUL byte terminates the string in the C API underneath every syscall,
	// so a name containing one means something different to the kernel than it
	// does to Go. The standard library rejects it too; doing so here makes the
	// reason explicit and the error consistent.
	if strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("%w: path contains a NUL byte", ErrInvalidPath)
	}

	// Normalize slashes so that a path taken from a URL works on Windows too,
	// where "a/b" and "a\\b" name the same file and only one of them is caught
	// by a naive separator check.
	name = filepath.FromSlash(name)

	var rel string
	if filepath.IsAbs(name) {
		// An absolute path is acceptable only if it is genuinely inside the
		// root. Rel decides that; a prefix comparison would not.
		var err error
		rel, err = filepath.Rel(g.dir, filepath.Clean(name))
		if err != nil {
			return "", fmt.Errorf("%w: %q", ErrOutsideRoot, name)
		}
	} else {
		rel = filepath.Clean(name)
	}

	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: %q", ErrOutsideRoot, name)
	}
	if filepath.IsAbs(rel) {
		// Clean can leave a rooted path on Windows (for example "\\foo"), which
		// os.Root would reject anyway; reject it here with a clear reason.
		return "", fmt.Errorf("%w: %q", ErrOutsideRoot, name)
	}
	return rel, nil
}

// wrap turns an error from an os.Root operation into one of this package's
// sentinel errors where the cause is a containment failure, so that a caller
// can distinguish "escaped the root" from "does not exist" without string
// matching.
//
// The original error is retained in the chain, so errors.Is against
// fs.ErrNotExist and friends keeps working.
func (g *Guard) wrap(name string, err error) error {
	if err == nil {
		return nil
	}
	// os.Root reports a containment violation as EPERM or EXDEV depending on
	// the platform and the operation, wrapped in a *PathError. Neither maps to
	// a portable sentinel, so treat "not a not-exist error" conservatively and
	// annotate with the path that was asked for.
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("pathguard: %q: %w", name, err)
	}
	if errors.Is(err, os.ErrClosed) {
		return fmt.Errorf("%w: %q", ErrClosed, name)
	}
	return fmt.Errorf("%w: %q: %w", ErrOutsideRoot, name, err)
}

// FileServer returns a handler that serves files from the root over HTTP.
//
// It is a hardened alternative to http.FileServer with three deliberate
// differences, each of which closes a way that static file serving leaks
// information:
//
//   - **Every rejection is a 404 with an identical body.** Not found, outside
//     the root, permission denied, is a directory, and hidden are all the same
//     response. Distinguishing them turns the handler into an oracle: an
//     attacker who can tell "403 forbidden" from "404 missing" can map the
//     filesystem one request at a time without ever reading a byte. The
//     response also never echoes the requested path back, which would make it a
//     reflection point.
//   - **Directory listings are off, with no way to turn them on.** A listing
//     publishes every filename in the tree, including the backup file somebody
//     left behind. A request for a directory is a 404. index.html is not served
//     implicitly either; if you want one, route it explicitly.
//   - **Path components beginning with a dot are refused.** Serving a directory
//     that happens to contain .git, .env or .htpasswd is one of the most
//     reliably exploited misconfigurations there is, and the default should not
//     depend on the operator having thought about it. If you need to serve a
//     dot-path such as /.well-known/acme-challenge, route that prefix to its
//     own handler with its own Guard.
//
// Only GET and HEAD are accepted; anything else is 405, which is a protocol
// answer rather than an information leak. Range requests and
// If-Modified-Since are handled by http.ServeContent, and the content type
// comes from the file extension.
//
// The handler serves the path from r.URL.Path, so wrap it in http.StripPrefix
// when it is mounted under a prefix.
//
// # Customizing the two rejections
//
// The handler can reject a request in two places, and both are replaceable:
// [WithNotFoundHandler] for the 404 and [WithMethodNotAllowedHandler] for the
// 405. Replace both or neither. An application with its own error envelope that
// overrides only one answers the same handler in two formats, which is the
// inconsistency the option existed to remove.
func (g *Guard) FileServer(opts ...Option) http.Handler {
	cfg := fileServerConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			// Set before dispatching, so a custom handler inherits it and does
			// not have to know that 405 requires Allow to be conformant.
			w.Header().Set("Allow", "GET, HEAD")
			cfg.writeMethodNotAllowed(w, r)
			return
		}

		name, ok := urlPathToName(r.URL.Path)
		if !ok {
			cfg.writeNotFound(w, r)
			return
		}

		f, err := g.Open(name)
		if err != nil {
			cfg.writeNotFound(w, r)
			return
		}
		defer f.Close()

		fi, err := f.Stat()
		if err != nil || fi.IsDir() || !fi.Mode().IsRegular() {
			// Directories are not listed, and a device or FIFO inside the root
			// is not something an HTTP file server should be streaming.
			cfg.writeNotFound(w, r)
			return
		}

		http.ServeContent(w, r, fi.Name(), fi.ModTime(), f)
	})
}

// Option configures the handler returned by [Guard.FileServer].
type Option func(*fileServerConfig)

// fileServerConfig holds the replaceable responses for one FileServer.
type fileServerConfig struct {
	notFound         http.Handler
	methodNotAllowed http.Handler
}

// WithNotFoundHandler replaces the response written for every rejection that is
// not a method mismatch.
//
// The default writes 404 with an identical body for all of them. A replacement
// must preserve that: it receives no indication of which check failed, and that
// is deliberate. Reintroducing the distinction — 403 for permission denied, 404
// for missing — rebuilds the filesystem-mapping oracle described above, and a
// handler that echoes r.URL.Path back turns the response into a reflection
// point. Write a constant body.
//
// A nil handler is ignored.
func WithNotFoundHandler(h http.Handler) Option {
	return func(c *fileServerConfig) {
		if h != nil {
			c.notFound = h
		}
	}
}

// WithMethodNotAllowedHandler replaces the response written when the method is
// neither GET nor HEAD. The default writes 405.
//
// The Allow header is already set on the ResponseWriter when the handler runs,
// so a replacement can write any body without having to remember that a 405
// without Allow is not a conformant response. Do not delete it.
//
// It is deliberately distinct from the not-found handler: 405 is a protocol
// answer that reveals nothing about the filesystem, whereas answering a bad
// method with the 404 body would tell a client that the path does not exist,
// which is a claim this handler otherwise refuses to make.
//
// A nil handler is ignored.
func WithMethodNotAllowedHandler(h http.Handler) Option {
	return func(c *fileServerConfig) {
		if h != nil {
			c.methodNotAllowed = h
		}
	}
}

// writeNotFound writes the single response used for every non-method
// rejection, so that no caller can tell which check failed.
func (c fileServerConfig) writeNotFound(w http.ResponseWriter, r *http.Request) {
	if c.notFound != nil {
		c.notFound.ServeHTTP(w, r)
		return
	}
	http.Error(w, "404 page not found", http.StatusNotFound)
}

// writeMethodNotAllowed writes the response for a method other than GET or HEAD.
func (c fileServerConfig) writeMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	if c.methodNotAllowed != nil {
		c.methodNotAllowed.ServeHTTP(w, r)
		return
	}
	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

// urlPathToName converts a URL path into a name relative to the root, rejecting
// anything with a dot-prefixed component.
//
// path.Clean is used rather than filepath.Clean because a URL path is
// slash-separated regardless of the host operating system. The result is then
// handed to Guard.Open, which applies the real containment check.
func urlPathToName(p string) (string, bool) {
	if p == "" {
		p = "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	// Cleaning an absolute path collapses "." and ".." without any chance of
	// the result escaping, since ".." at the root has nowhere to go.
	clean := path.Clean(p)
	if clean == "/" {
		return "", false // the root itself is a directory
	}
	name := strings.TrimPrefix(clean, "/")

	for _, component := range strings.Split(name, "/") {
		if strings.HasPrefix(component, ".") {
			return "", false
		}
	}
	return name, true
}
