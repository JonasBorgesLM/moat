// Command gosecure-secret prints a fresh CSRF secret.
//
// It exists because the library itself must never print. csrf.GenerateSecret
// returns a value; this program is the one place where writing that value to
// stdout is the caller's explicit intent rather than a library's side effect.
//
// Usage:
//
//	go run github.com/JonasBorgesLM/gosecure/cmd/gosecure-secret [-format hex|base64|raw]
//
// The output goes to stdout with no trailing commentary, so it can be piped
// straight into a secret store:
//
//	gosecure-secret | op create item ...
//	gosecure-secret > /run/secrets/csrf_key
//
// Handle the result as a credential. It will otherwise end up in your shell
// history, in your terminal scrollback, and in whatever ships those somewhere
// else. Do not commit it, do not put it in a Dockerfile, and do not generate a
// new one per deploy: rotating the secret invalidates every outstanding token.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/JonasBorgesLM/gosecure/csrf"
)

// main parses flags and writes the secret. It does no work of its own so that
// run can be exercised without spawning a process.
func main() {
	format := flag.String("format", "base64", "output encoding: base64, hex, or raw")
	flag.Parse()

	if err := run(*format, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "gosecure-secret:", err)
		os.Exit(1)
	}
}

// run is separated from main so that it can be tested without spawning a
// process or capturing the real stdout.
func run(format string, out *os.File) error {
	secret, err := csrf.GenerateSecret()
	if err != nil {
		return err
	}

	var encoded string
	switch format {
	case "base64":
		encoded = base64.StdEncoding.EncodeToString(secret)
	case "hex":
		encoded = hex.EncodeToString(secret)
	case "raw":
		// Raw bytes, for writing straight into a file or a secret store. No
		// newline: a trailing newline silently becomes part of the secret when
		// the file is read back whole, and then the secret differs between the
		// process that wrote it and the one that reads it.
		_, err := out.Write(secret)
		return err
	default:
		return fmt.Errorf("unknown format %q: want base64, hex, or raw", format)
	}

	_, err = fmt.Fprintln(out, encoded)
	return err
}
