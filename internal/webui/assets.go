package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// built holds the web app, compiled into the binary so the single-binary
// promise survives having a UI.
//
// The directory is committed with a placeholder, so `go build` works for
// someone who has not run pnpm — they get a page saying how to build the
// assets rather than a build failure.
//
//go:embed all:build
var built embed.FS

// Assets serves the built web app, or reports that this binary has none.
func Assets() (http.Handler, bool) {
	sub, err := fs.Sub(built, "build")
	if err != nil {
		return nil, false
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil, false
	}
	return spa(http.FS(sub), sub), true
}

// spa serves files, falling back to index.html so client-side routes work on a
// fresh load rather than 404ing.
func spa(fsys http.FileSystem, sub fs.FS) http.Handler {
	files := http.FileServer(fsys)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			files.ServeHTTP(w, r)
			return
		}
		if _, err := fs.Stat(sub, p); err == nil {
			files.ServeHTTP(w, r)
			return
		}
		r2 := *r
		r2.URL = &(*r.URL)
		r2.URL.Path = "/"
		files.ServeHTTP(w, &r2)
	})
}
