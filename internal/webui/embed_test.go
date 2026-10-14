package webui

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The embedded UI must not be older than the source it was built from.
//
// There were two build directories: `pnpm build` wrote web/build and go:embed
// read internal/webui/build, with nothing copying one to the other. A frontend
// change built cleanly, the binary rebuilt cleanly, and the browser kept
// running the previous version — no error anywhere, on any side, to explain it.
// A whole evening's UI work went into a directory the binary never read.
//
// The adapter now writes straight into the embedded directory, so the drift is
// structurally impossible. This test is the belt: if anyone repoints the output
// or forgets to rebuild after editing a component, it says so here rather than
// in a browser three hours later.
func TestEmbeddedUIIsNotStalerThanItsSource(t *testing.T) {
	newest := func(root string, skip func(string) bool) (string, time.Time) {
		var name string
		var at time.Time
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || (skip != nil && skip(p)) {
				return nil
			}
			fi, err := d.Info()
			if err != nil {
				return nil
			}
			if fi.ModTime().After(at) {
				at, name = fi.ModTime(), p
			}
			return nil
		})
		return name, at
	}

	srcRoot := filepath.Join("..", "..", "web", "src")
	if _, err := os.Stat(srcRoot); err != nil {
		t.Skip("no web sources here (a source tarball without the UI project)")
	}
	srcFile, srcAt := newest(srcRoot, nil)
	if srcAt.IsZero() {
		t.Skip("no web sources found")
	}

	// Ignore the build's own bookkeeping, which can be touched without the
	// bundles changing.
	buildFile, buildAt := newest("build", func(p string) bool {
		return strings.HasSuffix(p, ".DS_Store") || strings.Contains(p, "version.json")
	})
	if buildAt.IsZero() {
		t.Fatal("internal/webui/build is empty — the binary would serve no UI at all")
	}

	// A minute of slack: a checkout can write files in any order.
	if srcAt.After(buildAt.Add(time.Minute)) {
		t.Fatalf(`the embedded UI is older than its source.

  newest source: %s
                 %s
  newest build:  %s
                 %s

  The binary would serve the previous UI, with no error to explain it.
  Rebuild with:  cd web && pnpm build`,
			srcFile, srcAt.Format(time.RFC3339), buildFile, buildAt.Format(time.RFC3339))
	}
}

// The build must actually contain an application, not just a fallback page.
func TestEmbeddedUIHasItsBundles(t *testing.T) {
	assets, ok := Assets()
	if !ok {
		t.Fatal("no embedded assets")
	}
	_ = assets
	var js, css int
	filepath.WalkDir("build", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		switch filepath.Ext(p) {
		case ".js":
			js++
		case ".css":
			css++
		}
		return nil
	})
	if js == 0 {
		t.Error("no JavaScript in the embedded build; every asset request would fall back to index.html")
	}
	if css == 0 {
		t.Error("no CSS in the embedded build")
	}
}
