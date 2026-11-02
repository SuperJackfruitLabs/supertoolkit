// Command lint-go runs golangci-lint over the module with a ratchet (docs/code-quality.md).
//
// Findings are counted per linter in scripts/lint-go/baseline.json: a count may fall but never
// rise, a linter missing from the baseline must be clean, and an improvement must be locked in
// with `go run ./scripts/lint-go --update`, so a stale baseline cannot let the next regression
// through.
//
// The linter is pinned. Install that exact version once (never @latest):
//
//	GOBIN="$PWD/.bin" go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0
//
// The command uses $GOLANGCI_LINT, then .bin/golangci-lint, then golangci-lint on PATH, and
// refuses any other version: a newer linter finds more, and the counts would mean nothing.
//
// It always analyses the linux/amd64 build, which is what CI runs; on a Mac the darwin-only
// files would otherwise change the counts.
//
// Run it from the repository root.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const version = "2.15.0"

const baselinePath = "scripts/lint-go/baseline.json"

type finding struct {
	FromLinter string
	Text       string
	Pos        struct {
		Filename string
		Line     int
	}
}

func main() {
	update := flag.Bool("update", false, "lower the baseline to today's counts (it never raises one)")
	flag.Parse()
	os.Exit(run(*update, os.Stdout, os.Stderr))
}

func linterBinary() string {
	if b := os.Getenv("GOLANGCI_LINT"); b != "" {
		return b
	}
	local := filepath.Join(".bin", "golangci-lint")
	if _, err := os.Stat(local); err == nil {
		return local
	}
	return "golangci-lint"
}

func run(update bool, stdout, stderr io.Writer) int {
	bin := linterBinary()
	env := append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")

	v := exec.CommandContext(context.Background(), bin, "version", "--short")
	v.Env = env
	out, err := v.Output()
	got := strings.TrimPrefix(strings.TrimSpace(string(out)), "v")
	if err != nil || got != version {
		found := got
		if err != nil {
			found = "none"
		}
		_, _ = fmt.Fprintf(stderr, "lint-go needs golangci-lint %s (found %s).\n  GOBIN=\"$PWD/.bin\" go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v%s\n", version, found, version)
		return 2
	}

	lint := exec.CommandContext(context.Background(), bin, "run", "--output.json.path=stdout", "--output.text.path=stderr", "--show-stats=false", "./...")
	lint.Env = env
	var report, diag bytes.Buffer
	lint.Stdout, lint.Stderr = &report, &diag
	err = lint.Run()
	// Exit 1 means "issues found"; anything else is the linter failing to run.
	var exit *exec.ExitError
	if err != nil && (!errors.As(err, &exit) || exit.ExitCode() != 1) {
		_, _ = stderr.Write(diag.Bytes())
		_, _ = fmt.Fprintln(stderr, "lint-go: golangci-lint did not run:", err)
		return 2
	}
	var parsed struct{ Issues []finding }
	if err := json.Unmarshal(report.Bytes(), &parsed); err != nil {
		_, _ = stderr.Write(diag.Bytes())
		_, _ = fmt.Fprintln(stderr, "lint-go: unreadable golangci-lint report:", err)
		return 2
	}
	counts := map[string]int{}
	for _, f := range parsed.Issues {
		counts[f.FromLinter]++
	}

	raw, err := os.ReadFile(baselinePath)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "lint-go:", err)
		return 2
	}
	baseline := map[string]int{}
	if err := json.Unmarshal(raw, &baseline); err != nil {
		_, _ = fmt.Fprintf(stderr, "lint-go: %s: %v\n", baselinePath, err)
		return 2
	}

	raised, lowered := compare(counts, baseline)
	if len(raised) > 0 {
		for _, linter := range raised {
			_, _ = fmt.Fprintf(stderr, "%s: %d findings, the baseline allows %d\n", linter, counts[linter], baseline[linter])
			shown := 0
			for _, f := range parsed.Issues {
				if f.FromLinter == linter && shown < 20 {
					_, _ = fmt.Fprintf(stderr, "  %s:%d  %s\n", f.Pos.Filename, f.Pos.Line, f.Text)
					shown++
				}
			}
		}
		return 1
	}
	if update {
		body, err := json.MarshalIndent(counts, "", "  ")
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "lint-go:", err)
			return 2
		}
		if err := os.WriteFile(baselinePath, append(body, '\n'), 0o600); err != nil {
			_, _ = fmt.Fprintln(stderr, "lint-go:", err)
			return 2
		}
		_, _ = fmt.Fprintf(stdout, "lint-go baseline: %d findings across %d linters\n", len(parsed.Issues), len(counts))
		return 0
	}
	if len(lowered) > 0 {
		_, _ = fmt.Fprintf(stderr, "lint-go: %s improved; run `go run ./scripts/lint-go --update` to lock it in\n", strings.Join(lowered, ", "))
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "lint-go: ok (%d findings held by the baseline)\n", len(parsed.Issues))
	return 0
}

// compare names the linters whose count rose above the baseline (a linter missing from it allows
// none) and those whose count fell below it.
func compare(counts, baseline map[string]int) (raised, lowered []string) {
	for linter, n := range counts {
		if n > baseline[linter] {
			raised = append(raised, linter)
		}
	}
	for linter, n := range baseline {
		if counts[linter] < n {
			lowered = append(lowered, linter)
		}
	}
	sort.Strings(raised)
	sort.Strings(lowered)
	return raised, lowered
}
