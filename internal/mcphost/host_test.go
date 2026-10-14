package mcphost

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	placeholder = "stk:ref:fake:v1"
	realSecret  = "the_real_credential_never_given_to_the_child"
)

var (
	buildOnce sync.Once
	fakePath  string
	buildErr  error
)

// fakeserver is built from this repo's testdata. It stands in for a
// third-party MCP server: it reads its token from the environment, builds its
// own HTTP client, and knows nothing about supertoolkit.
func fakeserver(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "stk-fake")
		if err != nil {
			buildErr = err
			return
		}
		out := filepath.Join(dir, "fakeserver")
		cmd := exec.Command("go", "build", "-o", out, "../../testdata/fakeserver")
		if b, err := cmd.CombinedOutput(); err != nil {
			buildErr = err
			t.Logf("building the fixture server: %s", b)
			return
		}
		fakePath = out
	})
	if buildErr != nil {
		t.Fatalf("could not build the fixture server: %v", buildErr)
	}
	return fakePath
}

func host(t *testing.T, env []string) *Host {
	t.Helper()
	h := New(Spec{Name: "fake", Command: fakeserver(t), Env: env})
	t.Cleanup(func() { h.Close() })
	return h
}

func TestHandshakeAndToolList(t *testing.T) {
	h := host(t, []string{"FAKE_API_TOKEN=" + placeholder})
	tools, err := h.ListTools(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 3 {
		t.Fatalf("ListTools() = %d tools, want 3", len(tools))
	}
	byName := map[string]Tool{}
	for _, tl := range tools {
		byName[tl.Name] = tl
	}
	if _, ok := byName["whoami"]; !ok {
		t.Fatal("whoami missing")
	}
	ro, annotated := byName["whoami"].ReadOnly()
	if !annotated || !ro {
		t.Errorf("whoami should carry a read-only annotation, got ro=%v annotated=%v", ro, annotated)
	}
	// The unannotated tool must report as unannotated, not as safe.
	if _, annotated := byName["post_message"].ReadOnly(); annotated {
		t.Error("post_message is unannotated and must not report an annotation")
	}
}

// The point of the whole phase: the child holds the placeholder, not the
// credential, and it reports that itself.
func TestChildNeverSeesTheCredential(t *testing.T) {
	env := []string{"FAKE_API_TOKEN=" + placeholder}
	h := host(t, env)
	got, isErr, err := h.CallTool(context.Background(), "report_env", nil)
	if err != nil || isErr {
		t.Fatalf("report_env failed: %v (isErr=%v)", err, isErr)
	}
	if got != placeholder {
		t.Fatalf("the child believes its credential is %q, want the placeholder", got)
	}
	if strings.Contains(got, realSecret) {
		t.Fatal("the child holds the real credential")
	}
	for _, kv := range env {
		if strings.Contains(kv, realSecret) {
			t.Fatalf("the child's environment contains the credential: %s", kv)
		}
	}
}

func TestCallToolReturnsTheChildsAnswer(t *testing.T) {
	h := host(t, []string{"FAKE_API_TOKEN=" + placeholder, "FAKE_API_URL=http://127.0.0.1:1/nope"})
	got, _, err := h.CallTool(context.Background(), "whoami", nil)
	if err != nil {
		t.Fatal(err)
	}
	// The upstream is unreachable on purpose: what matters is that the child's
	// own words come back rather than the host inventing something.
	if !strings.Contains(got, "upstream error") {
		t.Fatalf("CallTool() = %q, want the child's own error text", got)
	}
}

func TestUnknownToolIsAnError(t *testing.T) {
	h := host(t, []string{"FAKE_API_TOKEN=" + placeholder})
	if _, _, err := h.CallTool(context.Background(), "no_such_tool", nil); err == nil {
		t.Fatal("calling an unknown tool returned no error")
	}
}

// A child that exits must produce an error rather than hanging the caller.
func TestDeadChildIsReportedNotHung(t *testing.T) {
	h := New(Spec{Name: "exits", Command: "/usr/bin/true"})
	t.Cleanup(func() { h.Close() })
	if err := h.Start(context.Background()); err == nil {
		t.Fatal("Start() on a process that exits immediately returned no error")
	}
}

func TestMissingCommandIsReported(t *testing.T) {
	h := New(Spec{Name: "absent", Command: "/definitely/not/a/binary"})
	if err := h.Start(context.Background()); err == nil {
		t.Fatal("Start() with a missing command returned no error")
	}
}

// A chatty child that writes notifications must not wedge the host.
func TestNoiseOnStdoutDoesNotWedgeTheHost(t *testing.T) {
	script := filepath.Join(t.TempDir(), "noisy.sh")
	// Emits a notification with no id before every real reply.
	body := `#!/bin/sh
while IFS= read -r line; do
  printf '{"jsonrpc":"2.0","method":"notifications/progress"}\n'
  case "$line" in
    *initialize*) printf '{"jsonrpc":"2.0","id":1,"result":{}}\n' ;;
    *tools/list*) printf '{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}\n' ;;
    *) printf '{"jsonrpc":"2.0","id":3,"result":{}}\n' ;;
  esac
done
`
	os.WriteFile(script, []byte(body), 0o755)
	h := New(Spec{Name: "noisy", Command: "/bin/sh", Args: []string{script}})
	t.Cleanup(func() { h.Close() })
	tools, err := h.ListTools(context.Background())
	if err != nil {
		t.Fatalf("a child emitting notifications wedged the host: %v", err)
	}
	if len(tools) != 0 {
		t.Fatalf("ListTools() = %v, want none", tools)
	}
}

// A child's tool list does not change while it runs, so asking once is
// correct — and asking per agent turn would cost a round trip each time.
func TestToolListIsCachedWhileTheChildRuns(t *testing.T) {
	h := host(t, []string{"FAKE_API_TOKEN=" + placeholder})
	first, err := h.ListTools(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := h.ListTools(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != len(second) {
		t.Fatalf("the cached list differs: %d then %d", len(first), len(second))
	}
	if !h.toolsValid {
		t.Error("the tool list was not cached")
	}
	// After Close the cache must be dropped, so a restart re-lists rather than
	// serving a stale list from a different version of the server.
	h.Close()
	if h.toolsValid {
		t.Error("the tool list survived Close(); a restarted child could serve a stale list")
	}
}
