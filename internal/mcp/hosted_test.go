package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/approval"
)

// recordingBoard accepts creates and records them.
type recordingBoard struct{ created []approval.ApprovalRequest }

func (b *recordingBoard) CreateApprovalRequest(_ context.Context, _ string, body approval.ApprovalRequest) (approval.ApprovalCreated, error) {
	b.created = append(b.created, body)
	return approval.ApprovalCreated{ApprovalRequestID: "apr_" + body.RequestID, State: "pending"}, nil
}

func (b *recordingBoard) ReadApprovalRequest(context.Context, string, string) (approval.ApprovalReadBack, error) {
	return approval.ApprovalReadBack{State: "pending"}, nil
}

// Regression guarded: with an approvals board set, a fronted server's tool
// approval stayed local, so an operator decided it and the agent's own
// session performed it — the charter makes no exception for them.
func TestFrontedToolApprovalIsHosted(t *testing.T) {
	srv, child, q := frontedRig(t, "", 0)
	board := &recordingBoard{}
	srv.hosting = &approval.Host{Queue: q, Client: board, Board: "brd_fixture", Station: "station-1"}
	got := callT(t, srv, "execute_action", map[string]string{
		"category": "faker", "action": "write_thing", "args": `{"path":"/a","mode":"x"}`,
	})
	if !strings.Contains(got, `"decided_on": "superpipeline"`) || len(child.called) != 0 {
		t.Fatalf("hosted fronted call answered %s (child calls %v)", got, child.called)
	}
	pending := q.Pending()
	if len(pending) != 1 || pending[0].HostedBoard != "brd_fixture" || pending[0].Target != "mcp://faker/write_thing" {
		t.Fatalf("pending = %+v", pending)
	}
	if _, err := q.DecideAndPerform(pending[0].ID, true, "root (uid 0)", func(*approval.Effect) (string, error) { return "", nil }); err == nil {
		t.Fatal("a hosted fronted approval was decided locally")
	}
	if len(board.created) != 1 {
		t.Fatalf("creates = %d", len(board.created))
	}
	raw, _ := json.Marshal(board.created[0])
	for _, want := range []string{"faker", "write_thing", "Argument path", "Argument mode", pending[0].RequestDigest} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("approval request lacks %q: %s", want, raw)
		}
	}
}

// swapQueue gives a rig a queue in a known directory, so a test can edit the
// record as anyone with write access to the state directory could.
func swapQueue(t *testing.T, srv *Server) (*approval.Queue, string) {
	t.Helper()
	dir := t.TempDir()
	q, err := approval.Open(dir, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	srv.queue = q
	return q, filepath.Join(dir, "approvals")
}

func forgeDigest(t *testing.T, dir, id string) {
	t.Helper()
	path := filepath.Join(dir, id+".req")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var e map[string]any
	_ = json.Unmarshal(raw, &e)
	e["request_digest"] = "sha256:approved-something-else"
	raw, _ = json.Marshal(e)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func awaitPending(t *testing.T, q *approval.Queue) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for len(q.Pending()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	p := q.Pending()
	if len(p) != 1 {
		t.Fatal("nothing queued")
	}
	return p[0].ID
}

// Regression guarded: a waiter that performs an approval nobody else performed
// ran the request without checking the approval on record binds it.
func TestWaiterRefusesWhenTheRecordedApprovalBindsAnotherRequest(t *testing.T) {
	r := newRig(t, "", 2*time.Second)
	q, dir := swapQueue(t, r.srv)
	done := make(chan string, 1)
	go func() {
		done <- r.callTool(t, "execute_action", map[string]string{
			"category": "github", "action": "create_issue", "args": `{"owner":"o","repo":"r","title":"t"}`,
		})
	}()
	id := awaitPending(t, q)
	forgeDigest(t, dir, id)
	if _, err := q.Decide(id, true, "operator"); err != nil {
		t.Fatal(err)
	}
	if got := <-done; !strings.Contains(got, "not the one approved") || len(r.sent) != 0 {
		t.Fatalf("waiter answered %s with %d sends; want a refusal and none", got, len(r.sent))
	}
}

func TestFrontedWaiterRefusesWhenTheRecordedApprovalBindsAnotherCall(t *testing.T) {
	srv, child, _ := frontedRig(t, "", 2*time.Second)
	q, dir := swapQueue(t, srv)
	done := make(chan string, 1)
	go func() {
		done <- callT(t, srv, "execute_action", map[string]string{"category": "faker", "action": "write_thing", "args": `{"path":"/a"}`})
	}()
	id := awaitPending(t, q)
	forgeDigest(t, dir, id)
	if _, err := q.Decide(id, true, "operator"); err != nil {
		t.Fatal(err)
	}
	if got := <-done; !strings.Contains(got, "not the one approved") || len(child.called) != 0 {
		t.Fatalf("fronted waiter answered %s, child calls %v; want a refusal and none", got, child.called)
	}
}
