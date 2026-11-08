package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/approval"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/daemon"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

func newTestService(t *testing.T, yaml string) *Service {
	svc, _ := newTestServiceDir(t, yaml)
	return svc
}

func newTestServiceDir(t *testing.T, yaml string) (*Service, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "supertoolkit.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := policy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	store, err := credential.OpenStore(filepath.Join(dir, "credentials"), "fixture")
	if err != nil {
		t.Fatal(err)
	}
	svc, err := New(cfg, store, filepath.Join(dir, "state"), "serve", "test")
	if err != nil {
		t.Fatal(err)
	}
	return svc, filepath.Join(dir, "state")
}

// Regression guarded: approvals.decide recorded the `who` its caller sent, so
// any caller could write any name into the record of who approved.
func TestDecideRecordsThePeerNotTheClaimedName(t *testing.T) {
	svc := newTestService(t, "workspace: test\nservices:\n  github:\n    scopes: []\n")
	e := svc.Queue.Submit("github", "create_issue", "Open an issue", map[string]string{"owner": "o", "repo": "r", "title": "t"})
	params, _ := json.Marshal(map[string]any{"id": e.ID, "allow": false, "who": "mallory"})
	resp := svc.Handle(4242, daemon.Request{Method: "approvals.decide", Params: params})
	if resp.Error != "" {
		t.Fatalf("decide: %s", resp.Error)
	}
	got, _ := svc.Queue.Get(e.ID)
	if got.DecidedBy != daemon.Identity(4242) || strings.Contains(got.DecidedBy, "mallory") {
		t.Fatalf("recorded decider = %q; want the peer's identity %q", got.DecidedBy, daemon.Identity(4242))
	}
	var out map[string]string
	_ = json.Unmarshal(resp.Result, &out)
	if out["by"] != daemon.Identity(4242) {
		t.Fatalf("response by = %q; want %q", out["by"], daemon.Identity(4242))
	}
}

const githubWriter = "workspace: test\nservices:\n  github:\n    scopes: []\n"

func submitThroughDaemon(t *testing.T, svc *Service) string {
	t.Helper()
	params, _ := json.Marshal(map[string]string{"category": "github", "action": "create_issue",
		"args": `{"owner":"o","repo":"r","title":"t"}`})
	resp := svc.Handle(4242, daemon.Request{Method: "execute_action", Params: params})
	if resp.Error != "" {
		t.Fatal(resp.Error)
	}
	pending := svc.Queue.Pending()
	if len(pending) != 1 {
		t.Fatalf("pending = %d, want 1 (%s)", len(pending), resp.Result)
	}
	return pending[0].ID
}

func countingPerform(svc *Service) *int {
	n := 0
	svc.Perform = func(ctx context.Context, service string, req *http.Request) (*http.Response, error) {
		n++
		return &http.Response{StatusCode: 201, Status: "201 Created", Body: io.NopCloser(strings.NewReader("{}"))}, nil
	}
	return &n
}

func TestApprovedRequestMatchingItsDigestIsPerformed(t *testing.T) {
	svc := newTestService(t, githubWriter)
	id := submitThroughDaemon(t, svc)
	e, _ := svc.Queue.Get(id)
	if !strings.HasPrefix(e.RequestDigest, "sha256:") || e.Requester != daemon.Identity(4242) {
		t.Fatalf("effect digest=%q requester=%q; want a bound digest and the peer as requester", e.RequestDigest, e.Requester)
	}
	sends := countingPerform(svc)
	got, err := svc.DecideAndPerform(id, true, "operator")
	if err != nil || *sends != 1 || got.Outcome != "201 Created" {
		t.Fatalf("perform: sends=%d outcome=%q err=%v", *sends, got.Outcome, err)
	}
}

// Regression guarded: an approval named an effect by id only, so a request
// changed after submission (an edited record, a reloaded catalogue) was
// performed under an approval given for something else.
func TestApprovedRequestThatChangedIsRefusedAndRecorded(t *testing.T) {
	svc, state := newTestServiceDir(t, githubWriter)
	id := submitThroughDaemon(t, svc)
	tamper(t, state, id, func(e map[string]any) {
		e["args"].(map[string]any)["repo"] = "other"
	})
	sends := countingPerform(svc)
	_, err := svc.DecideAndPerform(id, true, "operator")
	if *sends != 0 || err == nil || !strings.Contains(err.Error(), "not the one approved") {
		t.Fatalf("tampered request: sends=%d err=%v; want a refusal without a send", *sends, err)
	}
	got, _ := svc.Queue.Get(id)
	if got.Outcome != "refused" || !strings.Contains(got.Error, "not the one approved") {
		t.Fatalf("recorded outcome=%q error=%q; want the refusal recorded", got.Outcome, got.Error)
	}
}

func TestApprovalWithoutADigestIsNeverPerformed(t *testing.T) {
	svc := newTestService(t, githubWriter)
	e := svc.Queue.Submit("github", "create_issue", "Open an issue", map[string]string{"owner": "o", "repo": "r", "title": "t"})
	sends := countingPerform(svc)
	if _, err := svc.DecideAndPerform(e.ID, true, "operator"); err == nil || *sends != 0 {
		t.Fatalf("digest-less approval: sends=%d err=%v", *sends, err)
	}
}

// tamper rewrites a queued request record, as anyone with write access to the
// state directory could.
func tamper(t *testing.T, state, id string, edit func(map[string]any)) {
	t.Helper()
	path := filepath.Join(state, "approvals", id+".req")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var e map[string]any
	_ = json.Unmarshal(raw, &e)
	edit(e)
	raw, _ = json.Marshal(e)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

const hostedPolicy = githubWriter + "  superpipeline-approvals-read:\n    scopes: []\n  superpipeline-approvals-write:\n    scopes: []\n" +
	"superpipeline:\n  approvals_board: brd_fixture\n"

// With an approvals board, execute_action hosts the approval and even an
// operator uid cannot decide it locally.
func TestHostedPolicyHostsAndRefusesLocalDecide(t *testing.T) {
	svc := newTestService(t, hostedPolicy)
	svc.Perform = func(ctx context.Context, service string, req *http.Request) (*http.Response, error) {
		// No credential is connected in the test: the create fails, as an
		// unreachable SuperPipeline would.
		return nil, errors.New("no credential connected")
	}
	id := submitThroughDaemon(t, svc)
	e, _ := svc.Queue.Get(id)
	if e.HostedBoard != "brd_fixture" || e.Target != "POST https://api.github.com/repos/o/r/issues" {
		t.Fatalf("effect board=%q target=%q", e.HostedBoard, e.Target)
	}
	params, _ := json.Marshal(map[string]any{"id": id, "allow": true})
	resp := svc.Handle(0, daemon.Request{Method: "approvals.decide", Params: params})
	if !strings.Contains(resp.Error, "SuperPipeline") {
		t.Fatalf("operator decide on a hosted effect = %+v; want a refusal", resp)
	}
	if got, _ := svc.Queue.Get(id); got.State != "pending" {
		t.Fatalf("state = %q after a refused local decide", got.State)
	}
}

func TestHostingUsesNativeOnlyServiceCredentials(t *testing.T) {
	svc := newTestService(t, hostedPolicy)
	var seen []string
	svc.Perform = func(ctx context.Context, service string, req *http.Request) (*http.Response, error) {
		seen = append(seen, service+" "+req.Method+" "+req.URL.Host+req.URL.Path)
		return &http.Response{StatusCode: 201, Body: io.NopCloser(strings.NewReader(`{"approvalRequestId":"apr_x","state":"pending"}`))}, nil
	}
	h := svc.Hosting()
	if h == nil || h.Board != "brd_fixture" {
		t.Fatalf("Hosting() = %+v", h)
	}
	e := svc.Queue.SubmitRequest(approvalSubmission())
	if _, err := h.Publish(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0] != "superpipeline-approvals-write POST app.superpipeline.dev/v1/boards/brd_fixture/approval-requests" {
		t.Fatalf("calls = %v", seen)
	}
	if newTestService(t, githubWriter).Hosting() != nil {
		t.Fatal("a policy without a board hosted approvals")
	}
}

func approvalSubmission() approval.Submission {
	return approval.Submission{Service: "github", Capability: "create_issue", Summary: "Open an issue",
		Args: map[string]string{"owner": "o"}, Digest: "sha256:x", HostedBoard: "brd_fixture"}
}
