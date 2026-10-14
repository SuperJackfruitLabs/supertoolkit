package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/approval"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

const storedSecret = "ghp_the_real_credential_the_ui_must_never_see"

// fakeStore mirrors the narrow view the UI gets: it can say whether a
// credential exists and name its fields, and it cannot return a value.
type fakeStore struct {
	have    map[string][]string
	revoked []string
}

func (f *fakeStore) Has(s string) bool        { _, ok := f.have[s]; return ok }
func (f *fakeStore) Fields(s string) []string { return f.have[s] }
func (f *fakeStore) Revoke(s string) error {
	f.revoked = append(f.revoked, s)
	delete(f.have, s)
	return nil
}

// performed records every effect the rig actually carried out, so a test can
// assert that approving causes the effect exactly once.
var performed []string

func rig(t *testing.T) (http.Handler, Deps, *approval.Queue, *fakeStore) {
	t.Helper()
	performed = nil
	p := filepath.Join(t.TempDir(), "supertoolkit.yaml")
	os.WriteFile(p, []byte(`
workspace: test
services:
  github:
    scopes: []
  aws-sts:
    scopes: []
servers:
  slack:
    command: /bin/true
    host: slack.com
    env_var: SLACK_BOT_TOKEN
`), 0o600)
	cfg, err := policy.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeStore{have: map[string][]string{
		"github":  {"token"},
		"aws-sts": {"access_key_id", "secret_access_key"},
	}}
	q, qerr := approval.Open(t.TempDir(), time.Minute)
	if qerr != nil {
		t.Fatal(qerr)
	}
	d := Deps{
		Config: cfg, Store: store, Queue: q,
		// The rig decides and performs, the way cmd/stk does, so the test
		// exercises the path a browser actually takes.
		Decide: func(id string, allow bool, who string) (*approval.Effect, error) {
			return q.DecideAndPerform(id, allow, who, func(e *approval.Effect) (string, error) {
				performed = append(performed, e.ID)
				return "201 Created", nil
			})
		},
		Status: func() []Check {
			return []Check{{Label: "leak check", State: "ok", Detail: "no credential reachable"}}
		},
		Audit: func(int) []Effect {
			return []Effect{{When: time.Now(), Category: "github", Action: "get_user",
				Policy: "agent", Caller: "default", Credential: "sha256:0e49c51e", Outcome: "200"}}
		},
		SetPolicy: func(string, string, policy.Action) error { return nil },
	}
	return API(d), d, q, store
}

func get(t *testing.T, h http.Handler, path string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	return rec.Code, rec.Body.String()
}

func post(t *testing.T, h http.Handler, path string, body any) (int, string) {
	t.Helper()
	b, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", path, bytes.NewReader(b))
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestEachScreenHasItsData(t *testing.T) {
	h, _, _, _ := rig(t)
	for _, path := range []string{"/api/status", "/api/services", "/api/policy", "/api/approvals", "/api/audit"} {
		code, body := get(t, h, path)
		if code != http.StatusOK {
			t.Errorf("%s = %d, want 200 (%s)", path, code, body)
		}
		if strings.TrimSpace(body) == "" {
			t.Errorf("%s returned nothing", path)
		}
	}
}

// The column the services screen exists for.
func TestServicesReportsWhatReachesTheWire(t *testing.T) {
	h, _, _, _ := rig(t)
	_, body := get(t, h, "/api/services")
	var out struct {
		Services []struct {
			Name      string   `json:"name"`
			Operation string   `json:"operation"`
			OnTheWire string   `json:"on_the_wire"`
			LongLived bool     `json:"long_lived_on_the_wire"`
			Connected bool     `json:"connected"`
			Fields    []string `json:"fields"`
		} `json:"services"`
	}
	json.Unmarshal([]byte(body), &out)
	by := map[string]int{}
	for i, s := range out.Services {
		by[s.Name] = i
	}
	gh := out.Services[by["github"]]
	if !gh.LongLived {
		t.Error("a substituted token should be reported as long-lived on the wire")
	}
	aws := out.Services[by["aws-sts"]]
	if aws.LongLived {
		t.Error("a signing service must not be reported as sending a long-lived secret")
	}
	if !strings.Contains(aws.OnTheWire, "never") {
		t.Errorf("aws-sts on_the_wire = %q, want it to say the key stays behind", aws.OnTheWire)
	}
	// Field names are safe to show; values are not, and there is no path to one.
	if len(aws.Fields) != 2 {
		t.Errorf("aws-sts fields = %v, want the two field names", aws.Fields)
	}
}

// The leak assertion, repeated on this surface rather than assumed from the MCP
// layer, because a second surface is a second chance to get it wrong.
func TestNoResponseContainsACredential(t *testing.T) {
	h, _, q, _ := rig(t)
	q.Submit("github", "create_issue", "Open an issue", map[string]string{"title": "t"})

	paths := []string{"/api/status", "/api/services", "/api/policy", "/api/approvals", "/api/audit"}
	for _, p := range paths {
		_, body := get(t, h, p)
		if strings.Contains(body, storedSecret) {
			t.Fatalf("%s leaked a credential", p)
		}
	}
	// Error paths too.
	for _, c := range []struct {
		path string
		body any
	}{
		{"/api/policy", map[string]string{"category": "nope", "action": "nope", "policy": "agent"}},
		{"/api/approvals/decide", map[string]string{"id": "nope", "allow": "true"}},
		{"/api/services/revoke", map[string]string{"service": "nope"}},
	} {
		_, body := post(t, h, c.path, c.body)
		if strings.Contains(body, storedSecret) {
			t.Fatalf("%s error path leaked a credential", c.path)
		}
	}
}

func TestPolicyChangePersists(t *testing.T) {
	h, _, _, _ := rig(t)
	code, body := post(t, h, "/api/policy", map[string]string{
		"category": "github", "action": "get_user", "policy": "approval"})
	if code != http.StatusOK {
		t.Fatalf("setting a policy = %d (%s)", code, body)
	}
	if !strings.Contains(body, "approval") {
		t.Errorf("response = %s, want the new policy", body)
	}
}

// The UI is not a way around the rule that irreversible effects wait for a
// person. Deny is always available; promotion past the ceiling is not.
func TestAWriteCannotBePromotedToAgentFromTheUI(t *testing.T) {
	h, _, _, _ := rig(t)
	code, body := post(t, h, "/api/policy", map[string]string{
		"category": "github", "action": "delete_repo", "policy": "agent"})
	if code != http.StatusForbidden {
		t.Fatalf("promoting a destructive action = %d, want 403 (%s)", code, body)
	}
	if !strings.Contains(body, "ceiling") {
		t.Errorf("the refusal should explain the ceiling: %s", body)
	}
	// But denying it is always allowed.
	code, _ = post(t, h, "/api/policy", map[string]string{
		"category": "github", "action": "delete_repo", "policy": "deny"})
	if code != http.StatusOK {
		t.Fatalf("denying a destructive action = %d, want 200", code)
	}
}

func TestApprovalDecidesOnceThroughTheAPI(t *testing.T) {
	h, _, q, _ := rig(t)
	e := q.Submit("github", "create_issue", "Open an issue", nil)

	code, body := post(t, h, "/api/approvals/decide", map[string]any{"id": e.ID, "allow": true, "who": "rakesh"})
	if code != http.StatusOK {
		t.Fatalf("deciding = %d (%s)", code, body)
	}
	if !strings.Contains(body, "approved") || !strings.Contains(body, "rakesh") {
		t.Errorf("response = %s", body)
	}
	// A second decision must be refused, not performed again.
	code, _ = post(t, h, "/api/approvals/decide", map[string]any{"id": e.ID, "allow": true})
	if code != http.StatusConflict {
		t.Fatalf("a second decision = %d, want 409", code)
	}
}

func TestRevokeRemovesTheCredential(t *testing.T) {
	h, _, _, store := rig(t)
	code, _ := post(t, h, "/api/services/revoke", map[string]string{"service": "github"})
	if code != http.StatusOK {
		t.Fatalf("revoke = %d", code)
	}
	if store.Has("github") {
		t.Fatal("the credential is still stored after revoke")
	}
	if len(store.revoked) != 1 || store.revoked[0] != "github" {
		t.Errorf("revoked = %v", store.revoked)
	}
}

// Every write must sit behind the token, which the handler wraps.
func TestWritesAreBehindTheToken(t *testing.T) {
	api, _, _, _ := rig(t)
	h, err := Handler(Options{Token: "tok", API: api})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/api/policy", "/api/approvals/decide", "/api/services/revoke"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", p, strings.NewReader(`{}`))
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without a token = %d, want 401", p, rec.Code)
		}
	}
}

// The UI is a separate program that reads these responses by field name, so the
// field names are a contract. This pins them.
//
// Without it, adding JSON tags to an internal struct renamed every field in
// /api/approvals, the screen rendered blank rows reading "NaNh ago", and the
// Approve and Refuse buttons silently disappeared because they are gated on a
// state that had become undefined. Nothing failed; the page just stopped
// working. A shape test is the only thing that catches that.
func TestAPIShapesAreStable(t *testing.T) {
	h, _, q, _ := rig(t)
	q.Submit("github", "create_issue", "Open an issue.", map[string]string{"title": "t"})

	cases := []struct {
		path string
		list string
		want []string
	}{
		{"/api/approvals", "effects", []string{
			"id", "service", "capability", "summary", "args", "submitted", "expires", "state", "decided_by"}},
		{"/api/audit", "effects", []string{
			"when", "category", "action", "policy", "caller", "credential", "outcome"}},
		{"/api/status", "checks", []string{"label", "state", "detail"}},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest("GET", c.path, nil))
			if rec.Code != 200 {
				t.Fatalf("status %d", rec.Code)
			}
			// A response may carry scalars beside its list, so decode loosely
			// and inspect only the list this screen reads.
			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("not JSON: %v — %s", err, rec.Body.String())
			}
			raw, ok := body[c.list].([]any)
			if !ok || len(raw) == 0 {
				t.Fatalf("%q held no rows: %s", c.list, rec.Body.String())
			}
			row, ok := raw[0].(map[string]any)
			if !ok {
				t.Fatalf("%q[0] is not an object: %s", c.list, rec.Body.String())
			}
			for _, field := range c.want {
				if _, ok := row[field]; !ok {
					t.Errorf("field %q is missing — the UI reads it by name and will render blank", field)
				}
			}
		})
	}
}

// The approvals response must never carry a credential, and must carry enough
// for a person to judge the act rather than a description of it.
func TestApprovalsCarryTheRequestAndNoCredential(t *testing.T) {
	h, _, q, _ := rig(t)
	q.Submit("github", "create_issue", "Open an issue.", map[string]string{
		"owner": "o", "repo": "r", "title": "the exact title that would be sent"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/approvals", nil))
	body := rec.Body.String()

	for _, want := range []string{"the exact title that would be sent", "create_issue", "pending"} {
		if !strings.Contains(body, want) {
			t.Errorf("the response does not carry %q, so a person cannot judge the act", want)
		}
	}
	for _, never := range []string{"ghp_", "secret", "token"} {
		if strings.Contains(strings.ToLower(body), never) {
			t.Errorf("the response mentions %q", never)
		}
	}
}

// Approving from a browser must cause the effect, not merely record that
// someone said yes.
//
// This is the bug that made the audit trail false: the decision was written and
// no code anywhere performed the effect, so `approved` meant nothing had
// happened. It passed every test, because no test asked whether the effect
// occurred — only whether the decision was recorded.
func TestApprovingCausesTheEffectAndRecordsWhatHappened(t *testing.T) {
	h, _, q, _ := rig(t)
	e := q.Submit("github", "create_issue", "Open an issue.", map[string]string{"title": "t"})

	body := strings.NewReader(`{"id":"` + e.ID + `","allow":true,"who":"web"}`)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/api/approvals/decide", body))
	if rec.Code != 200 {
		t.Fatalf("deciding = %d (%s)", rec.Code, rec.Body.String())
	}

	if len(performed) != 1 || performed[0] != e.ID {
		t.Fatalf("the effect ran %d time(s); approving must cause it", len(performed))
	}
	// The response says what happened, not only that it was allowed.
	if !strings.Contains(rec.Body.String(), "201 Created") {
		t.Errorf("the response does not say what happened: %s", rec.Body.String())
	}
	// And the record carries the outcome, so the trail is true.
	got, ok := q.Get(e.ID)
	if !ok {
		t.Fatal("the effect vanished")
	}
	if got.Outcome != "201 Created" {
		t.Errorf("recorded outcome = %q, want what the provider answered", got.Outcome)
	}
	if !got.Performs {
		t.Error("the record does not say the decider carried it out, so a waiter might run it again")
	}
}

// Refusing must perform nothing at all.
func TestRefusingPerformsNothing(t *testing.T) {
	h, _, q, _ := rig(t)
	e := q.Submit("github", "create_issue", "Open an issue.", nil)

	body := strings.NewReader(`{"id":"` + e.ID + `","allow":false,"who":"web"}`)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/api/approvals/decide", body))
	if rec.Code != 200 {
		t.Fatalf("deciding = %d (%s)", rec.Code, rec.Body.String())
	}
	if len(performed) != 0 {
		t.Fatalf("a refusal performed %d effect(s)", len(performed))
	}
}
