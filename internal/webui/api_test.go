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

func rig(t *testing.T) (http.Handler, Deps, *approval.Queue, *fakeStore) {
	t.Helper()
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
	q := approval.New(time.Minute)
	d := Deps{
		Config: cfg, Store: store, Queue: q,
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
