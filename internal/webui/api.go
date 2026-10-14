package webui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/approval"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/catalog"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

// Store is the narrow view the UI needs of credentials.
//
// Deliberately narrow: it can ask **whether** a credential exists and what
// fields it has, and it can revoke one. There is no method here that returns a
// value, because the UI holds no privilege to read a secret.
type Store interface {
	Has(service string) bool
	Fields(service string) []string
	Revoke(service string) error
}

// Deps are what the API needs from the rest of the program.
type Deps struct {
	Config *policy.Config
	Store  Store
	Queue  *approval.Queue
	// Status supplies the doctor-style checks the status screen shows.
	Status func() []Check
	// Audit supplies recent effects.
	Audit func(limit int) []Effect
	// SetPolicy persists one capability's policy.
	SetPolicy func(category, action string, a policy.Action) error
}

// Check is one status line.
type Check struct {
	Label  string `json:"label"`
	State  string `json:"state"` // ok | warn | bad
	Detail string `json:"detail"`
}

// Effect is one audited effect, as the audit screen shows it.
type Effect struct {
	When     time.Time `json:"when"`
	Category string    `json:"category"`
	Action   string    `json:"action"`
	Policy   string    `json:"policy"`
	Caller   string    `json:"caller"`
	// Credential is a fingerprint or a description of what was sent. Never a
	// credential; there is a test that asserts so.
	Credential string `json:"credential"`
	Outcome    string `json:"outcome"`
}

// API builds the data handler.
func API(d Deps) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/status", d.status)
	mux.HandleFunc("GET /api/services", d.services)
	mux.HandleFunc("GET /api/policy", d.policy)
	mux.HandleFunc("GET /api/approvals", d.approvals)
	mux.HandleFunc("GET /api/audit", d.audit)
	mux.HandleFunc("POST /api/policy", d.setPolicy)
	mux.HandleFunc("POST /api/approvals/decide", d.decide)
	mux.HandleFunc("POST /api/services/revoke", d.revoke)
	return mux
}

func write(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, format string, a ...any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf(format, a...)})
}

func (d Deps) status(w http.ResponseWriter, r *http.Request) {
	checks := []Check{}
	if d.Status != nil {
		checks = d.Status()
	}
	write(w, map[string]any{
		"workspace": d.Config.Workspace,
		"services":  len(d.Config.Services()),
		"servers":   len(d.Config.Servers()),
		"profiles":  d.Config.Profiles(),
		"pending":   len(d.Queue.Pending()),
		"checks":    checks,
	})
}

// serviceView is what the services screen shows.
//
// `OnTheWire` is the column this screen exists for: it is the difference
// between a stored token that travels and a key that stays behind, which is what
// an operator needs when deciding how carefully to treat a credential.
type serviceView struct {
	Name      string   `json:"name"`
	Host      string   `json:"host"`
	Kind      string   `json:"kind"`
	Operation string   `json:"operation"`
	OnTheWire string   `json:"on_the_wire"`
	LongLived bool     `json:"long_lived_on_the_wire"`
	Connected bool     `json:"connected"`
	Fields    []string `json:"fields"`
}

func (d Deps) services(w http.ResponseWriter, r *http.Request) {
	out := []serviceView{}
	for _, name := range d.Config.Services() {
		svc, _ := d.Config.Service(name)
		e := svc.Entry()
		v := serviceView{
			Name: name, Host: e.Host, Kind: "service",
			Operation: e.Auth.String(), OnTheWire: e.Auth.Reassurance(),
			LongLived: e.Auth.LongLivedOnTheWire(),
			Connected: d.Store.Has(name), Fields: d.Store.Fields(name),
		}
		out = append(out, v)
	}
	for _, name := range d.Config.Servers() {
		srv, _ := d.Config.Server(name)
		out = append(out, serviceView{
			Name: name, Host: srv.Host, Kind: "fronted server",
			Operation: catalog.AuthToken.String(), OnTheWire: catalog.AuthToken.Reassurance(),
			LongLived: true, Connected: d.Store.Has(name), Fields: d.Store.Fields(name),
		})
	}
	write(w, map[string]any{"services": out})
}

type policyRow struct {
	Category string `json:"category"`
	Kind     string `json:"kind"`
	Action   string `json:"action"`
	Policy   string `json:"policy"`
	Summary  string `json:"summary"`
	// Ceiling is the strongest policy this action may be given. A destructive
	// action can never be promoted to agent from this screen.
	Ceiling string `json:"ceiling"`
}

func (d Deps) policy(w http.ResponseWriter, r *http.Request) {
	rows := []policyRow{}
	for _, name := range d.Config.Services() {
		svc, _ := d.Config.Service(name)
		for _, c := range svc.Entry().Capabilities {
			rows = append(rows, policyRow{
				Category: name, Kind: "service", Action: c.Name,
				Policy: svc.Policy(c.Name).String(), Summary: c.Summary,
				Ceiling: ceilingFor(c.Kind).String(),
			})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Category != rows[j].Category {
			return rows[i].Category < rows[j].Category
		}
		return rows[i].Action < rows[j].Action
	})
	write(w, map[string]any{"rows": rows})
}

// ceilingFor is the strongest policy an action of this kind may be given.
//
// A read may be handed to an agent. Anything that changes the world may not be
// promoted past approval from a screen — the UI is not a way around the rule
// that unknown and irreversible effects wait for a person.
func ceilingFor(k catalog.Kind) policy.Action {
	if k == catalog.Read {
		return policy.ActionAgent
	}
	return policy.ActionApproval
}

func (d Deps) approvals(w http.ResponseWriter, r *http.Request) {
	write(w, map[string]any{"effects": d.Queue.List()})
}

func (d Deps) audit(w http.ResponseWriter, r *http.Request) {
	out := []Effect{}
	if d.Audit != nil {
		out = d.Audit(200)
	}
	write(w, map[string]any{"effects": out})
}

func (d Deps) setPolicy(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Category string `json:"category"`
		Action   string `json:"action"`
		Policy   string `json:"policy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		fail(w, http.StatusBadRequest, "could not read the request: %v", err)
		return
	}
	want, err := policy.ParseAction(p.Policy)
	if err != nil {
		fail(w, http.StatusBadRequest, "%v", err)
		return
	}
	svc, ok := d.Config.Service(p.Category)
	if !ok {
		fail(w, http.StatusNotFound, "no service %q", p.Category)
		return
	}
	c, known := svc.Entry().Capability(p.Action)
	if !known {
		fail(w, http.StatusNotFound, "no action %q in %q", p.Action, p.Category)
		return
	}
	// The ceiling. Deny is always available; promotion past it is not.
	if want == policy.ActionAgent && ceilingFor(c.Kind) != policy.ActionAgent {
		fail(w, http.StatusForbidden,
			"%s/%s changes the world, so it cannot be made agent-callable from here; approval is its ceiling",
			p.Category, p.Action)
		return
	}
	if d.SetPolicy == nil {
		fail(w, http.StatusNotImplemented, "this build cannot persist policy changes")
		return
	}
	if err := d.SetPolicy(p.Category, p.Action, want); err != nil {
		fail(w, http.StatusInternalServerError, "%v", err)
		return
	}
	write(w, map[string]string{"category": p.Category, "action": p.Action, "policy": want.String()})
}

func (d Deps) decide(w http.ResponseWriter, r *http.Request) {
	var p struct {
		ID    string `json:"id"`
		Allow bool   `json:"allow"`
		Who   string `json:"who"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		fail(w, http.StatusBadRequest, "could not read the request: %v", err)
		return
	}
	if p.Who == "" {
		p.Who = "web"
	}
	if err := d.Queue.Decide(p.ID, p.Allow, p.Who); err != nil {
		fail(w, http.StatusConflict, "%v", err)
		return
	}
	state := "refused"
	if p.Allow {
		state = "approved"
	}
	write(w, map[string]string{"id": p.ID, "state": state, "by": p.Who})
}

func (d Deps) revoke(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Service string `json:"service"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		fail(w, http.StatusBadRequest, "could not read the request: %v", err)
		return
	}
	if err := d.Store.Revoke(p.Service); err != nil {
		fail(w, http.StatusInternalServerError, "%v", err)
		return
	}
	write(w, map[string]string{"service": p.Service, "state": "revoked"})
}
