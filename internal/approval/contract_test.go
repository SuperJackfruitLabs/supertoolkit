package approval

// Contract tests: stk's side of the superpipeline.approvals crossing, run against treaty's
// OpenAPI document and case corpus (vendored under testdata/treaty/ by `treaty sync`). Every
// valid response case goes through the client stk ships, and every body stk builds is
// validated against the request schema the board parses.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/treatytest"
)

const (
	approvalsAPI   = "schemas/http/superpipeline/approvals.v1.openapi.json"
	approvalsCases = "fixtures/http/superpipeline/approvals.v1.cases.json"
)

func approvalsContract(t *testing.T) *treatytest.API {
	t.Helper()
	return treatytest.Load(t, approvalsAPI)
}

// responseCases loads one response part and proves the schema reads it (every valid case
// passes, every invalid one fails) before the client is trusted with it.
func responseCases(t *testing.T, api *treatytest.API, operationID, status string) treatytest.Cases {
	t.Helper()
	cases := treatytest.LoadCases(t, approvalsCases, operationID, status)
	treatytest.CheckCorpus(t, api.Response(t, operationID, status), cases)
	return cases
}

func decodeCase(t *testing.T, c treatytest.Case, out any) {
	t.Helper()
	if err := json.Unmarshal(c.Body, out); err != nil {
		t.Fatalf("case %q: %v", c.Name, err)
	}
}

func TestContractCreateApprovalRequestReadsEveryResponse(t *testing.T) {
	api := approvalsContract(t)
	h, _, e := hostedRig(t)
	ran := 0
	for _, status := range []string{"201", "200"} {
		for _, c := range responseCases(t, api, "createApprovalRequest", status).Valid {
			var want struct {
				ApprovalRequestID string `json:"approvalRequestId"`
				State             string `json:"state"`
			}
			decodeCase(t, c, &want)
			code, _ := strconv.Atoi(status)
			var calls []string
			var body map[string]any
			write := canned{cred: "write", status: code, out: string(c.Body), calls: &calls, body: &body}
			client := &SuperPipelineHTTPClient{BaseURL: "https://app.superpipeline.dev", DeliveryDo: write.Do}
			got, err := client.CreateApprovalRequest(context.Background(), testBoard, h.Request(e))
			if err != nil {
				t.Errorf("%s %q: %v", status, c.Name, err)
				continue
			}
			if got.ApprovalRequestID != want.ApprovalRequestID || got.State != want.State {
				t.Errorf("%s %q: read %+v; want %+v", status, c.Name, got, want)
			}
			ran++
		}
	}
	if ran == 0 {
		t.Fatal("no response case ran")
	}
}

func TestContractReadApprovalRequestReadsEveryResponse(t *testing.T) {
	api := approvalsContract(t)
	cases := responseCases(t, api, "readApprovalRequest", "200")
	for _, c := range cases.Valid {
		var want struct {
			ApprovalRequestID string  `json:"approvalRequestId"`
			RequestID         string  `json:"requestId"`
			State             string  `json:"state"`
			Option            *string `json:"option"`
			DecidedBy         *struct {
				PrincipalID string `json:"principalId"`
				Label       string `json:"label"`
			} `json:"decidedBy"`
			DecidedAt *string `json:"decidedAt"`
			Subject   struct {
				ID     string `json:"id"`
				Digest string `json:"digest"`
			} `json:"subject"`
			ExpiresAt string `json:"expiresAt"`
		}
		decodeCase(t, c, &want)
		var calls []string
		var body map[string]any
		read := canned{cred: "read", status: 200, out: string(c.Body), calls: &calls, body: &body}
		client := &SuperPipelineHTTPClient{BaseURL: "https://app.superpipeline.dev", ApprovalDo: read.Do}
		got, err := client.ReadApprovalRequest(context.Background(), testBoard, want.ApprovalRequestID)
		if err != nil {
			t.Errorf("%q: %v", c.Name, err)
			continue
		}
		gotJSON, _ := json.Marshal(got)
		wantJSON, _ := json.Marshal(want)
		if string(gotJSON) != string(wantJSON) {
			t.Errorf("%q: read %s; want %s", c.Name, gotJSON, wantJSON)
		}
		if want.State == "approved" && (got.Option == nil || got.DecidedBy == nil || got.DecidedBy.PrincipalID == "") {
			t.Errorf("%q: an approval read without its option or decider: %s", c.Name, gotJSON)
		}
	}
}

// subjectServer answers verify and delivery with one body each and validates what stk sent
// against the request schemas.
func subjectServer(t *testing.T, api *treatytest.API, verifyOut, deliveryOut string) (*SubjectBoundGate, func()) {
	t.Helper()
	verifyReq := api.Request(t, "verifyApprovalSubject")
	deliveryReq := api.Request(t, "recordApprovalDelivery")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/verify"):
			if err := verifyReq.Validate(raw); err != nil {
				t.Errorf("verify body %s: %v", raw, err)
			}
			_, _ = w.Write([]byte(verifyOut))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/delivery"):
			if err := deliveryReq.Validate(raw); err != nil {
				t.Errorf("delivery body %s: %v", raw, err)
			}
			_, _ = w.Write([]byte(deliveryOut))
		default:
			http.NotFound(w, r)
		}
	}))
	token := func(context.Context) (string, error) { return "fixture", nil }
	client := &SuperPipelineHTTPClient{BaseURL: srv.URL, HTTP: srv.Client(), ApprovalToken: token, DeliveryToken: token}
	return &SubjectBoundGate{SuperPipelineHTTPClient: client, SubjectID: testSubject}, srv.Close
}

func TestContractVerifyApprovalSubjectReadsEveryResponse(t *testing.T) {
	api := approvalsContract(t)
	for _, c := range responseCases(t, api, "verifyApprovalSubject", "200").Valid {
		var want GateConfirmation
		decodeCase(t, c, &want)
		var fields map[string]any
		decodeCase(t, c, &fields)
		for _, k := range []string{"approved", "deliveryMode", "digest", "gateId", "expiresAt", "gateStatus"} {
			if _, ok := fields[k]; !ok {
				t.Fatalf("%q lacks %s, which stk reads", c.Name, k)
			}
		}
		gate, done := subjectServer(t, api, string(c.Body), "{}")
		got, err := gate.Confirm(context.Background(), testBoard, testSubject, want.Digest)
		done()
		if err != nil {
			t.Errorf("%q: %v", c.Name, err)
			continue
		}
		if !reflect.DeepEqual(got, want) || got.GateStatus == "" || got.DeliveryMode == "" {
			t.Errorf("%q: read %+v; want %+v", c.Name, got, want)
		}
	}
}

func TestContractRecordApprovalDeliveryAcceptsEveryResponse(t *testing.T) {
	api := approvalsContract(t)
	for _, c := range responseCases(t, api, "recordApprovalDelivery", "200").Valid {
		var recorded struct {
			GateID string `json:"gateId"`
			Digest string `json:"digest"`
			URL    string `json:"liveUrl"`
		}
		decodeCase(t, c, &recorded)
		gate, done := subjectServer(t, api, "{}", string(c.Body))
		err := gate.RecordDelivered(context.Background(), testBoard, recorded.GateID, recorded.Digest, recorded.URL)
		done()
		if err != nil {
			t.Errorf("%q: %v", c.Name, err)
		}
	}
}

// The request schemas read treaty's corpus as the board does: the control for the body checks.
func TestContractRequestSchemasReadTheCorpus(t *testing.T) {
	api := approvalsContract(t)
	for _, op := range []string{"createApprovalRequest", "verifyApprovalSubject", "recordApprovalDelivery"} {
		cases := treatytest.LoadCases(t, approvalsCases, op, "request")
		if len(cases.Invalid) == 0 {
			t.Errorf("%s: no invalid request case; the control cannot fail", op)
		}
		treatytest.CheckCorpus(t, api.Request(t, op), cases)
	}
}

// Every body Host.Request builds is one the board accepts.
func TestContractHostRequestIsAcceptedByTheBoard(t *testing.T) {
	schema := approvalsContract(t).Request(t, "createApprovalRequest")
	h, _, e := hostedRig(t)
	variants := map[string]func(*Effect){
		"as submitted": func(*Effect) {},
		"no arguments": func(x *Effect) { x.Args = nil },
		"no profile":   func(x *Effect) { x.Profile = "" },
		"an argument cut to fit": func(x *Effect) {
			x.Args = map[string]string{"body": strings.Repeat("é", PreviewTextMax+1)}
		},
		"more arguments than fit": func(x *Effect) {
			x.Args = map[string]string{}
			for i := 0; i < 30; i++ {
				x.Args["arg"+strconv.Itoa(i)] = "v"
			}
		},
		"a long summary":             func(x *Effect) { x.Summary = strings.Repeat("s", 2000) },
		"an expiry with sub-seconds": func(x *Effect) { x.Expires = time.Date(2030, 1, 2, 3, 4, 5, 6e8, time.FixedZone("IST", 19800)) },
	}
	for name, mutate := range variants {
		x := *e
		mutate(&x)
		assertBoardAccepts(t, schema, h, &x, name)
	}
}

func assertBoardAccepts(t *testing.T, schema *treatytest.Schema, h *Host, e *Effect, name string) {
	t.Helper()
	body, err := json.Marshal(h.Request(e))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(body); err != nil {
		t.Errorf("%s: the board would refuse %s: %v", name, body, err)
	}
}

const testSubject = "aps_1e5c9a7f03b24d86"

// An empty requester, station, target or argument used to drop its block's value or text
// (omitempty), and the board refuses a block without one: such a request was refused 400
// INVALID_APPROVAL_REQUEST and the effect could never be approved. Each is now sent, as a
// placeholder the person can see.
func TestContractEmptyValuesAreShownNotDropped(t *testing.T) {
	schema := approvalsContract(t).Request(t, "createApprovalRequest")
	h, _, e := hostedRig(t)
	for name, tc := range map[string]struct {
		mutate func(*Host, *Effect)
		label  string
		want   string
	}{
		"no requester": {func(_ *Host, x *Effect) { x.Requester = "" }, "Requested by", "(unnamed)"},
		"no station":   {func(h *Host, _ *Effect) { h.Station = "" }, "Station", "(unnamed)"},
		"no target":    {func(_ *Host, x *Effect) { x.Target = "" }, "Target", emptyValue},
		"an empty argument": {func(_ *Host, x *Effect) { x.Args = map[string]string{"title": ""} },
			"Argument title", emptyValue},
	} {
		host, x := *h, *e
		tc.mutate(&host, &x)
		assertBoardAccepts(t, schema, &host, &x, name)
		r := host.Request(&x)
		found := false
		for _, b := range r.Subject.Preview {
			if b.Label == tc.label {
				found = true
				if b.Value+b.Text != tc.want {
					t.Errorf("%s: %s shows %q; want %q", name, tc.label, b.Value+b.Text, tc.want)
				}
			}
		}
		if !found {
			t.Errorf("%s: no %s block", name, tc.label)
		}
	}
}

// A block marshals with every property the board requires, even an empty one.
func TestPreviewBlockNeverOmitsItsValueOrText(t *testing.T) {
	for _, tc := range []struct {
		block PreviewBlock
		want  string
	}{
		{PreviewBlock{Type: "field", Label: "Station"}, `{"type":"field","label":"Station","value":""}`},
		{PreviewBlock{Type: "field"}, `{"type":"field","label":"","value":""}`},
		{PreviewBlock{Type: "text", Label: "Target"}, `{"type":"text","label":"Target","text":""}`},
		{PreviewBlock{Type: "text"}, `{"type":"text","text":""}`},
	} {
		got, err := json.Marshal(tc.block)
		if err != nil || string(got) != tc.want {
			t.Errorf("marshal %+v = %s, %v; want %s", tc.block, got, err, tc.want)
		}
	}
}
