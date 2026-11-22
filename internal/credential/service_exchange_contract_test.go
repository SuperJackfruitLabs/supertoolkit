package credential

// Contract test: stk's side of the Organization plane's exchangeServiceToken (crossing
// accounts.plane-api), run against treaty's document and cases, vendored under testdata/treaty/.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/treatytest"
)

const (
	planeAPI   = "schemas/http/accounts/plane.v1.openapi.json"
	planeCases = "fixtures/http/accounts/plane.v1.cases.json"
)

func TestContractExchangeServiceTokenReadsEveryResponse(t *testing.T) {
	api := treatytest.Load(t, planeAPI)
	request := api.Request(t, "exchangeServiceToken")
	treatytest.CheckCorpus(t, request, treatytest.LoadCases(t, planeCases, "exchangeServiceToken", "request"))
	cases := treatytest.LoadCases(t, planeCases, "exchangeServiceToken", "200")
	treatytest.CheckCorpus(t, api.Response(t, "exchangeServiceToken", "200"), cases)
	for _, c := range cases.Valid {
		var want struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int64  `json:"expires_in"`
		}
		if err := json.Unmarshal(c.Body, &want); err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			if err := request.Validate(raw); err != nil {
				t.Errorf("exchange body %s: %v", raw, err)
			}
			_, _ = w.Write(c.Body)
		}))
		before := time.Now()
		tok, exp, err := ExchangeService(srv.Client(), serviceTarget(srv.URL))(context.Background(), "svc", Material{FieldToken: svcSecret})
		srv.Close()
		if err != nil {
			t.Errorf("%q: %v", c.Name, err)
			continue
		}
		lifetime := time.Duration(want.ExpiresIn) * time.Second
		if tok != want.AccessToken || exp.Before(before.Add(lifetime)) || exp.After(time.Now().Add(lifetime)) {
			t.Errorf("%q: token %q expiring %v; want the case's token for %v", c.Name, tok, exp, lifetime)
		}
	}
}
