package credential

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A fixture, not a credential: assembled so it reads as no literal secret.
var svcSecret = "svc_" + "ZZstoredZZ:ZZsecretZZ"

func serviceTarget(url string) func(string) (ServiceExchangeTarget, error) {
	return func(string) (ServiceExchangeTarget, error) {
		return ServiceExchangeTarget{TokenURL: url, Audience: "https://app.superpipeline.dev"}, nil
	}
}

func TestExchangeServicePresentsTheStoredCredentialAndAudienceOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer "+svcSecret {
			w.WriteHeader(401)
			return
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body) != 1 || body["audience"] != "https://app.superpipeline.dev" {
			w.WriteHeader(400)
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"ZZshortZZ","token_type":"Bearer","expires_in":300}`))
	}))
	defer srv.Close()
	before := time.Now()
	tok, exp, err := ExchangeService(srv.Client(), serviceTarget(srv.URL))(context.Background(), "svc", Material{FieldToken: svcSecret})
	if err != nil || tok != "ZZshortZZ" {
		t.Fatalf("token = %q, err = %v", tok, err)
	}
	if exp.Before(before.Add(299*time.Second)) || exp.After(time.Now().Add(301*time.Second)) {
		t.Errorf("expires = %v, want about five minutes from now", exp)
	}
}

func TestExchangeServiceRefusalNeverEchoesTheBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(401)
		_, _ = w.Write([]byte("bad " + svcSecret)) // a body echoing the credential
	}))
	defer srv.Close()
	_, _, err := ExchangeService(srv.Client(), serviceTarget(srv.URL))(context.Background(), "svc", Material{FieldToken: svcSecret})
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("err = %v, want the status", err)
	}
	if strings.Contains(err.Error(), "ZZsecretZZ") || strings.Contains(err.Error(), "bad") {
		t.Errorf("err = %v: it echoes the response body", err)
	}
}

// A redirect would carry the stored credential to wherever it points.
func TestExchangeServiceDoesNotFollowARedirect(t *testing.T) {
	var leaked atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Store(true)
		}
		_, _ = w.Write([]byte(`{"access_token":"x","expires_in":300}`))
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	_, _, err := ExchangeService(srv.Client(), serviceTarget(srv.URL))(context.Background(), "svc", Material{FieldToken: svcSecret})
	if err == nil {
		t.Error("a redirect was followed to a token")
	}
	if leaked.Load() {
		t.Error("the stored credential reached the redirect target")
	}
}

func TestExchangeServiceRefusesAMissingTargetOrToken(t *testing.T) {
	ex := ExchangeService(http.DefaultClient, func(string) (ServiceExchangeTarget, error) { return ServiceExchangeTarget{}, nil })
	if _, _, err := ex(context.Background(), "svc", Material{FieldToken: svcSecret}); err == nil {
		t.Error("exchanged with no endpoint configured")
	}
	ex = ExchangeService(http.DefaultClient, func(string) (ServiceExchangeTarget, error) { return ServiceExchangeTarget{}, errors.New("unknown") })
	if _, _, err := ex(context.Background(), "svc", Material{}); err == nil {
		t.Error("exchanged with no stored token")
	}
}

// Rule 4: twenty concurrent callers cause one exchange.
func TestServiceExchangeIsSingleFlight(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write([]byte(`{"access_token":"ZZshortZZ","expires_in":300}`))
	}))
	defer srv.Close()
	a := &Acquirer{
		Material: func(string) (Material, error) { return Material{FieldToken: svcSecret}, nil },
		Exchange: ExchangeService(srv.Client(), serviceTarget(srv.URL)),
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if tok, err := a.Token(context.Background(), "svc"); err != nil || tok != "ZZshortZZ" {
				t.Errorf("token = %q, err = %v", tok, err)
			}
		}()
	}
	wg.Wait()
	if n := calls.Load(); n != 1 {
		t.Errorf("exchanges = %d, want 1", n)
	}
}
