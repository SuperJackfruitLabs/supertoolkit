package native

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// api.x.com negotiates HTTP/2 whenever the client offers it. The managed client
// restricted Protocols to HTTP/1 but still offered "h2" in ALPN, so every
// publisher request to X failed as a malformed response before anything was
// sent. A server that speaks HTTP/2 is the case that matters.
func TestManagedTransportSpeaksHTTP1ToAnHTTP2Server(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Proto", r.Proto)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	tr := managedTransport()
	tr.TLSClientConfig.RootCAs = srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: managedStatusTransport{tr}}).Do(req)
	if err != nil {
		t.Fatalf("request to an HTTP/2-capable server failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || resp.Proto != "HTTP/1.1" || resp.Header.Get("X-Proto") != "HTTP/1.1" {
		t.Errorf("status %d, client proto %q, server saw %q; want 401 over HTTP/1.1", resp.StatusCode, resp.Proto, resp.Header.Get("X-Proto"))
	}
}

func TestManagedTransportOffersOnlyHTTP1InALPN(t *testing.T) {
	got := managedTransport().TLSClientConfig.NextProtos
	if len(got) != 1 || got[0] != "http/1.1" {
		t.Errorf("ALPN = %v, want only http/1.1", got)
	}
}
