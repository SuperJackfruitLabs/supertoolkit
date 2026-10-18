package broker

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

const theProxyKey = "pk_s3cret/with:odd@chars?&="

func basic(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// rawProxy sends one request line plus headers to the broker and returns the
// response, without letting any client library add or strip proxy headers.
func rawProxy(t *testing.T, f *fixture, requestLine string, headers map[string]string) *http.Response {
	t.Helper()
	c, err := net.DialTimeout("tcp", f.proxyURL.Host, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(10 * time.Second))
	var sb strings.Builder
	sb.WriteString(requestLine + "\r\n")
	sb.WriteString("Host: api.github.com:443\r\n")
	for k, v := range headers {
		sb.WriteString(k + ": " + v + "\r\n")
	}
	sb.WriteString("\r\n")
	if _, err := io.WriteString(c, sb.String()); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestProxyKeyRequiredWhenSet(t *testing.T) {
	connect := "CONNECT api.github.com:443 HTTP/1.1"
	cases := []struct {
		name, line string
		headers    map[string]string
	}{
		{"no header", connect, nil},
		{"wrong key", connect, map[string]string{"Proxy-Authorization": basic("stk", "nope")}},
		{"bearer scheme", connect, map[string]string{"Proxy-Authorization": "Bearer " + theProxyKey}},
		{"malformed base64", connect, map[string]string{"Proxy-Authorization": "Basic !!!not-base64"}},
		{"wrong username", connect, map[string]string{"Proxy-Authorization": basic("admin", theProxyKey)}},
		{"no colon", connect, map[string]string{"Proxy-Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("stk"+theProxyKey))}},
		{"key in other header", connect, map[string]string{"X-Proxy-Key": theProxyKey, "Authorization": basic("stk", theProxyKey)}},
		{"key in url", "CONNECT stk:" + url.QueryEscape(theProxyKey) + "@api.github.com:443 HTTP/1.1", nil},
		{"key in query on plain request", "GET http://api.github.com/user?proxy_key=" + url.QueryEscape(theProxyKey) + " HTTP/1.1", nil},
		{"plain request no header", "GET /credentials HTTP/1.1", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixtureKey(t, githubOnly, theProxyKey)
			resp := rawProxy(t, f, tc.line, tc.headers)
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusProxyAuthRequired {
				t.Fatalf("status = %d, want 407", resp.StatusCode)
			}
			if got := resp.Header.Get("Proxy-Authenticate"); got != `Basic realm="stk"` {
				t.Errorf("Proxy-Authenticate = %q", got)
			}
			if !strings.Contains(string(body), "proxy authentication required") {
				t.Errorf("body = %q", body)
			}
			if strings.Contains(string(body), theProxyKey) || strings.Contains(string(body), theSecret) {
				t.Fatalf("refusal body leaked a credential: %q", body)
			}
			st := f.broker.Stats()
			if st.Refused != 1 {
				t.Errorf("Refused = %d, want 1", st.Refused)
			}
			if *f.tunnelHits != 0 || st.Tunnel != 0 || st.Intercept != 0 {
				t.Fatalf("dialled or tunnelled without authentication: tunnelHits=%d stats=%+v", *f.tunnelHits, st)
			}
			if f.secretCalls.Load() != 0 || f.providerHits.Load() != 0 {
				t.Fatal("a secret was fetched or the provider reached without authentication")
			}
			if strings.Contains(f.logs.String(), theProxyKey) {
				t.Fatal("the proxy key appeared in the broker's logs")
			}
		})
	}
}

func (f *fixture) keyedClient(key string) *http.Client {
	c := f.client(false)
	pu, _ := url.Parse(ProxyURL(f.proxyURL.Host, key))
	c.Transport.(*http.Transport).Proxy = http.ProxyURL(pu)
	return c
}

func TestProxyKeyAccepted(t *testing.T) {
	f := newFixtureKey(t, githubOnly, theProxyKey)
	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	req.Header.Set("Authorization", "Bearer "+Placeholder("github"))
	resp, err := f.keyedClient(theProxyKey).Do(req)
	if err != nil {
		t.Fatalf("authenticated request failed: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]string
	json.NewDecoder(resp.Body).Decode(&out)
	if out["authorization"] != "Bearer "+theSecret {
		t.Fatalf("provider saw %q, want the substituted credential", out["authorization"])
	}
	st := f.broker.Stats()
	if st.Intercept != 1 || st.Swap != 1 || st.Refused != 0 {
		t.Fatalf("Stats() = %+v", st)
	}
	// The scheme is case-insensitive.
	r2 := rawProxy(t, f, "CONNECT elsewhere.example:443 HTTP/1.1",
		map[string]string{"Proxy-Authorization": "bAsIc " + base64.StdEncoding.EncodeToString([]byte("stk:"+theProxyKey))})
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("lower-case scheme: status %d, want 200", r2.StatusCode)
	}
}

func TestNoProxyKeyKeepsOldBehaviour(t *testing.T) {
	f := newFixture(t, githubOnly)
	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	req.Header.Set("Authorization", "Bearer "+Placeholder("github"))
	resp, err := f.client(false).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if st := f.broker.Stats(); st.Swap != 1 || st.Refused != 0 {
		t.Fatalf("Stats() = %+v", st)
	}
	r := rawProxy(t, f, "GET /credentials HTTP/1.1", nil)
	if r.StatusCode != http.StatusBadRequest {
		t.Fatalf("plain GET = %d, want the old 400", r.StatusCode)
	}
}

func TestProxyKeyNeverInRecords(t *testing.T) {
	f := newFixtureKey(t, githubOnly, theProxyKey)
	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	req.Header.Set("Authorization", "Bearer "+Placeholder("github"))
	resp, err := f.keyedClient(theProxyKey).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	recs := f.broker.Audit()
	if len(recs) == 0 {
		t.Fatal("no records")
	}
	enc := base64.StdEncoding.EncodeToString([]byte("stk:" + theProxyKey))
	for _, r := range recs {
		blob, _ := json.Marshal(r)
		if strings.Contains(string(blob), theProxyKey) || strings.Contains(string(blob), enc) ||
			strings.Contains(string(blob), url.QueryEscape(theProxyKey)) {
			t.Fatalf("record carries the proxy key: %s", blob)
		}
	}
	if strings.Contains(f.logs.String(), theProxyKey) || strings.Contains(f.logs.String(), enc) {
		t.Fatal("the proxy key appeared in the broker's logs")
	}
}

func TestProxyURLEscapesKey(t *testing.T) {
	got := ProxyURL("127.0.0.1:8080", theProxyKey)
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("ProxyURL produced an unparseable URL %q: %v", got, err)
	}
	pw, _ := u.User.Password()
	if u.Scheme != "http" || u.Host != "127.0.0.1:8080" || u.User.Username() != "stk" || pw != theProxyKey {
		t.Fatalf("ProxyURL = %q parsed to %+v", got, u)
	}
	if strings.Contains(got, "@chars") {
		t.Fatalf("key not escaped: %q", got)
	}
}
