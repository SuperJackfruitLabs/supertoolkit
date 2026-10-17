// Package broker runs the egress proxy that owns credentials.
//
// Clients reach it with HTTPS_PROXY and a placeholder where their token would
// be. For hosts named in policy the broker terminates TLS, substitutes the real
// credential, and forwards upstream. Every other host is tunnelled with CONNECT
// and never opened.
package broker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/rules"
)

// SecretSource hands the broker a credential for one service. It is the only
// inbound path for a secret, and it is never exposed to a caller.
type SecretSource func(service string) (string, error)

// Stats are the broker's own counters. They are the authoritative record of what
// happened: a client's status code cannot distinguish a bypass from a bad
// credential, so assertions belong here.
type Stats struct {
	Intercept, Tunnel, Swap, H2, H1, Refused, Denied int64
}

// Record is one audited effect. It carries fingerprints, never a secret.
type Record struct {
	When     time.Time
	Service  string
	Host     string
	Method   string
	Path     string
	Proto    string
	Injected string
	AuthzFP  string
	Status   string
	// Rule names the rule that denied the request, if one did.
	Rule string
	// Labels are the service's operator-set audit labels, from the same
	// policy snapshot that decided the request.
	Labels map[string]string
}

// Broker is the egress proxy.
type Broker struct {
	// snap is the policy in force: the config and the host map built from it,
	// replaced whole by Reload and never mutated. See snapshot.
	snap atomic.Pointer[snapshot]
	// extra are Options.Intercept, re-applied on every Reload.
	extra []string
	ca    *CA
	src   SecretSource
	log   *slog.Logger

	// upstream talks to the real provider. Injectable so tests can point it at
	// a local server and trust a test CA.
	upstream *http.Transport
	// dial opens tunnels for hosts outside policy. Injectable for the same reason.
	dial func(ctx context.Context, network, addr string) (net.Conn, error)

	intercept, tunnel, swap, h2, h1, refused, denied atomic.Int64

	auditMu sync.Mutex
	audit   []Record

	observer Observer

	// proxyKey gates use of the broker. Never logged, recorded or returned.
	proxyKey string
}

// Options configure a broker. Only cfg, ca and src are required.
type Options struct {
	Config   *policy.Config
	CA       *CA
	Secrets  SecretSource
	Logger   *slog.Logger
	Upstream *http.Transport
	Dial     func(ctx context.Context, network, addr string) (net.Conn, error)
	// Intercept are extra hostnames to terminate TLS for, beyond the ones the
	// configured services declare. They are mapped to the first configured
	// service, so its placement and auth scheme apply.
	//
	// This exists for `stk doctor --probe`, which must drive a real request
	// through a real broker at a hostname that can never resolve — a .invalid
	// name, so that a client failing DNS proves it bypassed the proxy. Every
	// other caller leaves it empty, and the set of intercepted hosts stays
	// exactly what policy declares.
	Intercept []string
	// Observer receives every effect for durable recording. It is an interface
	// rather than a *ledger.Ledger so the broker owns no storage decision and
	// its tests need no filesystem: the mapping from a wire record to an audit
	// entry happens at the edge, where the catalogue is already in hand.
	Observer Observer
	// ProxyKey, when set, is required from every caller as
	// Proxy-Authorization: Basic base64("stk:"+key). It gates use of the
	// broker only: it is not a service credential, never unlocks a secret, and
	// is never logged or recorded. Empty means no authentication.
	ProxyKey string
}

// ProxyURL is the proxy address a caller uses when ProxyKey is set.
func ProxyURL(addr, key string) string {
	return (&url.URL{Scheme: "http", User: url.UserPassword("stk", key), Host: addr}).String()
}

// Observer is told about each effect as it completes.
//
// It is called on the request path, so an implementation that blocks delays a
// request. Writing one append-only line does not; anything slower should buffer.
type Observer interface {
	Observe(Record)
}

// New builds a broker.
func New(o Options) (*Broker, error) {
	if o.Config == nil || o.CA == nil || o.Secrets == nil {
		return nil, fmt.Errorf("broker: Config, CA and Secrets are all required")
	}
	b := &Broker{
		ca: o.CA, src: o.Secrets,
		log:      o.Logger,
		observer: o.Observer,
		proxyKey: o.ProxyKey,
		upstream: o.Upstream,
		dial:     o.Dial,
		extra:    append([]string(nil), o.Intercept...),
	}
	if b.log == nil {
		b.log = slog.New(slog.DiscardHandler)
	}
	if b.upstream == nil {
		b.upstream = &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
		}
	}
	if b.dial == nil {
		d := &net.Dialer{Timeout: 15 * time.Second}
		b.dial = d.DialContext
	}
	snap, err := b.build(o.Config)
	if err != nil {
		return nil, err
	}
	b.snap.Store(snap)
	return b, nil
}

// snapshot is one policy, immutable once stored. A request reads it once and
// decides everything — which service, its rules, its labels — from that one
// value, so a reload can never give a single request a mix of two policies.
type snapshot struct {
	cfg    *policy.Config
	byHost map[string]*policy.Service
}

// build makes a snapshot from cfg, including the extra intercepted hosts.
func (b *Broker) build(cfg *policy.Config) (*snapshot, error) {
	s := &snapshot{cfg: cfg, byHost: map[string]*policy.Service{}}
	for _, name := range cfg.Services() {
		svc, _ := cfg.Service(name)
		for _, h := range svc.Entry().Hosts() {
			s.byHost[h] = svc
		}
	}
	if len(b.extra) > 0 {
		names := cfg.Services()
		if len(names) == 0 {
			return nil, fmt.Errorf("broker: Intercept needs at least one configured service to borrow a scheme from")
		}
		svc, _ := cfg.Service(names[0])
		for _, h := range b.extra {
			s.byHost[h] = svc
		}
	}
	return s, nil
}

// Reload replaces the policy without a restart. cfg must already be fully
// validated (policy.Load); a nil cfg, or one the broker cannot build a host
// map from, is refused and nothing changes.
//
// Semantics, chosen so a reload reaches long-lived tunnels:
//   - Which hosts are intercepted is decided when a CONNECT arrives, from the
//     policy current then. A host whose service was removed is tunnelled blind
//     on its next CONNECT.
//   - Everything else is decided per request, from the policy current when the
//     request arrives: an HTTP/2 or keep-alive tunnel opened before a reload
//     enforces the new rules on its next request. A request already in flight
//     keeps the policy it started with.
//   - A request on a tunnel whose host no longer maps to the service it was
//     opened for is refused with 403; it is never forwarded under another
//     service's credential or without rules.
func (b *Broker) Reload(cfg *policy.Config) error {
	if cfg == nil {
		return fmt.Errorf("broker: Reload needs a config")
	}
	snap, err := b.build(cfg)
	if err != nil {
		return err
	}
	b.snap.Store(snap)
	return nil
}

// Placeholder is the worthless stand-in a client carries instead of a
// credential. It is safe for an agent to read: it means nothing off this host.
func Placeholder(service string) string { return "stk:ref:" + service + ":v1" }

// Stats snapshots the counters.
func (b *Broker) Stats() Stats {
	return Stats{
		Intercept: b.intercept.Load(), Tunnel: b.tunnel.Load(), Swap: b.swap.Load(),
		H2: b.h2.Load(), H1: b.h1.Load(), Refused: b.refused.Load(),
		Denied: b.denied.Load(),
	}
}

// Audit returns the audited effects, oldest first.
func (b *Broker) Audit() []Record {
	b.auditMu.Lock()
	defer b.auditMu.Unlock()
	return append([]Record(nil), b.audit...)
}

func (b *Broker) record(r Record) {
	b.auditMu.Lock()
	b.audit = append(b.audit, r)
	b.auditMu.Unlock()
	if b.observer != nil {
		b.observer.Observe(r)
	}
}

// isUpgrade reports whether this request asks to leave HTTP behind.
//
// Both headers are checked because either alone is meaningless: RFC 9110
// requires Connection to list Upgrade, and a request naming a protocol without
// it is not an upgrade request.
func isUpgrade(r *http.Request) bool {
	if r.Header.Get("Upgrade") == "" {
		return false
	}
	for _, v := range r.Header.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
				return true
			}
		}
	}
	return false
}

func fingerprint(s string) string {
	if s == "" {
		return "(absent)"
	}
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])[:12]
}

// Serve accepts proxy connections until the listener closes.
func (b *Broker) Serve(ln net.Listener) error {
	srv := &http.Server{Handler: http.HandlerFunc(b.handle)}
	return srv.Serve(ln)
}

// authorized reports whether r carries the proxy key. Only the
// Proxy-Authorization header is consulted; a key anywhere else does not count.
func (b *Broker) authorized(r *http.Request) bool {
	if b.proxyKey == "" {
		return true
	}
	scheme, enc, ok := strings.Cut(r.Header.Get("Proxy-Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(enc))
	if err != nil {
		return false
	}
	user, key, ok := strings.Cut(string(raw), ":")
	if !ok || user != "stk" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(key), []byte(b.proxyKey)) == 1
}

func (b *Broker) handle(w http.ResponseWriter, r *http.Request) {
	// Judged before anything else: an unauthenticated caller is never hijacked,
	// dialled, tunnelled or intercepted, whatever its method.
	if !b.authorized(r) {
		b.refused.Add(1)
		w.Header().Set("Proxy-Authenticate", `Basic realm="stk"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	if r.Method != http.MethodConnect {
		// The broker is a proxy, not an API. There is deliberately no endpoint
		// here that could return a credential.
		b.refused.Add(1)
		http.Error(w, "supertoolkit broker speaks CONNECT only", http.StatusBadRequest)
		return
	}
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "proxy requires a hijackable connection", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	// Read once: the interception decision for this tunnel is made here.
	svc, inPolicy := b.snap.Load().byHost[host]
	if !inPolicy {
		b.tunnel.Add(1)
		b.log.Debug("tunnelling a host outside policy", "host", host)
		b.blindTunnel(r.Context(), client, r.Host)
		return
	}
	b.intercept.Add(1)
	b.interceptTLS(client, host, svc.Name)
}

// blindTunnel copies bytes without looking at them. A host outside policy is
// never decrypted, which keeps interception's blast radius equal to the
// configured service list.
func (b *Broker) blindTunnel(ctx context.Context, client net.Conn, hostport string) {
	up, err := b.dial(ctx, "tcp", hostport)
	if err != nil {
		b.log.Debug("tunnel dial failed", "target", hostport, "error", err)
		return
	}
	defer up.Close()
	done := make(chan struct{})
	go func() { io.Copy(up, client); close(done) }()
	io.Copy(client, up)
	<-done
}

// interceptTLS serves the requests of one intercepted tunnel. It holds the
// service's name, not its policy: each request looks its policy up afresh.
func (b *Broker) interceptTLS(client net.Conn, host, svcName string) {
	leaf, err := b.ca.leafFor(host)
	if err != nil {
		b.log.Error("could not mint a leaf", "host", host, "error", err)
		return
	}
	tc := tls.Server(client, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err := tc.Handshake(); err != nil {
		// The client refused our CA. This is the loud failure mode, and it is
		// the safe one: nothing proceeded.
		b.log.Warn("client refused the broker certificate", "host", host, "error", err)
		return
	}
	defer tc.Close()

	proto := tc.ConnectionState().NegotiatedProtocol
	if proto == "" {
		proto = "http/1.1"
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.forward(w, r, host, proto, svcName)
	})
	if proto == "h2" {
		b.h2.Add(1)
		(&http2.Server{}).ServeConn(tc, &http2.ServeConnOpts{Handler: h})
		return
	}
	b.h1.Add(1)
	(&http.Server{Handler: h}).Serve(newSingleConnListener(tc))
}

func (b *Broker) forward(w http.ResponseWriter, r *http.Request, host, proto, svcName string) {
	// The one read of the policy for this request. Everything below — the
	// service, its rules, its labels — comes from this snapshot.
	svc, ok := b.snap.Load().byHost[host]
	if !ok || svc.Name != svcName {
		// The tunnel was opened for a service a reload has since removed or
		// moved. Its credential and rules no longer apply here, so nothing is
		// sent; a fresh CONNECT gets whatever the current policy says.
		b.refused.Add(1)
		b.record(Record{When: time.Now(), Service: svcName, Host: host, Method: r.Method, Path: r.URL.Path, Proto: proto,
			Status: "403 service no longer brokered"})
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if r.ProtoMajor == 1 {
			w.Header().Set("Connection", "close")
		}
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "supertoolkit: %s is no longer brokered for this host after a policy reload. Nothing was sent; reconnect.\n", svcName)
		return
	}
	rec := Record{When: time.Now(), Service: svc.Name, Host: host, Method: r.Method, Path: r.URL.Path, Proto: proto,
		Labels: svc.Labels()}

	// A protocol upgrade cannot survive this path. Forwarding through a
	// round-trip into a ResponseWriter gives no way to hand the raw connection
	// to the client, so a WebSocket handshake would appear to succeed and then
	// hang — which reads as the provider's fault and is the most expensive kind
	// of wrong answer. Saying so is cheap and the alternative is a day of
	// someone else's debugging.
	if isUpgrade(r) {
		rec.Status = "501 upgrade not brokered"
		b.record(rec)
		b.log.Warn("refusing a protocol upgrade on an intercepted host", "host", host, "upgrade", r.Header.Get("Upgrade"))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusNotImplemented)
		fmt.Fprintf(w, `supertoolkit cannot broker a %s upgrade to %s.

The credential is substituted on an HTTP request, and an upgraded connection
carries no further HTTP requests to substitute into. Nothing was sent.

Tunnel the host instead of brokering it: remove %s from the services in
your supertoolkit.yaml, and the broker will pass its traffic through
unopened. The connection will work and will carry whatever credential the
client itself holds — which is the trade this product otherwise avoids.

See docs/limitations.md.
`, r.Header.Get("Upgrade"), host, svc.Name)
		return
	}

	// Rules are decided before the secret is fetched: a request the rules do
	// not allow never causes the credential to be read, let alone sent.
	if set := svc.Rules(); set != nil {
		if id, reason, ok := b.decide(r, set, svc); !ok {
			b.denied.Add(1)
			rec.Rule = id
			rec.Status = "403 denied: " + id
			b.record(rec)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, "supertoolkit denied this request: rule %s (%s). Nothing was sent.\n", id, reason)
			return
		}
	}

	secret, err := b.src(svc.Name)
	if err != nil {
		rec.Status = "no credential: " + err.Error()
		b.record(rec)
		http.Error(w, "supertoolkit: no credential for "+svc.Name, http.StatusBadGateway)
		return
	}
	entry := svc.Entry()
	if where, ok := credential.Inject(r, Placeholder(svc.Name), secret, entry.Placement, entry.Field); ok {
		b.swap.Add(1)
		rec.Injected = where
	}
	rec.AuthzFP = fingerprint(r.Header.Get("Authorization"))

	out := r.Clone(r.Context())
	out.URL.Scheme = "https"
	out.URL.Host = host
	out.Host = host
	out.RequestURI = ""
	// Let the upstream negotiate its own encoding; we re-stream the body.
	out.Header.Del("Accept-Encoding")

	resp, err := b.upstream.RoundTrip(out)
	if err != nil {
		rec.Status = "upstream error"
		b.record(rec)
		b.log.Warn("upstream failed", "host", host, "error", err)
		http.Error(w, "supertoolkit: upstream unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	rec.Status = resp.Status
	b.record(rec)

	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	// Trailers must be announced before WriteHeader. Go's client moves the
	// announced names into resp.Trailer and does not leave them in resp.Header,
	// so the announce list is rebuilt from there. gRPC carries its status in a
	// trailer, so dropping these breaks gRPC silently.
	if names := trailerNames(resp.Trailer); len(names) > 0 {
		w.Header().Set("Trailer", strings.Join(names, ", "))
	}
	w.WriteHeader(resp.StatusCode)

	// Stream rather than buffer, so server-sent events and chunked responses
	// reach the client as they arrive.
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if rerr != nil {
			break
		}
	}
	for k, vs := range resp.Trailer {
		for _, v := range vs {
			w.Header().Set(k, v)
		}
	}
}

// GraphQLRuleID names the built-in deny on a forge's GraphQL endpoint.
const GraphQLRuleID = "builtin:graphql"

// decide evaluates r against set. Any failure is a deny. When the body is read
// for evaluation, r.Body is replaced so that forwarding sends the same bytes.
func (b *Broker) decide(r *http.Request, set *rules.Set, svc *policy.Service) (id, reason string, ok bool) {
	escaped := r.URL.EscapedPath()
	full, err := rules.NormalizePath(escaped)
	if err != nil {
		return rules.IDBadPath, rules.ReasonBadPath, false
	}
	// GraphQL is one endpoint carrying every operation, so path rules cannot
	// govern it. No allow rule reopens it; only allow_graphql does.
	if !svc.AllowGraphQL() {
		if p, in := rules.StripPrefix(svc.APIPrefix(), full); in {
			lp := strings.ToLower(p)
			if lp == "/graphql" || strings.HasPrefix(lp, "/graphql/") {
				return GraphQLRuleID, "graphql", false
			}
		}
	}
	req := rules.Request{
		Method: r.Method, EscapedPath: escaped, Header: r.Header,
		ContentType: r.Header.Get("Content-Type"),
	}
	if carriesBody(r.Method) && r.Body != nil && r.Body != http.NoBody {
		buf, err := io.ReadAll(io.LimitReader(r.Body, rules.MaxBody+1))
		// Restore the body exactly: the bytes read, then the rest unread.
		r.Body = readCloser{io.MultiReader(bytes.NewReader(buf), r.Body), r.Body}
		if err != nil {
			return rules.IDDefaultDeny, "body unreadable", false
		}
		if len(buf) > rules.MaxBody {
			buf, req.BodyTruncated = buf[:rules.MaxBody], true
		}
		req.Body = buf
	}
	d := set.Evaluate(svc.APIPrefix(), req)
	if !d.Allowed {
		return d.RuleID, d.Reason, false
	}
	return d.RuleID, d.Reason, true
}

func carriesBody(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// readCloser reads from a restored stream and closes the original body.
type readCloser struct {
	io.Reader
	io.Closer
}

func trailerNames(t http.Header) []string {
	if len(t) == 0 {
		return nil
	}
	out := make([]string, 0, len(t))
	for k := range t {
		out = append(out, k)
	}
	return out
}

// Config is the policy currently in force.
func (b *Broker) Config() *policy.Config { return b.snap.Load().cfg }
