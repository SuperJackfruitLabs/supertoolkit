// Package broker runs the egress proxy that owns credentials.
//
// Clients reach it with HTTPS_PROXY and a placeholder where their token would
// be. For hosts named in policy the broker terminates TLS, substitutes the real
// credential, and forwards upstream. Every other host is tunnelled with CONNECT
// and never opened.
package broker

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

// SecretSource hands the broker a credential for one service. It is the only
// inbound path for a secret, and it is never exposed to a caller.
type SecretSource func(service string) (string, error)

// Stats are the broker's own counters. They are the authoritative record of what
// happened: a client's status code cannot distinguish a bypass from a bad
// credential, so assertions belong here.
type Stats struct {
	Intercept, Tunnel, Swap, H2, H1, Refused int64
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
}

// Broker is the egress proxy.
type Broker struct {
	cfg *policy.Config
	ca  *CA
	src SecretSource
	log *slog.Logger

	// upstream talks to the real provider. Injectable so tests can point it at
	// a local server and trust a test CA.
	upstream *http.Transport
	// dial opens tunnels for hosts outside policy. Injectable for the same reason.
	dial func(ctx context.Context, network, addr string) (net.Conn, error)

	byHost map[string]*policy.Service

	intercept, tunnel, swap, h2, h1, refused atomic.Int64

	auditMu sync.Mutex
	audit   []Record

	observer Observer
}

// Options configure a broker. Only cfg, ca and src are required.
type Options struct {
	Config   *policy.Config
	CA       *CA
	Secrets  SecretSource
	Logger   *slog.Logger
	Upstream *http.Transport
	Dial     func(ctx context.Context, network, addr string) (net.Conn, error)
	// Observer receives every effect for durable recording. It is an interface
	// rather than a *ledger.Ledger so the broker owns no storage decision and
	// its tests need no filesystem: the mapping from a wire record to an audit
	// entry happens at the edge, where the catalogue is already in hand.
	Observer Observer
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
		cfg: o.Config, ca: o.CA, src: o.Secrets,
		log:      o.Logger,
		observer: o.Observer,
		upstream: o.Upstream,
		dial:     o.Dial,
		byHost:   map[string]*policy.Service{},
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
	for _, name := range o.Config.Services() {
		s, _ := o.Config.Service(name)
		for _, h := range s.Entry().Hosts() {
			b.byHost[h] = s
		}
	}
	return b, nil
}

// Placeholder is the worthless stand-in a client carries instead of a
// credential. It is safe for an agent to read: it means nothing off this host.
func Placeholder(service string) string { return "stk:ref:" + service + ":v1" }

// Stats snapshots the counters.
func (b *Broker) Stats() Stats {
	return Stats{
		Intercept: b.intercept.Load(), Tunnel: b.tunnel.Load(), Swap: b.swap.Load(),
		H2: b.h2.Load(), H1: b.h1.Load(), Refused: b.refused.Load(),
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

func (b *Broker) handle(w http.ResponseWriter, r *http.Request) {
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

	svc, inPolicy := b.byHost[host]
	if !inPolicy {
		b.tunnel.Add(1)
		b.log.Debug("tunnelling a host outside policy", "host", host)
		b.blindTunnel(r.Context(), client, r.Host)
		return
	}
	b.intercept.Add(1)
	b.interceptTLS(client, host, svc)
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

func (b *Broker) interceptTLS(client net.Conn, host string, svc *policy.Service) {
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
		b.forward(w, r, host, proto, svc)
	})
	if proto == "h2" {
		b.h2.Add(1)
		(&http2.Server{}).ServeConn(tc, &http2.ServeConnOpts{Handler: h})
		return
	}
	b.h1.Add(1)
	(&http.Server{Handler: h}).Serve(newSingleConnListener(tc))
}

func (b *Broker) forward(w http.ResponseWriter, r *http.Request, host, proto string, svc *policy.Service) {
	rec := Record{When: time.Now(), Service: svc.Name, Host: host, Method: r.Method, Path: r.URL.Path, Proto: proto}

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
