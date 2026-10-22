package broker

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/http2"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/egress"
)

// egressService is the audit name of a request decided by egress: the server
// it was made for, or "egress" for the workspace default.
func egressService(ident string) string {
	if ident == "" {
		return "egress"
	}
	return ident
}

// refuseEgress answers a refused egress request and records it. Nothing has
// been dialled when this runs.
func (b *Broker) refuseEgress(w http.ResponseWriter, rec Record, rule, why string) {
	b.denied.Add(1)
	rec.Rule = rule
	rec.Status = "403 denied: " + rule
	b.record(rec)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, "supertoolkit denied this request: rule %s (%s). Nothing was sent.\n", rule, why)
}

func withPort(hostport, port string) string {
	if _, _, err := net.SplitHostPort(hostport); err == nil {
		return hostport
	}
	return net.JoinHostPort(strings.Trim(hostport, "[]"), port)
}

// pinnedTransport talks to one decided address only. Whatever host the request
// names, the connection goes to addr: that is the DNS-rebinding guard, because
// no second lookup ever happens.
func (b *Broker) pinnedTransport(addr, serverName string) *http.Transport {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if b.upstream != nil && b.upstream.TLSClientConfig != nil {
		tc = b.upstream.TLSClientConfig.Clone()
	}
	tc.ServerName = serverName
	return &http.Transport{
		Proxy: nil, // never chain to another proxy from the environment
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return b.dial(ctx, network, addr)
		},
		TLSClientConfig:       tc,
		ForceAttemptHTTP2:     true,
		ResponseHeaderTimeout: 60 * time.Second,
	}
}

// egressConnect decides a CONNECT to a host outside policy.
func (b *Broker) egressConnect(w http.ResponseWriter, r *http.Request, pol *egress.Policy, ident string) {
	hostport := withPort(r.Host, "443")
	host, _, _ := net.SplitHostPort(hostport)
	rec := Record{When: time.Now(), Service: egressService(ident), Host: host, Method: http.MethodConnect, Kind: KindEgress}
	if !pol.AllowsScheme("https") {
		b.refuseEgress(w, rec, "egress:scheme", "https is not allowed for this egress")
		return
	}
	d, addr, err := pol.Resolve(r.Context(), b.resolve, hostport)
	if d.Addr.IsValid() {
		rec.Addr = d.Addr.String()
	}
	if err != nil {
		b.refuseEgress(w, rec, d.Rule, err.Error())
		return
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
	rec.Addr = addr
	if !pol.Inspects() {
		// Decided by address and passed through unopened, to the address that
		// was decided.
		b.tunnel.Add(1)
		rec.Rule, rec.Status = d.Rule, "tunnelled to "+addr
		b.record(rec)
		b.blindTunnel(r.Context(), client, addr)
		return
	}
	b.intercept.Add(1)
	b.egressIntercept(client, host, addr, d.Rule, pol, ident)
}

// egressIntercept opens an allowed tunnel so each request's method can be
// checked and its path recorded. This is opt-in per egress (`methods:`): a
// host outside policy is otherwise never opened.
func (b *Broker) egressIntercept(client net.Conn, host, addr, rule string, pol *egress.Policy, ident string) {
	leaf, err := b.ca.leafFor(host)
	if err != nil {
		b.log.Error("could not mint a leaf", "host", host, "error", err)
		return
	}
	tc := tls.Server(client, &tls.Config{
		Certificates: []tls.Certificate{*leaf}, MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	})
	if err := tc.Handshake(); err != nil {
		b.log.Warn("client refused the broker certificate", "host", host, "error", err)
		return
	}
	defer tc.Close()
	tr := b.pinnedTransport(addr, host)
	defer tr.CloseIdleConnections()
	proto := tc.ConnectionState().NegotiatedProtocol
	if proto == "" {
		proto = "http/1.1"
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := Record{When: time.Now(), Service: egressService(ident), Host: host, Method: r.Method,
			Path: r.URL.Path, Proto: proto, Kind: KindEgress, Addr: addr}
		if !pol.AllowsMethod(r.Method) {
			b.refuseEgress(w, rec, "egress:method", r.Method+" is not allowed for this egress")
			return
		}
		out := r.Clone(r.Context())
		out.URL.Scheme, out.URL.Host, out.Host, out.RequestURI = "https", host, host, ""
		b.relay(w, out, tr, rec, rule)
	})
	if proto == "h2" {
		b.h2.Add(1)
		(&http2.Server{}).ServeConn(tc, &http2.ServeConnOpts{Handler: h})
		return
	}
	b.h1.Add(1)
	(&http.Server{Handler: h}).Serve(newSingleConnListener(tc))
}

// egressPlain decides and forwards one absolute-form http:// request.
func (b *Broker) egressPlain(w http.ResponseWriter, r *http.Request, pol *egress.Policy, ident string) {
	hostport := withPort(r.URL.Host, "80")
	host, _, _ := net.SplitHostPort(hostport)
	rec := Record{When: time.Now(), Service: egressService(ident), Host: host, Method: r.Method,
		Path: r.URL.Path, Proto: "http/1.1", Kind: KindEgress}
	if !pol.AllowsMethod(r.Method) {
		b.refuseEgress(w, rec, "egress:method", r.Method+" is not allowed for this egress")
		return
	}
	if isUpgrade(r) {
		b.refuseEgress(w, rec, "egress:upgrade", "a protocol upgrade is not brokered")
		return
	}
	d, addr, err := pol.Resolve(r.Context(), b.resolve, hostport)
	if d.Addr.IsValid() {
		rec.Addr = d.Addr.String()
	}
	if err != nil {
		b.refuseEgress(w, rec, d.Rule, err.Error())
		return
	}
	rec.Addr = addr
	out := r.Clone(r.Context())
	out.RequestURI = ""
	// The proxy key is for this hop only; it must never reach the destination.
	out.Header.Del("Proxy-Authorization")
	out.Header.Del("Proxy-Connection")
	tr := b.pinnedTransport(addr, host)
	defer tr.CloseIdleConnections()
	b.relay(w, out, tr, rec, d.Rule)
}

// relay sends an allowed egress request and streams the answer back. A
// redirect is returned to the client, never followed here, so its next hop is
// a new request that is decided afresh.
func (b *Broker) relay(w http.ResponseWriter, out *http.Request, tr http.RoundTripper, rec Record, rule string) {
	rec.Rule = rule
	resp, err := tr.RoundTrip(out)
	if err != nil {
		rec.Status = "upstream error"
		b.record(rec)
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
	w.WriteHeader(resp.StatusCode)
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
			if rerr != io.EOF {
				b.log.Debug("egress body ended early", "error", rerr)
			}
			return
		}
	}
}
