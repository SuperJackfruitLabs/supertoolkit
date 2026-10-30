package broker

import (
	"net"
	"net/http"
	"strings"
	"time"
)

// LocalCommandsIdentity is the one identity a local-commands listener serves.
const LocalCommandsIdentity = "local-commands"

// ServeAs accepts proxy connections pinned to one identity until the listener closes.
//
// It is for local commands (operator ruling 2026-10-30). A command can read its own HTTP_PROXY,
// so on the shared proxy it could rename itself (stk+fetch) and take another identity's egress.
// Here the identity is the listener's, whatever the client sends; the listener is a unix socket
// whose file mode is the only gate, so no proxy key is asked for (a key handed to a command is a
// key the command can read). Only that identity's own egress decides, never the workspace's, and
// no brokered service is reachable: a command gets tunnels to listed hosts and nothing else.
func (b *Broker) ServeAs(ln net.Listener, ident string) error {
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.handleAs(w, r, ident)
	})}
	return srv.Serve(ln)
}

func (b *Broker) handleAs(w http.ResponseWriter, r *http.Request, ident string) {
	snap := b.snap.Load()
	host := r.URL.Hostname()
	if r.Method == http.MethodConnect {
		if h, _, err := net.SplitHostPort(r.Host); err == nil {
			host = h
		} else {
			host = r.Host
		}
	}
	rec := Record{When: time.Now(), Service: ident, Host: host, Method: r.Method, Kind: KindEgress}
	if user, _, ok := proxyCreds(r); ok {
		if claimed, found := strings.CutPrefix(user, IdentityUser+"+"); found && claimed != ident {
			over := rec
			over.Rule = "local-commands:identity-forced"
			over.Status = "client claimed " + user + "; decided as " + IdentityUser + "+" + ident
			b.record(over)
		}
	}
	pol := snap.cfg.ServerEgress(ident)
	if pol == nil {
		b.refuseEgress(w, rec, "local-commands:no-policy",
			"this host's stk policy has no egress for "+ident+"; the host operator adds servers."+ident+".egress.hosts")
		return
	}
	if _, brokered := snap.byHost[host]; brokered {
		b.refuseEgress(w, rec, "local-commands:brokered-service",
			host+" is a brokered service; local commands reach only the hosts in "+ident+"'s egress, never a brokered service")
		return
	}
	switch {
	case r.Method == http.MethodConnect:
		b.egressConnect(w, r, pol, ident)
	case r.URL.IsAbs() && strings.EqualFold(r.URL.Scheme, "http"):
		if !pol.AllowsScheme("http") {
			b.refuseEgress(w, rec, "egress:scheme", "plain http is not allowed for this egress")
			return
		}
		b.egressPlain(w, r, pol, ident)
	default:
		b.refused.Add(1)
		http.Error(w, "supertoolkit broker speaks CONNECT only", http.StatusBadRequest)
	}
}
