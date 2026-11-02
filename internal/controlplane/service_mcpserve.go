package controlplane

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/daemon"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/ledger"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/mcpserve"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

// ServeSpec is what the daemon tells `stk mcp serve` about one server: how to
// start it and how its child reaches the broker. No credential is in it — the
// proxy key gates use of the proxy only, and the CA is public.
type ServeSpec struct {
	Command   string            `json:"command"`
	Args      []string          `json:"args"`
	Env       map[string]string `json:"env,omitempty"`
	EnvVar    string            `json:"env_var,omitempty"`
	Network   string            `json:"network"`
	ProxyAddr string            `json:"proxy_addr"`
	ProxyKey  string            `json:"proxy_key,omitempty"`
	CAPEM     string            `json:"ca_pem"`
}

type MCPServeParams struct {
	Server  string          `json:"server"`
	Tool    string          `json:"tool,omitempty"`
	Hint    policy.ToolHint `json:"hint,omitempty"`
	Rule    string          `json:"rule,omitempty"`
	Outcome string          `json:"outcome,omitempty"`
	Remote  string          `json:"remote,omitempty"`
}

// handleMCPServe answers the daemon side of `stk mcp serve`. Decisions are made
// here, from the policy this daemon holds, and recorded in its ledger: the
// caller only learns the answer.
func (s *Service) handleMCPServe(uid int, cfg *policy.Config, prof *policy.Profile, r daemon.Request) (json.RawMessage, error) {
	var p MCPServeParams
	if err := json.Unmarshal(r.Params, &p); err != nil || p.Server == "" {
		return nil, fmt.Errorf("%s needs a server", r.Method)
	}
	srv, ok := cfg.Server(p.Server)
	if !ok {
		return nil, fmt.Errorf("unknown server %q; declared: %s", p.Server, strings.Join(cfg.Servers(), ", "))
	}
	caller := fmt.Sprintf("uid:%d mcp serve", uid)
	switch r.Method {
	case "mcp.spec":
		if s.ProxyAddr == "" || s.CAPath == "" {
			return nil, fmt.Errorf("this broker has no proxy for a fronted server to use")
		}
		ca, err := os.ReadFile(s.CAPath)
		if err != nil {
			return nil, err
		}
		return json.Marshal(ServeSpec{
			Command: srv.Command, Args: srv.Args, Env: srv.Env, EnvVar: srv.EnvVar, Network: srv.Network,
			ProxyAddr: s.ProxyAddr, ProxyKey: s.ProxyKey, CAPEM: string(ca),
		})
	case "mcp.decide":
		d := mcpserve.Decide(cfg, prof, p.Server, p.Tool, p.Hint)
		if err := s.obs.Led.Append(mcpserve.DecisionEntry(p.Server, p.Tool, caller, d)); err != nil {
			// Not recorded, so not allowed.
			d = mcpserve.Decision{Policy: "deny", Rule: "audit:unwritable", Reason: err.Error()}
		}
		return json.Marshal(d)
	case "mcp.visible":
		return json.Marshal(mcpserve.Decide(cfg, prof, p.Server, p.Tool, p.Hint))
	case "mcp.done":
		return nil, s.obs.Led.Append(mcpserve.DoneEntry(p.Server, p.Tool, caller, p.Rule, p.Outcome))
	case "mcp.violation":
		return nil, s.obs.Led.Append(ViolationEntry(p.Server, caller, p.Remote))
	}
	return nil, fmt.Errorf("unknown method %s", r.Method)
}

func ViolationEntry(server, caller, remote string) ledger.Entry {
	return ledger.Entry{
		When: time.Now().UTC(), Service: server, Capability: "(egress)", Method: "CONNECT", Host: remote, Addr: remote,
		Policy: "deny", Caller: caller, Credential: "none", Rule: "netwatch:direct",
		Outcome: "bypass detected: the child connected around the broker and was stopped",
	}
}
