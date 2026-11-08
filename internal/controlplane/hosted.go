package controlplane

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/approval"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/mcp"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/native"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

// superPipelineBaseURL is where hosted approvals go: the host the catalogue's
// superpipeline-approvals-* entries inject their credentials for.
const superPipelineBaseURL = "https://app.superpipeline.dev"

// Hosted approvals are read back every hostedInterval while they wait; an
// effect whose create or read fails backs off up to hostedMaxBackoff.
const (
	hostedInterval   = 3 * time.Second
	hostedMaxBackoff = time.Minute
)

// Hosting is the host for the policy in force, or nil when the policy names no
// approvals board and approvals stay local.
func (s *Service) Hosting() *approval.Host {
	board := s.config().ApprovalsBoard()
	if board == "" {
		return nil
	}
	station, _ := os.Hostname()
	return &approval.Host{Queue: s.Queue, Board: board, Station: station, Client: s.superPipelineClient()}
}

// superPipelineClient reaches SuperPipeline on stk's own service credentials.
// They are native-only: no agent can name them, and the token is applied in
// the broker's transport, never returned here.
func (s *Service) superPipelineClient() *approval.SuperPipelineHTTPClient {
	return &approval.SuperPipelineHTTPClient{
		BaseURL:    superPipelineBaseURL,
		DeliveryDo: nativeService{s, policy.ApprovalsWriteService}.Do,
		ApprovalDo: nativeService{s, policy.ApprovalsReadService}.Do,
	}
}

// nativeService sends one request on a native-only service credential. The
// caller owns the response and closes its body.
type nativeService struct {
	s    *Service
	name string
}

func (n nativeService) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	return n.s.Perform(native.PublisherContext(ctx), n.name, req)
}

// WatchHosted resolves hosted approvals until ctx ends: it reads each decision
// back from SuperPipeline and performs an approved effect once its subject,
// digest and expiry check out. Failures go to report (nil drops them).
func (s *Service) WatchHosted(ctx context.Context, report func(string)) {
	perform := func(e *approval.Effect) (string, error) {
		pctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		return s.performApproved(pctx, e)
	}
	approval.Watch(ctx, s.Hosting, hostedInterval, hostedMaxBackoff, perform, func(id string, err error) {
		if report != nil {
			report(fmt.Sprintf("hosted approval %s: %v", id, err))
		}
	})
}

// performHostedTool carries out a fronted MCP server's tool call that
// SuperPipeline approved. There is no agent session waiting on a hosted
// approval, so this process runs the tool on the server it fronts (started on
// first use, like any fronted server), after checking the call is the one
// approved.
func (s *Service) performHostedTool(ctx context.Context, e *approval.Effect) (string, error) {
	bound := approval.ToolCapabilityRequest(e.Service, e.Capability, e.Profile, e.Args)
	if err := approval.VerifyDigest(e, bound); err != nil {
		return "refused", err
	}
	srv, err := s.frontedServer(e.Service)
	if err != nil {
		return "", err
	}
	text, isErr, err := srv.CallTool(ctx, e.Capability, e.Args)
	if err != nil {
		return "", err
	}
	if isErr {
		return "tool_error", fmt.Errorf("%s/%s: %s", e.Service, e.Capability, text)
	}
	return "done", nil
}

// frontedServer resolves a fronted server for a hosted tool call; tests set
// s.fronted to stand in for the child.
func (s *Service) frontedServer(name string) (mcp.FrontedServer, error) {
	if s.fronted != nil {
		return s.fronted(name)
	}
	return s.FrontedServer(name)
}
