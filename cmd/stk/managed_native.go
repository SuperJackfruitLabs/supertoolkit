package main

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/catalog"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/managedmcp"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

func managedUnavailable() error { return errors.New("managed Toolkit invocation is unavailable") }

type managedNative struct {
	admission *managedmcp.Admission
	cfg       *policy.Config
	profile   *policy.Profile
	ledger    *managedmcp.Ledger
	live      *liveConfig
	store     *credential.Store
	observer  observer
	client    *http.Client
}

func newManagedNative(admission *managedmcp.Admission) (*managedNative, error) {
	if admission.Check() != nil {
		return nil, managedUnavailable()
	}
	cfg, err := policy.Parse("managed policy", admission.Policy)
	if err != nil || len(cfg.Servers()) != 0 {
		return nil, managedUnavailable()
	}
	// Fronted executables and dynamic forge request rules need their own
	// admission proof. They are not enabled by this initial native profile.
	for _, name := range cfg.Services() {
		svc, _ := cfg.Service(name)
		if svc.Entry().Forge != nil || (svc.Entry().Auth == catalog.AuthToken && svc.Entry().Placement != catalog.BearerHeader) {
			return nil, managedUnavailable()
		}
	}
	profile, ok := cfg.Profile(admission.Manifest.Profile)
	if !ok {
		return nil, managedUnavailable()
	}
	pass, err := admission.Passphrase()
	if err != nil {
		return nil, managedUnavailable()
	}
	store, err := credential.OpenStore(admission.Manifest.StoreDir, pass)
	if err != nil {
		return nil, managedUnavailable()
	}
	ledger, err := managedmcp.Open(admission.Manifest.StateDir)
	if err != nil {
		return nil, managedUnavailable()
	}
	client := managedNativeClient()
	live := newLive(cfg, store, client)
	obs, err := newObserverLive(live, admission.Manifest.StateDir, "managed-mcp-v1")
	if err != nil {
		return nil, managedUnavailable()
	}
	return &managedNative{admission, cfg, profile, ledger, live, store, obs, client}, nil
}

// request is constructed from the actual admitted native policy. The model can
// supply action arguments; it cannot supply root, profile or approval policy.
func (s *managedNative) request(invocation, service, action string, args map[string]string, deadline int64) (managedmcp.Request, error) {
	if !s.profile.Visible(service, action) {
		return managedmcp.Request{}, managedUnavailable()
	}
	svc, _ := s.cfg.Service(service)
	capability, ok := svc.Entry().Capability(action)
	if !ok {
		return managedmcp.Request{}, managedUnavailable()
	}
	params := map[string]bool{}
	for _, p := range capability.Params {
		params[p.Name] = true
	}
	for key := range args {
		if !params[key] {
			return managedmcp.Request{}, managedUnavailable()
		}
	}
	if _, err := svc.Entry().Request(action, args); err != nil {
		return managedmcp.Request{}, managedUnavailable()
	}
	m := s.admission.Manifest
	r := managedmcp.Request{Version: 1, RootDigest: m.RootDigest, InvocationID: invocation, ProfileDigest: m.ProfileDigest, Service: service, Action: action, Args: maps.Clone(args), Approval: s.profile.Resolve(service, action) == policy.ActionApproval, ExpiresAtMS: deadline}
	body, err := json.Marshal(r)
	if err != nil {
		return managedmcp.Request{}, managedUnavailable()
	}
	out, err := managedmcp.DecodeRequest(body)
	if err != nil {
		return out, managedUnavailable()
	}
	return out, nil
}

func (s *managedNative) invoke(ctx context.Context, r managedmcp.Request) (managedmcp.Receipt, error) {
	bound, err := s.request(r.InvocationID, r.Service, r.Action, r.Args, r.ExpiresAtMS)
	if err != nil || managedmcp.RequestFingerprint(bound) != managedmcp.RequestFingerprint(r) {
		return managedmcp.Receipt{}, managedUnavailable()
	}
	// Saved receipts are consulted before new leases, decisions or credentials.
	v, err := s.ledger.Prepare(bound)
	if err != nil {
		return v, managedUnavailable()
	}
	if v.State == managedmcp.AwaitingDecision {
		answer, err := s.admission.Verify(ctx, "review", r)
		if err != nil {
			if saved, readErr := s.ledger.Prepare(r); readErr == nil {
				v = saved
			}
			return v, managedUnavailable()
		}
		if answer.Decision == "pending" {
			return v, nil
		}
		v, err = s.ledger.Decide(v.ID, answer.DecisionID, answer.Decision == "allowed")
		if err != nil {
			if saved, readErr := s.ledger.Prepare(r); readErr == nil {
				v = saved
			}
			return v, managedUnavailable()
		}
	}
	var prepared *preparedNative
	return s.ledger.Execute(ctx, v.ID, v.RequestDigest, func(ctx context.Context, exact managedmcp.Request) error {
		// Credential acquisition may perform an exchange. It needs a fresh
		// non-consuming admission check, then the one final dispatch grant.
		answer, err := s.admission.Verify(ctx, "admit", exact)
		if err != nil || answer.Decision != "allowed" {
			return managedUnavailable()
		}
		svc, ok := s.cfg.Service(exact.Service)
		if !ok {
			return managedUnavailable()
		}
		req, err := svc.Entry().Request(exact.Action, exact.Args)
		if err != nil {
			return managedUnavailable()
		}
		prepared, err = prepareNative(ctx, s.live, s.store, s.client, s.observer, exact.Service, req)
		if err != nil {
			return managedUnavailable()
		}
		answer, err = s.admission.Verify(ctx, "dispatch", exact)
		if err != nil || answer.Decision != "allowed" {
			return managedUnavailable()
		}
		return nil
	}, func(ctx context.Context, _ managedmcp.Request) (string, error) {
		if prepared == nil || ctx.Err() != nil || s.admission.Check() != nil {
			return "", managedUnavailable()
		}
		return prepared.managedResponse()
	})
}
