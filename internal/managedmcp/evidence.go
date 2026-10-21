package managedmcp

import "context"

// Evidence is a credential-free projection of an exact durable receipt. Digests
// bind consistency, not product-effect authenticity. No field grants authority.
// Returned denotes a protocol response; acknowledged uncertainty is not success.
type Evidence struct {
	EvidenceDigest        string `json:"evidence_digest,omitempty"`
	Version               int    `json:"version"`
	RootDigest            string `json:"root_digest"`
	ProfileDigest         string `json:"profile_digest"`
	InvocationID          string `json:"invocation_id"`
	ReceiptID             string `json:"receipt_id"`
	RequestDigest         string `json:"request_digest"`
	State                 State  `json:"state"`
	DecisionID            string `json:"decision_id,omitempty"`
	CancellationRequested bool   `json:"cancellation_requested"`
	ResolutionID          string `json:"resolution_id,omitempty"`
	ResolutionStopDigest  string `json:"resolution_stop_digest,omitempty"`
	RootRevoked           bool   `json:"root_revoked"`
	Authority             bool   `json:"authority"`
	ProductEffectVerified bool   `json:"product_effect_verified"`
}

// Evidence only accepts the existing closed inspect control. It requires the
// same fresh historical-reader owner confirmation and exact durable root/profile/
// request binding as Apply, even after execution expiry or revocation. It neither
// loads credential configuration nor authorizes an executor or mutates a receipt.
func (a *ControlAdmission) Evidence(ctx context.Context, c Control) (Evidence, error) {
	if c.Action != "inspect" {
		return Evidence{}, refused()
	}
	out, err := a.Apply(ctx, c)
	if err != nil || out.Receipt == nil {
		return Evidence{}, refused()
	}
	r := out.Receipt
	e := Evidence{Version: 1, RootDigest: c.RootDigest, ProfileDigest: c.ProfileDigest,
		InvocationID: c.InvocationID, ReceiptID: r.ID, RequestDigest: r.RequestDigest,
		State: r.State, DecisionID: r.DecisionID, CancellationRequested: r.CancellationRequested,
		ResolutionID: r.ResolutionID, ResolutionStopDigest: r.ResolutionStopDigest,
		RootRevoked: out.RootRevoked}
	e.EvidenceDigest = fingerprint(e)
	return e, nil
}
