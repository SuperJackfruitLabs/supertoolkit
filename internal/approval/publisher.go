package approval

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// GatedRequest is the complete provider request bound by a SuperPipeline gate.
// Media is ordered: changing an item or its position changes Digest.
type GatedRequest struct {
	BoardID   string
	SubjectID string
	Method    string
	URL       string
	Body      []byte
	Media     [][]byte
}

// Digest length-prefixes every field so no two field boundaries are ambiguous.
func (r GatedRequest) Digest() string {
	h := sha256.New()
	write := func(label string, value []byte) {
		_ = binary.Write(h, binary.BigEndian, uint64(len(label)))
		_, _ = h.Write([]byte(label))
		_ = binary.Write(h, binary.BigEndian, uint64(len(value)))
		_, _ = h.Write(value)
	}
	write("method", []byte(r.Method))
	write("url", []byte(r.URL))
	write("body", r.Body)
	_ = binary.Write(h, binary.BigEndian, uint64(len(r.Media)))
	for i, media := range r.Media {
		mediaHash := sha256.Sum256(media)
		write(fmt.Sprintf("media:%d", i), mediaHash[:])
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

type GateConfirmation struct {
	Approved     bool   `json:"approved"`
	DeliveryMode string `json:"deliveryMode"`
	Digest       string `json:"digest"`
	GateID       string `json:"gateId"`
}

type GateClient interface {
	Confirm(ctx context.Context, boardID, subjectID, expectedDigest string) (GateConfirmation, error)
	RecordDelivered(ctx context.Context, boardID, gateID, digest, liveURL string) error
}

type SendResult struct{ StatusCode int }

type ReadBackStatus string

const (
	ReadBackFound        ReadBackStatus = "found"
	ReadBackNotFound     ReadBackStatus = "not_found"
	ReadBackInconclusive ReadBackStatus = "inconclusive"
)

type ReadBackResult struct {
	Status  ReadBackStatus
	LiveURL string
}

type XProvider interface {
	Send(context.Context, GatedRequest) (SendResult, error)
	ReadBack(context.Context, GatedRequest) (ReadBackResult, error)
}

type unknownOutcomeError struct{ error }

func (unknownOutcomeError) OutcomeUnknown() bool { return true }

// UnknownOutcome marks a transport failure that happened after a write may have reached the provider.
func UnknownOutcome(err error) error { return unknownOutcomeError{err} }

func isUnknownOutcome(err error) bool {
	var marked interface{ OutcomeUnknown() bool }
	return errors.As(err, &marked) && marked.OutcomeUnknown()
}

type publicationRecord struct {
	Outcome        string `json:"outcome"`
	Error          string `json:"error,omitempty"`
	ApprovedDigest string `json:"approved_digest,omitempty"`
	RequestDigest  string `json:"request_digest,omitempty"`
	GateID         string `json:"gate_id,omitempty"`
	LiveURL        string `json:"live_url,omitempty"`
	ReadBack       string `json:"read_back,omitempty"`
	Attempts       int    `json:"attempts"`
	CardRecorded   bool   `json:"card_recorded,omitempty"`
}

func (q *Queue) pubPath(id string) string   { return filepath.Join(q.dir, id+".pub") }
func (q *Queue) gatedPath(id string) string { return filepath.Join(q.dir, id+".gated") }
func (q *Queue) retryPath(id string) string { return filepath.Join(q.dir, id+".retry") }

// SubmitGated durably joins an approval queue entry to the exact provider
// request. A later executor needs only the id; request bytes never have to be
// supplied again after approval.
func (q *Queue) SubmitGated(req GatedRequest, summary string) (*Effect, error) {
	e := q.Submit("x", "post_tweet", summary, map[string]string{
		"_approval_authority": "superpipeline",
		"_approval_board":     req.BoardID,
		"_approval_subject":   req.SubjectID,
	})
	if e.State != Pending {
		return e, errors.New("could not persist gated effect")
	}
	body, err := json.Marshal(req)
	if err == nil {
		err = writeNew(q.gatedPath(e.ID), body)
	}
	if err != nil {
		_ = os.Remove(q.reqPath(e.ID))
		return e, err
	}
	return e, nil
}

// GatedRequest returns the immutable request stored at ingress.
func (q *Queue) GatedRequest(id string) (GatedRequest, error) {
	var req GatedRequest
	if !validID(id) {
		return req, fmt.Errorf("no effect %q is waiting", id)
	}
	raw, err := os.ReadFile(q.gatedPath(id))
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return req, err
	}
	return req, nil
}
func (q *Queue) readPublication(id string) (publicationRecord, error) {
	var r publicationRecord
	b, err := os.ReadFile(q.pubPath(id))
	if err != nil {
		return r, err
	}
	err = json.Unmarshal(b, &r)
	return r, err
}
func (q *Queue) writePublication(id string, r publicationRecord) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(q.dir, id+".pub-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0o600); err == nil {
		_, err = f.Write(b)
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, q.pubPath(id))
}

// Publisher is the automatic path. Gate holds stk's service-authenticated
// SuperPipeline client; no caller-provided assertion can replace its answer.
type Publisher struct {
	Queue *Queue
	Gate  GateClient
	X     XProvider
}

func (p *Publisher) Perform(ctx context.Context, id string, req GatedRequest) (*Effect, error) {
	if p.Queue == nil || p.Gate == nil || p.X == nil {
		return nil, errors.New("publisher requires queue, gate and X provider")
	}
	e, ok := p.Queue.Get(id)
	if !ok {
		return nil, fmt.Errorf("no effect %q is waiting", id)
	}
	if e.Args["_approval_authority"] != "superpipeline" || e.Args["_approval_board"] != req.BoardID || e.Args["_approval_subject"] != req.SubjectID {
		return p.refuse(e, publicationRecord{Outcome: "refused", RequestDigest: req.Digest()}, errors.New("effect is not bound to this SuperPipeline approval subject"))
	}

	rec, recErr := p.Queue.readPublication(id)
	if recErr == nil {
		p.apply(e, rec)
		current := req.Digest()
		if current != rec.RequestDigest {
			err := fmt.Errorf("approved digest %s does not match request digest %s", rec.ApprovedDigest, current)
			rec.Outcome, rec.Error, rec.RequestDigest = "refused", err.Error(), current
			if writeErr := p.Queue.writePublication(id, rec); writeErr != nil {
				return e, writeErr
			}
			p.apply(e, rec)
			return e, err
		}
		switch rec.Outcome {
		case "delivered":
			if !rec.CardRecorded {
				if err := p.Gate.RecordDelivered(ctx, req.BoardID, rec.GateID, rec.RequestDigest, rec.LiveURL); err != nil {
					return e, err
				}
				rec.CardRecorded = true
				_ = p.Queue.writePublication(id, rec)
				p.apply(e, rec)
			}
			return e, nil
		case "provider_error", "refused":
			return e, errors.New(rec.Error)
		case "outcome_unknown":
			return p.resolveUnknown(ctx, e, req, rec)
		case "sending":
			rec.Outcome, rec.Error = "outcome_unknown", "publisher stopped after the write began; provider read-back required"
			_ = p.Queue.writePublication(id, rec)
			return p.resolveUnknown(ctx, e, req, rec)
		}
	}

	requestDigest := req.Digest()
	confirmation, err := p.Gate.Confirm(ctx, req.BoardID, req.SubjectID, requestDigest)
	if err != nil {
		return p.refuse(e, publicationRecord{Outcome: "refused", RequestDigest: requestDigest}, err)
	}
	rec = publicationRecord{ApprovedDigest: confirmation.Digest, RequestDigest: requestDigest, GateID: confirmation.GateID}
	if !confirmation.Approved || confirmation.DeliveryMode != "automatic" {
		return p.refuse(e, rec, errors.New("SuperPipeline did not confirm automatic delivery"))
	}
	if confirmation.Digest != requestDigest {
		return p.refuse(e, rec, fmt.Errorf("approved digest %s does not match request digest %s", confirmation.Digest, requestDigest))
	}
	claimed, err := p.Queue.decide(id, true, "superpipeline:"+confirmation.GateID, true)
	if err != nil {
		return nil, err
	}
	e = claimed
	return p.send(ctx, e, req, rec, false)
}

func (p *Publisher) authorizeAgain(ctx context.Context, req GatedRequest, rec publicationRecord) (GateConfirmation, error) {
	current := req.Digest()
	confirmation, err := p.Gate.Confirm(ctx, req.BoardID, req.SubjectID, current)
	if err != nil {
		return confirmation, err
	}
	if !confirmation.Approved || confirmation.DeliveryMode != "automatic" || confirmation.GateID != rec.GateID || confirmation.Digest != current || current != rec.RequestDigest {
		return confirmation, fmt.Errorf("retry request digest %s no longer matches approved digest %s", current, confirmation.Digest)
	}
	return confirmation, nil
}

func (p *Publisher) send(ctx context.Context, e *Effect, req GatedRequest, rec publicationRecord, reauthorize bool) (*Effect, error) {
	if reauthorize {
		confirmation, err := p.authorizeAgain(ctx, req, rec)
		if err != nil {
			rec.Outcome, rec.Error = "refused", err.Error()
			if confirmation.Digest != "" {
				rec.ApprovedDigest = confirmation.Digest
			}
			_ = p.Queue.writePublication(e.ID, rec)
			p.apply(e, rec)
			return e, err
		}
	}
	// Recompute immediately before the provider write. No cached digest authorizes a side effect.
	current := req.Digest()
	if current != rec.ApprovedDigest || current != rec.RequestDigest {
		err := fmt.Errorf("approved digest %s does not match request digest %s", rec.ApprovedDigest, current)
		rec.Outcome, rec.Error, rec.RequestDigest = "refused", err.Error(), current
		_ = p.Queue.writePublication(e.ID, rec)
		p.apply(e, rec)
		return e, err
	}
	rec.Attempts++
	rec.Outcome, rec.Error = "sending", ""
	if err := p.Queue.writePublication(e.ID, rec); err != nil {
		return e, err
	}
	result, err := p.X.Send(ctx, req)
	if err != nil {
		if isUnknownOutcome(err) {
			rec.Outcome, rec.Error = "outcome_unknown", err.Error()
			_ = p.Queue.writePublication(e.ID, rec)
			return p.resolveUnknown(ctx, e, req, rec)
		}
		rec.Outcome, rec.Error = "provider_error", err.Error()
		_ = p.Queue.writePublication(e.ID, rec)
		p.apply(e, rec)
		return e, err
	}
	if result.StatusCode < 200 || result.StatusCode >= 300 {
		err = fmt.Errorf("x returned HTTP %d", result.StatusCode)
		rec.Outcome, rec.Error = "provider_error", err.Error()
		_ = p.Queue.writePublication(e.ID, rec)
		p.apply(e, rec)
		return e, err
	}
	read, readErr := p.X.ReadBack(ctx, req)
	if readErr == nil && read.Status == ReadBackFound && read.LiveURL != "" {
		return p.deliver(ctx, e, req, rec, read.LiveURL)
	}
	rec.Outcome, rec.ReadBack = "outcome_unknown", string(read.Status)
	if readErr != nil {
		rec.Error = readErr.Error()
	} else {
		rec.Error = "successful write was not conclusively found by read-back"
	}
	_ = p.Queue.writePublication(e.ID, rec)
	p.apply(e, rec)
	return e, errors.New(rec.Error)
}

func (p *Publisher) resolveUnknown(ctx context.Context, e *Effect, req GatedRequest, rec publicationRecord) (*Effect, error) {
	read, err := p.X.ReadBack(ctx, req)
	if err != nil {
		read.Status = ReadBackInconclusive
		rec.Error = err.Error()
	}
	rec.ReadBack = string(read.Status)
	switch read.Status {
	case ReadBackFound:
		if read.LiveURL == "" {
			rec.Error = "X read-back found a post without a canonical URL"
			break
		}
		return p.deliver(ctx, e, req, rec, read.LiveURL)
	case ReadBackNotFound:
		if rec.Attempts == 1 {
			claim, _ := json.Marshal(map[string]any{"request_digest": rec.RequestDigest, "claimed_at": p.Queue.now().UTC()})
			if err := writeNew(p.Queue.retryPath(e.ID), claim); err != nil {
				if errors.Is(err, os.ErrExist) {
					latest, readErr := p.Queue.readPublication(e.ID)
					if readErr == nil {
						p.apply(e, latest)
					}
					return e, errors.New("the single permitted retry was already claimed by another recovery process")
				}
				return e, err
			}
			rec.Outcome, rec.Error = "retry_allowed", ""
			if err := p.Queue.writePublication(e.ID, rec); err != nil {
				return e, err
			}
			return p.send(ctx, e, req, rec, true)
		}
		rec.Error = "negative read-back after the single permitted retry"
	default:
		if rec.Error == "" {
			rec.Error = "X read-back was inconclusive"
		}
	}
	rec.Outcome = "outcome_unknown"
	_ = p.Queue.writePublication(e.ID, rec)
	p.apply(e, rec)
	return e, errors.New(rec.Error)
}

func (p *Publisher) deliver(ctx context.Context, e *Effect, req GatedRequest, rec publicationRecord, liveURL string) (*Effect, error) {
	rec.Outcome, rec.Error, rec.LiveURL, rec.ReadBack = "delivered", "", liveURL, string(ReadBackFound)
	if err := p.Queue.writePublication(e.ID, rec); err != nil {
		return e, err
	}
	p.apply(e, rec)
	if err := p.Gate.RecordDelivered(ctx, req.BoardID, rec.GateID, rec.RequestDigest, liveURL); err != nil {
		return e, err
	}
	rec.CardRecorded = true
	if err := p.Queue.writePublication(e.ID, rec); err != nil {
		return e, err
	}
	p.apply(e, rec)
	return e, nil
}

func (p *Publisher) refuse(e *Effect, rec publicationRecord, cause error) (*Effect, error) {
	rec.Outcome, rec.Error = "refused", cause.Error()
	if e.State == Pending {
		decided, err := p.Queue.decide(e.ID, false, "supertoolkit", false)
		if err != nil {
			return nil, err
		}
		e = decided
	}
	if err := p.Queue.writePublication(e.ID, rec); err != nil {
		return e, err
	}
	p.apply(e, rec)
	return e, cause
}
func (p *Publisher) apply(e *Effect, r publicationRecord) {
	e.Outcome, e.Error, e.ApprovedDigest, e.RequestDigest = r.Outcome, r.Error, r.ApprovedDigest, r.RequestDigest
	e.LiveURL, e.ReadBack, e.Attempts = r.LiveURL, r.ReadBack, r.Attempts
}

// SuperPipelineHTTPClient authenticates with stk-owned token suppliers. Tokens
// are applied inside the client and are never accepted in an effect or returned.
type SuperPipelineHTTPClient struct {
	BaseURL       string
	HTTP          *http.Client
	ApprovalToken func(context.Context) (string, error)
	DeliveryToken func(context.Context) (string, error)
	// Production uses broker-owned transports so a token is never returned to
	// this package (or to the command caller). Token suppliers remain a test seam.
	ApprovalDo func(context.Context, *http.Request) (*http.Response, error)
	DeliveryDo func(context.Context, *http.Request) (*http.Response, error)
}

func (c *SuperPipelineHTTPClient) post(ctx context.Context, path string, body any, token func(context.Context) (string, error), do func(context.Context, *http.Request) (*http.Response, error), out any) error {
	if token == nil && do == nil {
		return errors.New("stk service credential is not configured")
	}
	payload, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.BaseURL, "/")+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	var resp *http.Response
	if do != nil {
		resp, err = do(ctx, req)
	} else {
		secret, tokenErr := token(ctx)
		if tokenErr != nil {
			return tokenErr
		}
		req.Header.Set("Authorization", "Bearer "+secret)
		client := c.HTTP
		if client == nil {
			client = http.DefaultClient
		}
		resp, err = client.Do(req)
	}
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("SuperPipeline returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}
func (c *SuperPipelineHTTPClient) Confirm(ctx context.Context, boardID, subjectID, digest string) (GateConfirmation, error) {
	var out GateConfirmation
	err := c.post(ctx, "/v1/boards/"+url.PathEscape(boardID)+"/approval-subjects/"+url.PathEscape(subjectID)+"/verify", map[string]string{"expectedDigest": digest}, c.ApprovalToken, c.ApprovalDo, &out)
	return out, err
}
func (c *SuperPipelineHTTPClient) RecordDelivered(ctx context.Context, boardID, gateID, digest, liveURL string) error {
	// subject id is part of the verified gate URL in production callers; the endpoint accepts it in the path.
	return errors.New("RecordDelivered requires a subject-bound client")
}

// SubjectBoundGate binds the immutable subject once, avoiding caller-controlled reporting paths.
type SubjectBoundGate struct {
	*SuperPipelineHTTPClient
	SubjectID string
}

func (c *SubjectBoundGate) RecordDelivered(ctx context.Context, boardID, gateID, digest, liveURL string) error {
	return c.post(ctx, "/v1/boards/"+url.PathEscape(boardID)+"/approval-subjects/"+url.PathEscape(c.SubjectID)+"/delivery", map[string]string{"expectedDigest": digest, "gateId": gateID, "liveUrl": liveURL}, c.DeliveryToken, c.DeliveryDo, nil)
}

// XHTTPProvider performs the deterministic X write and exact-text read-back
// through stk's credentialed transport. Do injects the credential internally;
// neither GatedRequest nor the caller can supply or observe it.
type XHTTPProvider struct {
	Do       func(context.Context, *http.Request) (*http.Response, error)
	Username string
}

func (x *XHTTPProvider) Send(ctx context.Context, request GatedRequest) (SendResult, error) {
	if x.Do == nil {
		return SendResult{}, errors.New("x credentialed transport is not configured")
	}
	req, err := http.NewRequestWithContext(ctx, request.Method, request.URL, bytes.NewReader(request.Body))
	if err != nil {
		return SendResult{}, err
	}
	if len(request.Body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := x.Do(ctx, req)
	if err != nil {
		// Once handed to a transport, an error cannot prove that no request bytes
		// reached X. Conservatively fence it until read-back resolves the outcome.
		return SendResult{}, UnknownOutcome(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 256<<10))
	return SendResult{StatusCode: resp.StatusCode}, nil
}

func (x *XHTTPProvider) ReadBack(ctx context.Context, request GatedRequest) (ReadBackResult, error) {
	if x.Do == nil || strings.TrimSpace(x.Username) == "" {
		return ReadBackResult{Status: ReadBackInconclusive}, errors.New("x read-back identity is not configured")
	}
	var post struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(request.Body, &post); err != nil || post.Text == "" {
		return ReadBackResult{Status: ReadBackInconclusive}, errors.New("x request body has no exact text to read back")
	}
	base, err := url.Parse(request.URL)
	if err != nil {
		return ReadBackResult{Status: ReadBackInconclusive}, err
	}
	base.Path = "/2/tweets/search/recent"
	base.RawQuery = url.Values{
		"query":        {fmt.Sprintf("from:%s %q", x.Username, post.Text)},
		"tweet.fields": {"author_id,created_at"},
		"max_results":  {"10"},
	}.Encode()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	resp, err := x.Do(ctx, req)
	if err != nil {
		return ReadBackResult{Status: ReadBackInconclusive}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ReadBackResult{Status: ReadBackInconclusive}, fmt.Errorf("x read-back returned HTTP %d", resp.StatusCode)
	}
	var result struct {
		Data []struct {
			ID   string `json:"id"`
			Text string `json:"text"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(&result); err != nil {
		return ReadBackResult{Status: ReadBackInconclusive}, err
	}
	matches := make([]string, 0, 1)
	for _, item := range result.Data {
		if item.Text == post.Text && item.ID != "" {
			matches = append(matches, item.ID)
		}
	}
	if len(matches) == 0 {
		return ReadBackResult{Status: ReadBackNotFound}, nil
	}
	if len(matches) != 1 {
		return ReadBackResult{Status: ReadBackInconclusive}, errors.New("x read-back found multiple exact candidates")
	}
	return ReadBackResult{Status: ReadBackFound, LiveURL: "https://x.com/" + url.PathEscape(x.Username) + "/status/" + url.PathEscape(matches[0])}, nil
}
