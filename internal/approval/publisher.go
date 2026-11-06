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
	"html"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	xWebScheme = regexp.MustCompile(`https?://`)
	xMediaURL  = regexp.MustCompile(`/((photo)|(video))/[0-9]+(?:$|[?#])`)
)

type xURLEntity struct {
	URL         string `json:"url"`
	ExpandedURL string `json:"expanded_url"`
	MediaKey    string `json:"media_key"`
}

type xEntities struct {
	URLs []xURLEntity `json:"urls"`
}

type xNoteTweet struct {
	Text     string    `json:"text"`
	Entities xEntities `json:"entities"`
}

func normalizeXText(text string, entities []xURLEntity) string {
	normalized := html.UnescapeString(text)
	for _, entity := range entities {
		if entity.URL == "" {
			continue
		}
		if entity.MediaKey != "" || xMediaURL.MatchString(entity.ExpandedURL) {
			normalized = strings.ReplaceAll(normalized, " "+entity.URL, "")
			normalized = strings.ReplaceAll(normalized, entity.URL+" ", "")
			normalized = strings.ReplaceAll(normalized, entity.URL, "")
			continue
		}
		if entity.ExpandedURL != "" {
			normalized = strings.ReplaceAll(normalized, entity.URL, entity.ExpandedURL)
		}
	}
	return strings.TrimSpace(xWebScheme.ReplaceAllString(normalized, ""))
}

func normalizeXPost(text string, entities xEntities, note xNoteTweet) string {
	if note.Text != "" {
		return normalizeXText(note.Text, note.Entities.URLs)
	}
	return normalizeXText(text, entities.URLs)
}

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
	ExpiresAt    string `json:"expiresAt"`
	GateStatus   string `json:"gateStatus"`
}

type GateClient interface {
	Confirm(ctx context.Context, boardID, subjectID, expectedDigest string) (GateConfirmation, error)
	RecordDelivered(ctx context.Context, boardID, gateID, digest, liveURL string) error
}

type SendResult struct {
	StatusCode int
	PostID     string
	MediaIDs   []string
}

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
	ReadBack(context.Context, GatedRequest, SendResult) (ReadBackResult, error)
}

type unknownOutcomeError struct{ error }

func (unknownOutcomeError) OutcomeUnknown() bool { return true }

// UnknownOutcome marks a transport failure that happened after a write may have reached the provider.
func UnknownOutcome(err error) error { return unknownOutcomeError{err} }

func isUnknownOutcome(err error) bool {
	var marked interface{ OutcomeUnknown() bool }
	return errors.As(err, &marked) && marked.OutcomeUnknown()
}

// AwaitingDecisionError means the SuperPipeline gate is still open. It is a
// non-terminal result: the durable effect remains untouched for later review.
type AwaitingDecisionError struct{}

func (AwaitingDecisionError) Error() string { return "SuperPipeline gate is awaiting_decision" }

// IsAwaitingDecision lets command callers distinguish a pending human gate
// from a failed publish attempt.
func IsAwaitingDecision(err error) bool {
	var pending AwaitingDecisionError
	return errors.As(err, &pending)
}

type publicationRecord struct {
	Outcome        string   `json:"outcome"`
	Error          string   `json:"error,omitempty"`
	ApprovedDigest string   `json:"approved_digest,omitempty"`
	RequestDigest  string   `json:"request_digest,omitempty"`
	GateID         string   `json:"gate_id,omitempty"`
	LiveURL        string   `json:"live_url,omitempty"`
	ReadBack       string   `json:"read_back,omitempty"`
	Attempts       int      `json:"attempts"`
	CardRecorded   bool     `json:"card_recorded,omitempty"`
	PostID         string   `json:"post_id,omitempty"`
	MediaIDs       []string `json:"media_ids,omitempty"`
}

func (q *Queue) pubPath(id string) string   { return filepath.Join(q.dir, id+".pub") }
func (q *Queue) gatedPath(id string) string { return filepath.Join(q.dir, id+".gated") }
func (q *Queue) retryPath(id string) string { return filepath.Join(q.dir, id+".retry") }

// SubmitGated durably joins an approval queue entry to the exact provider
// request. A later executor needs only the id; request bytes never have to be
// supplied again after approval.
func (q *Queue) SubmitGated(req GatedRequest, summary string) (*Effect, error) {
	now := q.now()
	e := &Effect{
		ID: newID(), Service: "x", Capability: "post_tweet", Summary: summary,
		Args: map[string]string{
			"_approval_authority": "superpipeline",
			"_approval_board":     req.BoardID,
			"_approval_subject":   req.SubjectID,
		},
		Submitted: now, Expires: now.Add(gatedBackstopTTL), State: Pending,
	}
	gatedBody, err := json.Marshal(req)
	if err != nil {
		return e, err
	}
	requestBody, err := json.Marshal(e)
	if err != nil {
		return e, err
	}
	// Publish the immutable authority marker before the request becomes visible,
	// so a concurrent local approvals command can never mistake it for an
	// ordinary effect. A partial gated marker is harmless and collectible.
	if err := writeNew(q.gatedPath(e.ID), gatedBody); err != nil {
		return e, err
	}
	if err := writeNew(q.reqPath(e.ID), requestBody); err != nil {
		_ = os.Remove(q.gatedPath(e.ID))
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
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(name, q.pubPath(id)); err != nil {
		return err
	}
	dir, err := os.Open(q.dir)
	if err != nil {
		return err
	}
	err = dir.Sync()
	if closeErr := dir.Close(); err == nil {
		err = closeErr
	}
	return err
}

// Publisher is the automatic path. Gate holds stk's service-authenticated
// SuperPipeline client; no caller-provided assertion can replace its answer.
type Publisher struct {
	Queue *Queue
	Gate  GateClient
	X     XProvider
}

func (p *Publisher) Perform(ctx context.Context, id string, req GatedRequest) (effect *Effect, err error) {
	if p.Queue == nil || p.Gate == nil || p.X == nil {
		return nil, errors.New("publisher requires queue, gate and X provider")
	}
	if !validID(id) {
		return nil, fmt.Errorf("no effect %q is waiting", id)
	}
	unlock, err := p.Queue.lockPublication(id)
	if err != nil {
		return nil, err
	}
	defer func() {
		if unlockErr := unlock(); err == nil && unlockErr != nil {
			err = unlockErr
		}
	}()

	e, ok := p.Queue.Get(id)
	if !ok {
		return nil, fmt.Errorf("no effect %q is waiting", id)
	}
	if e.Args["_approval_authority"] != "superpipeline" || e.Args["_approval_board"] != req.BoardID || e.Args["_approval_subject"] != req.SubjectID {
		return p.refuse(e, publicationRecord{Outcome: "refused", RequestDigest: req.Digest()}, errors.New("effect is not bound to this SuperPipeline approval subject"))
	}
	if e.State == Expired && !e.GateExpirySet {
		return p.refuse(e, publicationRecord{Outcome: "refused", RequestDigest: req.Digest()}, errors.New("unconfirmed SuperPipeline gate exceeded its backstop"))
	}

	rec, recErr := p.Queue.readPublication(id)
	if recErr == nil {
		p.apply(e, rec)
		current := req.Digest()
		if current != rec.RequestDigest {
			err := fmt.Errorf("approved digest %s does not match request digest %s", rec.ApprovedDigest, current)
			if rec.Outcome == "delivered" || rec.Outcome == "sending" || rec.Outcome == "outcome_unknown" {
				return e, err
			}
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
		case "retry_allowed":
			return e, errors.New("publisher retry was authorized but not completed; manual recovery is required")
		}
	}
	if e.State == Approved {
		return e, errors.New("automatic delivery was approved but no durable sending marker exists; manual recovery is required")
	}

	requestDigest := req.Digest()
	confirmation, err := p.Gate.Confirm(ctx, req.BoardID, req.SubjectID, requestDigest)
	if err != nil {
		return e, err
	}
	rec = publicationRecord{ApprovedDigest: confirmation.Digest, RequestDigest: requestDigest, GateID: confirmation.GateID}
	if !confirmation.Approved && confirmation.DeliveryMode == "none" && (confirmation.GateStatus == "pending" || confirmation.GateStatus == "open") {
		return e, AwaitingDecisionError{}
	}
	if !confirmation.Approved || confirmation.DeliveryMode != "automatic" {
		return p.refuse(e, rec, errors.New("SuperPipeline did not confirm automatic delivery"))
	}
	if confirmation.Digest != requestDigest {
		return p.refuse(e, rec, fmt.Errorf("approved digest %s does not match request digest %s", confirmation.Digest, requestDigest))
	}
	expires, parseErr := time.Parse(time.RFC3339, confirmation.ExpiresAt)
	if parseErr != nil || !expires.After(p.Queue.now()) {
		return p.refuse(e, rec, errors.New("SuperPipeline approval expiry is missing, invalid or elapsed"))
	}
	if err := p.Queue.setGateExpiry(id, expires); err != nil {
		return e, err
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
	rec.PostID = result.PostID
	rec.MediaIDs = append([]string(nil), result.MediaIDs...)
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
	if err := p.Queue.writePublication(e.ID, rec); err != nil {
		return e, err
	}
	read, readErr := p.X.ReadBack(ctx, req, result)
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
	read, err := p.X.ReadBack(ctx, req, SendResult{PostID: rec.PostID, MediaIDs: append([]string(nil), rec.MediaIDs...)})
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
		// X's exact-id and recent-search indexes are eventually consistent. A
		// miss cannot prove the create failed, so it never authorizes a retry.
		rec.Error = "X read-back has not found the post yet; search/index lag is inconclusive and retry remains fenced"
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
	e.PostID, e.MediaIDs = r.PostID, append([]string(nil), r.MediaIDs...)
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
	frozenDigest := request.Digest()
	mediaTypes, postBody, err := prepareXMedia(request)
	if err != nil {
		return SendResult{}, err
	}
	result := SendResult{}
	for i, media := range request.Media {
		mediaID, uploadErr := x.uploadMedia(ctx, request, frozenDigest, i, mediaTypes[i], media)
		if uploadErr != nil {
			return result, uploadErr
		}
		result.MediaIDs = append(result.MediaIDs, mediaID)
	}
	if len(result.MediaIDs) > 0 {
		postBody, err = attachXMedia(postBody, result.MediaIDs)
		if err != nil {
			return result, err
		}
	}
	if err := requireFrozenDigest(request, frozenDigest, "create post"); err != nil {
		return result, err
	}
	req, err := http.NewRequestWithContext(ctx, request.Method, request.URL, bytes.NewReader(postBody))
	if err != nil {
		return result, err
	}
	if len(postBody) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := x.Do(ctx, req)
	if err != nil {
		// Once the public-post write reaches a transport, an error cannot prove
		// that no request bytes reached X. Media-only writes are handled above
		// and do not make a public post.
		return result, UnknownOutcome(err)
	}
	defer resp.Body.Close()
	result.StatusCode = resp.StatusCode
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 256<<10))
		return result, nil
	}
	var created struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(&created); err != nil || strings.TrimSpace(created.Data.ID) == "" {
		return result, UnknownOutcome(errors.New("x create response has no post id"))
	}
	result.PostID = created.Data.ID
	return result, nil
}

func prepareXMedia(request GatedRequest) ([]string, []byte, error) {
	if len(request.Media) > 4 {
		return nil, nil, errors.New("x media validation: a post accepts at most four images")
	}
	var post map[string]json.RawMessage
	if err := json.Unmarshal(request.Body, &post); err != nil || len(post) == 0 {
		return nil, nil, errors.New("x post body must be a JSON object")
	}
	if len(request.Media) > 0 {
		if _, exists := post["media"]; exists {
			return nil, nil, errors.New("x post body media must come from the frozen media bytes")
		}
	}
	mediaTypes := make([]string, len(request.Media))
	for i, media := range request.Media {
		if len(media) == 0 || len(media) > 5<<20 {
			return nil, nil, fmt.Errorf("x media validation [%d]: image must contain 1 byte through 5 MiB", i)
		}
		mediaType := http.DetectContentType(media)
		switch mediaType {
		case "image/jpeg", "image/png", "image/gif", "image/webp", "image/bmp":
			mediaTypes[i] = mediaType
		default:
			return nil, nil, fmt.Errorf("x media validation [%d]: unsupported image type %s", i, mediaType)
		}
	}
	return mediaTypes, append([]byte(nil), request.Body...), nil
}

func attachXMedia(body []byte, mediaIDs []string) ([]byte, error) {
	var post map[string]json.RawMessage
	if err := json.Unmarshal(body, &post); err != nil {
		return nil, err
	}
	media, err := json.Marshal(struct {
		IDs []string `json:"media_ids"`
	}{IDs: mediaIDs})
	if err != nil {
		return nil, err
	}
	post["media"] = media
	return json.Marshal(post)
}

func requireFrozenDigest(request GatedRequest, frozenDigest, operation string) error {
	if current := request.Digest(); current != frozenDigest {
		return fmt.Errorf("x %s refused: frozen request digest changed from %s to %s", operation, frozenDigest, current)
	}
	return nil
}

func (x *XHTTPProvider) uploadMedia(ctx context.Context, request GatedRequest, frozenDigest string, index int, mediaType string, media []byte) (string, error) {
	base, err := url.Parse(request.URL)
	if err != nil {
		return "", err
	}
	base.Path, base.RawQuery = "/2/media/upload/initialize", ""
	initialize, _ := json.Marshal(struct {
		MediaCategory string `json:"media_category"`
		MediaType     string `json:"media_type"`
		TotalBytes    int    `json:"total_bytes"`
	}{MediaCategory: "tweet_image", MediaType: mediaType, TotalBytes: len(media)})
	if err := requireFrozenDigest(request, frozenDigest, "media initialize"); err != nil {
		return "", err
	}
	initReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base.String(), bytes.NewReader(initialize))
	if err != nil {
		return "", err
	}
	initReq.Header.Set("Content-Type", "application/json")
	initResp, err := x.Do(ctx, initReq)
	if err != nil {
		return "", fmt.Errorf("x media initialize [%d]: %w", index, err)
	}
	var initialized struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := decodeXMediaResponse(initResp, "initialize", index, &initialized); err != nil {
		return "", err
	}
	mediaID := strings.TrimSpace(initialized.Data.ID)
	if mediaID == "" {
		return "", fmt.Errorf("x media initialize [%d]: response has no media id", index)
	}

	var appendBody bytes.Buffer
	writer := multipart.NewWriter(&appendBody)
	boundaryHash := sha256.Sum256([]byte(frozenDigest))
	boundary := "stk-" + hex.EncodeToString(boundaryHash[:16]) + "-" + strconv.Itoa(index)
	if err := writer.SetBoundary(boundary); err != nil {
		return "", err
	}
	if err := writer.WriteField("segment_index", "0"); err != nil {
		return "", err
	}
	part, err := writer.CreateFormFile("media", "media")
	if err != nil {
		return "", err
	}
	if _, err := part.Write(media); err != nil {
		return "", err
	}
	if err := writer.Close(); err != nil {
		return "", err
	}
	base.Path = "/2/media/upload/" + url.PathEscape(mediaID) + "/append"
	if err := requireFrozenDigest(request, frozenDigest, "media append"); err != nil {
		return "", err
	}
	appendReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base.String(), &appendBody)
	if err != nil {
		return "", err
	}
	appendReq.Header.Set("Content-Type", writer.FormDataContentType())
	appendResp, err := x.Do(ctx, appendReq)
	if err != nil {
		return "", fmt.Errorf("x media append [%d]: %w", index, err)
	}
	if err := decodeXMediaResponse(appendResp, "append", index, nil); err != nil {
		return "", err
	}

	base.Path = "/2/media/upload/" + url.PathEscape(mediaID) + "/finalize"
	if err := requireFrozenDigest(request, frozenDigest, "media finalize"); err != nil {
		return "", err
	}
	finalizeReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base.String(), nil)
	if err != nil {
		return "", err
	}
	finalizeResp, err := x.Do(ctx, finalizeReq)
	if err != nil {
		return "", fmt.Errorf("x media finalize [%d]: %w", index, err)
	}
	var finalized struct {
		Data struct {
			ID             string `json:"id"`
			ProcessingInfo struct {
				State          string `json:"state"`
				CheckAfterSecs int    `json:"check_after_secs"`
			} `json:"processing_info"`
		} `json:"data"`
	}
	if err := decodeXMediaResponse(finalizeResp, "finalize", index, &finalized); err != nil {
		return "", err
	}
	if finalized.Data.ID != mediaID {
		return "", fmt.Errorf("x media finalize [%d]: media id changed from %s to %s", index, mediaID, finalized.Data.ID)
	}
	for attempts := 0; finalized.Data.ProcessingInfo.State == "pending" || finalized.Data.ProcessingInfo.State == "in_progress"; attempts++ {
		if attempts >= 20 {
			return "", fmt.Errorf("x media finalize [%d]: processing did not finish", index)
		}
		delay := time.Duration(finalized.Data.ProcessingInfo.CheckAfterSecs) * time.Second
		if delay <= 0 {
			delay = 100 * time.Millisecond
		}
		if delay > 2*time.Second {
			delay = 2 * time.Second
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", ctx.Err()
		case <-timer.C:
		}
		base.Path = "/2/media/upload"
		base.RawQuery = url.Values{"command": {"STATUS"}, "media_id": {mediaID}}.Encode()
		statusReq, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
		if err != nil {
			return "", err
		}
		statusResp, err := x.Do(ctx, statusReq)
		if err != nil {
			return "", fmt.Errorf("x media status [%d]: %w", index, err)
		}
		if err := decodeXMediaResponse(statusResp, "status", index, &finalized); err != nil {
			return "", err
		}
	}
	if state := finalized.Data.ProcessingInfo.State; state != "" && state != "succeeded" {
		return "", fmt.Errorf("x media finalize [%d]: processing state %s failed", index, state)
	}
	return mediaID, nil
}

func decodeXMediaResponse(resp *http.Response, operation string, index int, out any) error {
	if resp == nil {
		return fmt.Errorf("x media %s [%d]: empty response", operation, index)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 256<<10))
		return fmt.Errorf("x media %s [%d] returned HTTP %d", operation, index, resp.StatusCode)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 256<<10))
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(out); err != nil {
		return fmt.Errorf("x media %s [%d]: %w", operation, index, err)
	}
	return nil
}

func xMediaKeysMatch(keys, mediaIDs []string) bool {
	if len(keys) != len(mediaIDs) {
		return false
	}
	for i, key := range keys {
		prefix, id, found := strings.Cut(key, "_")
		if !found || prefix == "" || id != mediaIDs[i] {
			return false
		}
	}
	return true
}

func (x *XHTTPProvider) ReadBack(ctx context.Context, request GatedRequest, sent SendResult) (ReadBackResult, error) {
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
	if sent.PostID != "" {
		base.Path = "/2/tweets/" + url.PathEscape(sent.PostID)
		base.RawQuery = url.Values{
			"expansions":   {"attachments.media_keys"},
			"media.fields": {"media_key"},
			"tweet.fields": {"attachments,entities,note_tweet"},
		}.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
		if err != nil {
			return ReadBackResult{Status: ReadBackInconclusive}, err
		}
		resp, doErr := x.Do(ctx, req)
		if doErr != nil {
			return ReadBackResult{Status: ReadBackInconclusive}, doErr
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			return ReadBackResult{Status: ReadBackNotFound}, nil
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return ReadBackResult{Status: ReadBackInconclusive}, fmt.Errorf("x read-back returned HTTP %d", resp.StatusCode)
		}
		var exact struct {
			Data struct {
				ID          string `json:"id"`
				Text        string `json:"text"`
				Attachments struct {
					MediaKeys []string `json:"media_keys"`
				} `json:"attachments"`
				Entities  xEntities  `json:"entities"`
				NoteTweet xNoteTweet `json:"note_tweet"`
			} `json:"data"`
		}
		if decodeErr := json.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(&exact); decodeErr != nil {
			return ReadBackResult{Status: ReadBackInconclusive}, decodeErr
		}
		// The provider-assigned id is the correlation key, but the returned
		// content must still match after accounting for X's documented entity,
		// media-suffix and long-form note_tweet representations.
		if exact.Data.ID != sent.PostID {
			return ReadBackResult{Status: ReadBackInconclusive}, errors.New("x read-back did not match the created post id")
		}
		if !xMediaKeysMatch(exact.Data.Attachments.MediaKeys, sent.MediaIDs) {
			return ReadBackResult{Status: ReadBackInconclusive}, errors.New("x read-back media does not match the uploaded media ids")
		}
		// URL entities describe X's t.co transformation. Media entities are a
		// presentation-only suffix and are absent from the approved post text.
		if normalizeXPost(exact.Data.Text, exact.Data.Entities, exact.Data.NoteTweet) != normalizeXText(post.Text, nil) {
			return ReadBackResult{Status: ReadBackInconclusive}, errors.New("x read-back content does not match the approved post")
		}
		return ReadBackResult{Status: ReadBackFound, LiveURL: "https://x.com/" + url.PathEscape(x.Username) + "/status/" + url.PathEscape(sent.PostID)}, nil
	}

	base.Path = "/2/tweets/search/recent"
	base.RawQuery = url.Values{
		// Search only by the authenticated author. Quoting the entire post both
		// exceeds X's 512-character query limit and misses t.co rewrites.
		"query":        {"from:" + x.Username},
		"tweet.fields": {"author_id,created_at,entities,note_tweet"},
		"max_results":  {"10"},
	}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return ReadBackResult{Status: ReadBackInconclusive}, err
	}
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
			ID        string     `json:"id"`
			Text      string     `json:"text"`
			Entities  xEntities  `json:"entities"`
			NoteTweet xNoteTweet `json:"note_tweet"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(&result); err != nil {
		return ReadBackResult{Status: ReadBackInconclusive}, err
	}
	matches := make([]string, 0, 1)
	for _, item := range result.Data {
		if normalizeXPost(item.Text, item.Entities, item.NoteTweet) == normalizeXText(post.Text, nil) && item.ID != "" {
			matches = append(matches, item.ID)
		}
	}
	if len(matches) == 0 {
		return ReadBackResult{Status: ReadBackInconclusive}, errors.New("x recent search has not indexed an exact normalized match yet")
	}
	return ReadBackResult{Status: ReadBackInconclusive}, errors.New("x read-back found normalized text but cannot correlate it to an unknown create outcome")
}
