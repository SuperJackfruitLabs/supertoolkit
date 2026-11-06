// Package publishcmd is the durable command path for SuperPipeline-gated X
// effects. Submission stores exact bytes; perform and recover load those bytes
// back before independently checking the gate.
package publishcmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/approval"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/controlplane"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/localstate"
)

const superPipelineBaseURL = "https://app.superpipeline.dev"

// Runtime carries the durable queue and the broker-owned dependency factory.
// Publisher is called only after the request has been loaded from disk.
type Runtime struct {
	Queue     *approval.Queue
	Publisher func(context.Context, approval.GatedRequest) (*approval.Publisher, error)
}

type submission struct {
	BoardID    string   `json:"boardId"`
	SubjectID  string   `json:"subjectId"`
	Method     string   `json:"method"`
	URL        string   `json:"url"`
	BodyBase64 string   `json:"bodyBase64"`
	Media      []string `json:"mediaBase64"`
	Summary    string   `json:"summary"`
}

// Command loads the broker-owned credentials and runs the publishing command.
func Command(args []string, version string) error {
	runtime, closeRuntime, err := productionRuntime(version)
	if err != nil {
		return err
	}
	defer closeRuntime()
	return Run(context.Background(), args, os.Stdin, os.Stdout, runtime)
}

// Run is the command protocol with explicit streams for tests.
func Run(ctx context.Context, args []string, in io.Reader, out io.Writer, runtime Runtime) error {
	if runtime.Queue == nil || runtime.Publisher == nil {
		return errors.New("publisher runtime is unavailable")
	}
	if len(args) == 0 {
		return errors.New("usage: stk publish submit|perform <id>|recover")
	}
	switch args[0] {
	case "submit":
		if len(args) != 1 {
			return errors.New("usage: stk publish submit")
		}
		return submit(in, out, runtime.Queue)
	case "perform":
		if len(args) != 2 {
			return errors.New("usage: stk publish perform <id>")
		}
		effect, err := perform(ctx, args[1], runtime)
		if effect != nil {
			if approval.IsAwaitingDecision(err) {
				_ = json.NewEncoder(out).Encode(map[string]string{"id": effect.ID, "state": "awaiting_decision"})
			} else {
				_ = json.NewEncoder(out).Encode(effect)
			}
		}
		return err
	case "recover":
		if len(args) != 1 {
			return errors.New("usage: stk publish recover")
		}
		return recover(ctx, out, runtime)
	default:
		return errors.New("usage: stk publish submit|perform <id>|recover")
	}
}

func submit(in io.Reader, out io.Writer, queue *approval.Queue) error {
	dec := json.NewDecoder(io.LimitReader(in, 32<<20))
	dec.DisallowUnknownFields()
	var input submission
	if err := dec.Decode(&input); err != nil {
		return fmt.Errorf("read publishing request: %w", err)
	}
	if input.Method != http.MethodPost || input.URL != "https://api.x.com/2/tweets" {
		return errors.New("automatic X publishing accepts only POST https://api.x.com/2/tweets")
	}
	if !identifier(input.BoardID, "brd_") || !identifier(input.SubjectID, "aps_") {
		return errors.New("publishing request needs valid SuperPipeline boardId and subjectId")
	}
	body, err := base64.StdEncoding.Strict().DecodeString(input.BodyBase64)
	if err != nil || len(body) == 0 {
		return errors.New("bodyBase64 must contain the exact non-empty request body")
	}
	media := make([][]byte, len(input.Media))
	for i, encoded := range input.Media {
		media[i], err = base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil {
			return fmt.Errorf("mediaBase64[%d] is invalid", i)
		}
	}
	if strings.TrimSpace(input.Summary) == "" {
		return errors.New("summary is required")
	}
	req := approval.GatedRequest{BoardID: input.BoardID, SubjectID: input.SubjectID, Method: input.Method, URL: input.URL, Body: body, Media: media}
	effect, err := queue.SubmitGated(req, input.Summary)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(map[string]string{"id": effect.ID, "digest": req.Digest(), "state": string(effect.State)})
}

func identifier(value, prefix string) bool {
	if len(value) != len(prefix)+16 || !strings.HasPrefix(value, prefix) {
		return false
	}
	for _, r := range value[len(prefix):] {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}

func perform(ctx context.Context, id string, runtime Runtime) (*approval.Effect, error) {
	req, err := runtime.Queue.GatedRequest(id)
	if err != nil {
		return nil, err
	}
	publisher, err := runtime.Publisher(ctx, req)
	if err != nil {
		return nil, err
	}
	return publisher.Perform(ctx, id, req)
}

func recover(ctx context.Context, out io.Writer, runtime Runtime) error {
	var first error
	for _, effect := range runtime.Queue.List() {
		if _, err := runtime.Queue.GatedRequest(effect.ID); err != nil {
			continue
		}
		// A pending gated effect is waiting on a person, not on recovery.
		if effect.State == approval.Pending {
			continue
		}
		switch effect.Outcome {
		case "outcome_unknown", "sending", "delivered", "retry_allowed":
		default:
			continue
		}
		got, err := perform(ctx, effect.ID, runtime)
		if got != nil {
			if approval.IsAwaitingDecision(err) {
				_ = json.NewEncoder(out).Encode(map[string]string{"id": got.ID, "state": "awaiting_decision"})
			} else {
				_ = json.NewEncoder(out).Encode(got)
			}
		}
		if err != nil && first == nil {
			first = err
		}
	}
	return first
}

func productionRuntime(version string) (Runtime, func(), error) {
	cfg, store, dir, err := localstate.LoadForRun()
	if err != nil {
		return Runtime{}, func() {}, err
	}
	service, err := controlplane.New(cfg, store, dir, "publish", version)
	if err != nil {
		return Runtime{}, func() {}, err
	}
	factory := func(ctx context.Context, req approval.GatedRequest) (*approval.Publisher, error) {
		username, err := xUsername(ctx, service.Perform)
		if err != nil {
			return nil, err
		}
		sp := &approval.SuperPipelineHTTPClient{
			BaseURL: superPipelineBaseURL,
			ApprovalDo: func(callCtx context.Context, request *http.Request) (*http.Response, error) {
				return service.Perform(callCtx, "superpipeline-approvals-read", request)
			},
			DeliveryDo: func(callCtx context.Context, request *http.Request) (*http.Response, error) {
				return service.Perform(callCtx, "superpipeline-approvals-write", request)
			},
		}
		gate := &approval.SubjectBoundGate{SuperPipelineHTTPClient: sp, SubjectID: req.SubjectID}
		x := &approval.XHTTPProvider{Username: username, Do: func(callCtx context.Context, request *http.Request) (*http.Response, error) {
			return service.Perform(callCtx, "x", request)
		}}
		return &approval.Publisher{Queue: service.Queue, Gate: gate, X: x}, nil
	}
	return Runtime{Queue: service.Queue, Publisher: factory}, service.CloseHosts, nil
}

type nativeExecutor = func(context.Context, string, *http.Request) (*http.Response, error)

func xUsername(ctx context.Context, execute nativeExecutor) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.x.com/2/users/me", nil)
	if err != nil {
		return "", err
	}
	resp, err := execute(ctx, "x", req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("x identity returned HTTP %d", resp.StatusCode)
	}
	var body struct {
		Data struct {
			Username string `json:"username"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body); err != nil || strings.TrimSpace(body.Data.Username) == "" {
		return "", errors.New("x identity response has no username")
	}
	return body.Data.Username, nil
}
