package approval

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// CreateApprovalRequest hosts an approval on the board. It goes out on the
// write credential (approval-requests:write), applied inside DeliveryDo.
func (c *SuperPipelineHTTPClient) CreateApprovalRequest(ctx context.Context, board string, body ApprovalRequest) (ApprovalCreated, error) {
	var out ApprovalCreated
	err := c.post(ctx, "/v1/boards/"+url.PathEscape(board)+"/approval-requests", body, c.DeliveryToken, c.DeliveryDo, &out)
	return out, err
}

// ReadApprovalRequest reads the decision back on the read credential
// (approval-requests:read), applied inside ApprovalDo.
func (c *SuperPipelineHTTPClient) ReadApprovalRequest(ctx context.Context, board, id string) (ApprovalReadBack, error) {
	var out ApprovalReadBack
	if c.ApprovalToken == nil && c.ApprovalDo == nil {
		return out, errors.New("stk service credential is not configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(c.BaseURL, "/")+"/v1/boards/"+url.PathEscape(board)+"/approval-requests/"+url.PathEscape(id), nil)
	if err != nil {
		return out, err
	}
	var resp *http.Response
	if c.ApprovalDo != nil {
		resp, err = c.ApprovalDo(ctx, req)
	} else {
		secret, tokenErr := c.ApprovalToken(ctx)
		if tokenErr != nil {
			return out, tokenErr
		}
		req.Header.Set("Authorization", "Bearer "+secret)
		client := c.HTTP
		if client == nil {
			client = http.DefaultClient
		}
		resp, err = client.Do(req)
	}
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return out, fmt.Errorf("SuperPipeline returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return out, json.Unmarshal(raw, &out)
}
