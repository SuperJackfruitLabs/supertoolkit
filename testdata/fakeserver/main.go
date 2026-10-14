// Command fakeserver stands in for a third-party MCP server.
//
// It behaves the way a real one does and the way we must assume they all do:
// it reads its credential from an environment variable, builds its own HTTP
// client, and knows nothing about supertoolkit. The point of the tests that use
// it is that it is given only a placeholder and still works.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

type req struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type resp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rerr           `json:"error,omitempty"`
}

type rerr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func textResult(s string) any {
	return map[string]any{"content": []any{map[string]any{"type": "text", "text": s}}}
}

func main() {
	// Exactly as a real server does: the credential comes from the environment.
	token := os.Getenv("FAKE_API_TOKEN")
	target := os.Getenv("FAKE_API_URL")
	if target == "" {
		target = "https://fake.example/whoami"
	}

	in := bufio.NewReader(os.Stdin)
	enc := json.NewEncoder(os.Stdout)
	dec := json.NewDecoder(in)

	for {
		var r req
		if err := dec.Decode(&r); err != nil {
			if err == io.EOF {
				return
			}
			return
		}
		switch r.Method {
		case "initialize":
			enc.Encode(resp{JSONRPC: "2.0", ID: r.ID, Result: map[string]any{
				"protocolVersion": "2025-06-18",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "fakeserver", "version": "1.0"},
			}})
		case "notifications/initialized":
			// no reply
		case "tools/list":
			enc.Encode(resp{JSONRPC: "2.0", ID: r.ID, Result: map[string]any{
				"tools": []any{
					map[string]any{
						"name":        "whoami",
						"description": "Ask the upstream API who we are.",
						"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
						"annotations": map[string]any{"readOnlyHint": true},
					},
					map[string]any{
						"name":        "post_message",
						"description": "Send a message upstream.",
						"inputSchema": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"text": map[string]any{"type": "string"},
							},
							"required": []any{"text"},
						},
					},
					map[string]any{
						"name":        "report_env",
						"description": "Report what this server can see of its own credential.",
						"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
					},
				},
			}})
		case "tools/call":
			var p struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			}
			json.Unmarshal(r.Params, &p)
			switch p.Name {
			case "report_env":
				// What this server believes its credential is. The test asserts
				// it is the placeholder and not the real thing.
				enc.Encode(resp{JSONRPC: "2.0", ID: r.ID, Result: textResult(token)})
			case "whoami", "post_message":
				body, status := callUpstream(target, token, p)
				enc.Encode(resp{JSONRPC: "2.0", ID: r.ID,
					Result: textResult(fmt.Sprintf("%d %s", status, strings.TrimSpace(body)))})
			default:
				enc.Encode(resp{JSONRPC: "2.0", ID: r.ID, Error: &rerr{Code: -32602, Message: "unknown tool " + p.Name}})
			}
		default:
			enc.Encode(resp{JSONRPC: "2.0", ID: r.ID, Error: &rerr{Code: -32601, Message: "unknown method " + r.Method}})
		}
	}
}

// callUpstream builds its own client and sets its own header, which is what
// makes this a fair stand-in: nothing here cooperates with a broker.
func callUpstream(target, token string, p struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}) (string, int) {
	method := "GET"
	var body io.Reader
	if p.Name == "post_message" {
		method = "POST"
		raw, _ := json.Marshal(p.Arguments)
		body = strings.NewReader(string(raw))
	}
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		return "request error: " + err.Error(), 0
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "upstream error: " + err.Error(), 0
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	return string(out), resp.StatusCode
}
