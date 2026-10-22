// Command fetchserver stands in for a fetch-style MCP server such as the
// reference mcp-server-fetch: it fetches whatever URL it is given, follows
// redirects, and honours the proxy environment like any ordinary client. It
// also has a tool that ignores the proxy and connects directly, which is what a
// misbehaving server would do.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	dec := json.NewDecoder(bufio.NewReader(os.Stdin))
	enc := json.NewEncoder(os.Stdout)
	text := func(id json.RawMessage, s string, isErr bool) {
		enc.Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{
			"content": []any{map[string]any{"type": "text", "text": s}}, "isError": isErr}})
	}
	client := &http.Client{Timeout: 10 * time.Second} // DefaultTransport: ProxyFromEnvironment
	for {
		var r struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := dec.Decode(&r); err != nil {
			return
		}
		switch r.Method {
		case "initialize":
			enc.Encode(map[string]any{"jsonrpc": "2.0", "id": r.ID, "result": map[string]any{
				"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}},
				"serverInfo": map[string]any{"name": "fetchserver", "version": "1"}}})
		case "tools/list":
			enc.Encode(map[string]any{"jsonrpc": "2.0", "id": r.ID, "result": map[string]any{"tools": []any{
				map[string]any{"name": "fetch", "description": "Fetch a URL", "inputSchema": map[string]any{"type": "object"}},
				map[string]any{"name": "direct", "description": "Connect around the proxy", "inputSchema": map[string]any{"type": "object"}},
			}}})
		case "tools/call":
			var p struct {
				Name      string            `json:"name"`
				Arguments map[string]string `json:"arguments"`
			}
			json.Unmarshal(r.Params, &p)
			switch p.Name {
			case "fetch":
				resp, err := client.Get(p.Arguments["url"])
				if err != nil {
					text(r.ID, "error: "+err.Error(), true)
					continue
				}
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
				resp.Body.Close()
				text(r.ID, fmt.Sprintf("%d %s", resp.StatusCode, body), resp.StatusCode >= 400)
			case "direct":
				c, err := net.DialTimeout("tcp", p.Arguments["addr"], 2*time.Second)
				if err != nil {
					text(r.ID, "direct: "+err.Error(), true)
					continue
				}
				time.Sleep(time.Second)
				c.Close()
				text(r.ID, "direct: connected", false)
			}
		}
	}
}
