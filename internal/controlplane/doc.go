// Package controlplane is what a broker process serves: the daemon's control-socket methods,
// approving and performing an effect, the fronted MCP servers it starts on first use, and the
// daemon side of `stk mcp serve`. Every effect it performs goes through internal/native, so a
// credential meets a request in one place.
package controlplane
