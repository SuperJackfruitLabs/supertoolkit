package broker

import (
	"os"
	"strings"
)

// Unlock material belongs only to the broker. A fronted server or stk-run command
// must not inherit it, even if a service's extra environment attempts to restore it.
func brokerPrivateEnv(name string) bool {
	return name == "STK_PASSPHRASE" || name == "STK_PASSPHRASE_FILE" || name == "CREDENTIALS_DIRECTORY"
}

// ChildEnv builds the environment a brokered child process runs with, whether
// that child is a command from `stk run` or a fronted MCP server.
//
// One implementation on purpose: these three details came from measuring real
// clients, and a second copy would eventually drift from them.
//
//   - NODE_USE_ENV_PROXY is set, because Node's fetch ignores proxy environment
//     variables by default and would otherwise go straight out and succeed —
//     the silent failure this product exists to prevent.
//   - NO_PROXY is cleared, because it is a confirmed bypass: anything that can
//     set it can opt itself out of the broker.
//   - The CA is announced in four variables, because curl, Go, Python and Node
//     each read a different one.
//
// placeholders maps an environment variable to the worthless stand-in a client
// should find there instead of a credential.
func ChildEnv(base []string, proxyURL, caPath string, placeholders map[string]string, extra map[string]string) []string {
	drop := map[string]bool{
		"NO_PROXY": true, "no_proxy": true, // a confirmed bypass
		"HTTPS_PROXY": true, "https_proxy": true,
		"HTTP_PROXY": true, "http_proxy": true,
	}
	// Anything we are about to set explicitly is dropped first, so a value
	// inherited from the parent cannot win.
	for k := range placeholders {
		drop[k] = true
	}
	for k := range extra {
		drop[k] = true
	}

	out := make([]string, 0, len(base)+12)
	for _, kv := range base {
		name := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			name = kv[:i]
		}
		if drop[name] || brokerPrivateEnv(name) {
			continue
		}
		out = append(out, kv)
	}
	out = append(out,
		"HTTPS_PROXY="+proxyURL,
		"https_proxy="+proxyURL,
		"HTTP_PROXY="+proxyURL,
		"http_proxy="+proxyURL,
		"SSL_CERT_FILE="+caPath,
		"CURL_CA_BUNDLE="+caPath,
		"REQUESTS_CA_BUNDLE="+caPath,
		"NODE_EXTRA_CA_CERTS="+caPath,
		"NODE_USE_ENV_PROXY=1",
		"STK_BROKERED=1",
	)
	for k, v := range extra {
		if brokerPrivateEnv(k) {
			continue
		}
		out = append(out, k+"="+v)
	}
	for k, v := range placeholders {
		if brokerPrivateEnv(k) {
			continue
		}
		out = append(out, k+"="+v)
	}
	return out
}

// OSEnv is the parent environment, as the starting point for ChildEnv.
func OSEnv() []string { return os.Environ() }
