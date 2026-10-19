package broker

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestBrokerChildProbe(t *testing.T) {
	if os.Getenv("STK_CHILD_ENV_PROBE") != "1" {
		return
	}
	for _, name := range []string{"STK_PASSPHRASE", "STK_PASSPHRASE_FILE"} {
		if _, ok := os.LookupEnv(name); ok {
			os.Exit(41)
		}
	}
	os.Exit(0)
}

func TestActualBrokerChildCannotReadUnlockEnvironment(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestBrokerChildProbe$")
	cmd.Env = ChildEnv([]string{"STK_PASSPHRASE=fixture-secret", "STK_PASSPHRASE_FILE=/fixture/private-unlock"}, "http://127.0.0.1:9", "/fixture/ca", nil, map[string]string{"STK_CHILD_ENV_PROBE": "1"})
	if err := cmd.Run(); err != nil {
		t.Fatal("actual broker child retained private unlock material")
	}
}

func envMap(t *testing.T, kvs []string) map[string]string {
	t.Helper()
	m := map[string]string{}
	for _, kv := range kvs {
		k, v, _ := strings.Cut(kv, "=")
		m[k] = v
	}
	return m
}

func TestChildEnvSetsTheProxyAndThePlaceholder(t *testing.T) {
	got := envMap(t, ChildEnv(
		[]string{"PATH=/usr/bin"},
		"http://127.0.0.1:9", "/tmp/ca.pem",
		map[string]string{"GH_TOKEN": Placeholder("github")},
		nil,
	))
	if got["HTTPS_PROXY"] != "http://127.0.0.1:9" {
		t.Errorf("HTTPS_PROXY = %q", got["HTTPS_PROXY"])
	}
	if got["GH_TOKEN"] != "stk:ref:github:v1" {
		t.Errorf("GH_TOKEN = %q, want the placeholder", got["GH_TOKEN"])
	}
	if got["PATH"] != "/usr/bin" {
		t.Error("the inherited PATH was lost")
	}
}

// NODE_USE_ENV_PROXY is not cosmetic: without it Node's fetch ignores the proxy
// entirely and succeeds, which is the silent bypass this product prevents.
func TestChildEnvOptsNodeIntoTheProxy(t *testing.T) {
	got := envMap(t, ChildEnv(nil, "http://p", "/ca", nil, nil))
	if got["NODE_USE_ENV_PROXY"] != "1" {
		t.Fatal("NODE_USE_ENV_PROXY is unset; Node's fetch would bypass the broker silently")
	}
}

// NO_PROXY is a confirmed bypass, so it must not reach the child even when the
// parent has it set.
func TestChildEnvClearsNoProxy(t *testing.T) {
	got := envMap(t, ChildEnv(
		[]string{"NO_PROXY=api.github.com", "no_proxy=api.github.com"},
		"http://p", "/ca", nil, nil,
	))
	if v, ok := got["NO_PROXY"]; ok {
		t.Fatalf("NO_PROXY reached the child as %q; it is a confirmed bypass", v)
	}
	if v, ok := got["no_proxy"]; ok {
		t.Fatalf("no_proxy reached the child as %q", v)
	}
}

// Four variables, because each runtime reads a different one.
func TestChildEnvAnnouncesTheCAForEveryRuntime(t *testing.T) {
	got := envMap(t, ChildEnv(nil, "http://p", "/tmp/ca.pem", nil, nil))
	for _, v := range []string{"SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"} {
		if got[v] != "/tmp/ca.pem" {
			t.Errorf("%s = %q, want the CA path", v, got[v])
		}
	}
}

// A real credential inherited from the parent must not shadow the placeholder.
func TestInheritedValueCannotShadowThePlaceholder(t *testing.T) {
	got := envMap(t, ChildEnv(
		[]string{"GH_TOKEN=ghp_a_real_token_from_the_parent"},
		"http://p", "/ca",
		map[string]string{"GH_TOKEN": Placeholder("github")},
		nil,
	))
	if got["GH_TOKEN"] != "stk:ref:github:v1" {
		t.Fatalf("GH_TOKEN = %q; an inherited real token won over the placeholder", got["GH_TOKEN"])
	}
	// And it must appear exactly once, so a child reading the last occurrence
	// and a child reading the first both see the placeholder.
	n := 0
	for _, kv := range ChildEnv([]string{"GH_TOKEN=real"}, "http://p", "/ca",
		map[string]string{"GH_TOKEN": Placeholder("github")}, nil) {
		if strings.HasPrefix(kv, "GH_TOKEN=") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("GH_TOKEN appears %d times; a child could read either", n)
	}
}

func TestExtraEnvIsPassedThrough(t *testing.T) {
	got := envMap(t, ChildEnv(nil, "http://p", "/ca", nil, map[string]string{"SLACK_TEAM_ID": "T123"}))
	if got["SLACK_TEAM_ID"] != "T123" {
		t.Errorf("extra env was dropped: %v", got["SLACK_TEAM_ID"])
	}
}

func TestBrokerUnlockCredentialsNeverReachAnAgentOrFrontedServer(t *testing.T) {
	for _, key := range []string{"STK_PASSPHRASE", "STK_PASSPHRASE_FILE"} {
		for _, source := range []string{"inherited", "extra", "placeholder"} {
			t.Run(key+"/"+source, func(t *testing.T) {
				var base []string
				var extra, placeholders map[string]string
				switch source {
				case "inherited":
					base = []string{key + "=fixture-unlock-material"}
				case "extra":
					extra = map[string]string{key: "fixture-unlock-material"}
				case "placeholder":
					placeholders = map[string]string{key: "fixture-unlock-material"}
				}
				got := envMap(t, ChildEnv(base, "http://p", "/ca", placeholders, extra))
				if _, ok := got[key]; ok {
					t.Fatal("broker unlock material reached the child environment")
				}
			})
		}
	}
}
