package serve

import (
	"strings"
	"testing"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/clitest"
)

func TestServeProxyListenRejectsNonLoopback(t *testing.T) {
	for _, a := range []string{"0.0.0.0:8080", "192.168.1.5:8080", "10.0.0.1:1", "[::]:8080", "example.com:8080", ":8080", "8.8.8.8:53", "127.0.0.1", "127.0.0.1:notaport", "127.0.0.1:0"} {
		if _, err := parseProxyListen(a); err == nil {
			t.Errorf("parseProxyListen(%q) accepted, want an error", a)
		}
	}
	for _, a := range []string{"127.0.0.1:18080", "127.1.2.3:9", "[::1]:18080", "localhost:18080"} {
		if _, err := parseProxyListen(a); err != nil {
			t.Errorf("parseProxyListen(%q) = %v, want accepted", a, err)
		}
	}
	clitest.Rig(t, "workspace: test\nservices:\n  github:\n    scopes: []\n")
	err := Command([]string{"--proxy-listen", "0.0.0.0:8080"}, "test")
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("cmdServe err = %v, want one naming loopback", err)
	}
}
