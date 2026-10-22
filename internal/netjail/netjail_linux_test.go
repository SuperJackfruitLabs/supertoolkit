//go:build linux

package netjail

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// The test binary plays three parts: the test, the shim (ShimCommand), and the
// confined child (STK_NETJAIL_CHILD), which reports what it could reach.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == ShimCommand {
		code, err := Shim(os.Args[2:])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(code)
	}
	if len(os.Args) > 1 && os.Args[1] == ShimCommand+"-probe" {
		if err := ProbeChild(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if target := os.Getenv("STK_WATCH_CHILD"); target != "" {
		// Hold one connection open long enough to be seen, then exit.
		if c, err := net.Dial("tcp", target); err == nil {
			time.Sleep(time.Second)
			c.Close()
		}
		os.Exit(0)
	}
	if os.Getenv("STK_NETJAIL_CHILD") != "" {
		child()
		return
	}
	os.Exit(m.Run())
}

// child tries the direct targets, then the proxy port, and prints a verdict.
func child() {
	out := map[string]string{}
	for _, target := range strings.Split(os.Getenv("STK_NETJAIL_DIRECT"), ",") {
		c, err := net.DialTimeout("tcp", target, 2*time.Second)
		if err != nil {
			out[target] = "refused: " + err.Error()
			continue
		}
		c.Close()
		out[target] = "connected"
	}
	c, err := net.DialTimeout("tcp", os.Getenv("STK_NETJAIL_PROXY"), 2*time.Second)
	if err != nil {
		out["proxy"] = "refused: " + err.Error()
	} else {
		fmt.Fprintln(c, "hello")
		line, _ := bufio.NewReader(c).ReadString('\n')
		out["proxy"] = strings.TrimSpace(line)
		c.Close()
	}
	json.NewEncoder(os.Stdout).Encode(out)
	os.Exit(0)
}

func hostAddrs(t *testing.T) []string {
	// Every non-loopback IPv4 address of the host: a confined child must reach
	// none of them, and an unconfined one reaches all.
	var out []string
	ifs, _ := net.InterfaceAddrs()
	for _, a := range ifs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLoopback() {
			out = append(out, ipn.IP.String())
		}
	}
	if len(out) == 0 {
		t.Skip("no non-loopback address to test against")
	}
	return out
}

func TestConfinedChildReachesOnlyTheBroker(t *testing.T) {
	self, _ := os.Executable()
	if err := Probe(self); err != nil {
		if os.Getenv("STK_REQUIRE_USERNS") != "" {
			t.Fatalf("namespaces unavailable but required: %v", err)
		}
		t.Skipf("namespaces unavailable here: %v", err)
	}
	// A listener on every host address: what a direct connection would reach.
	target, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	_, port, _ := net.SplitHostPort(target.Addr().String())
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	var direct []string
	for _, a := range hostAddrs(t) {
		direct = append(direct, net.JoinHostPort(a, port))
	}
	direct = append(direct, "1.1.1.1:443")

	// The stand-in broker: echoes "broker:<line>".
	broker, _ := net.Listen("tcp", "127.0.0.1:0")
	defer broker.Close()
	go func() {
		for {
			c, err := broker.Accept()
			if err != nil {
				return
			}
			go func() {
				line, _ := bufio.NewReader(c).ReadString('\n')
				io.WriteString(c, "broker:"+line)
				c.Close()
			}()
		}
	}()

	j, err := Open(broker.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	cmd := j.Command(self, 18899, self)
	cmd.Env = append(os.Environ(), "STK_NETJAIL_CHILD=1",
		"STK_NETJAIL_DIRECT="+strings.Join(direct, ","), "STK_NETJAIL_PROXY=127.0.0.1:18899")
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("confined child failed: %v %s", err, raw)
	}
	var got map[string]string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("child output %q: %v", raw, err)
	}
	if got["proxy"] != "broker:hello" {
		t.Errorf("the relay to the broker did not work: %q", got["proxy"])
	}
	for _, d := range direct {
		if !strings.HasPrefix(got[d], "refused") {
			t.Errorf("confined child reached %s directly: %s", d, got[d])
		}
	}
}
