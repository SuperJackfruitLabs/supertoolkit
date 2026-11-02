package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/netjail"
)

// The test binary stands in for stk when a test re-executes it as the
// netjail shim or its probe, exactly as `stk mcp serve` re-executes stk.
func TestMain(m *testing.M) {
	if runAsCharacterizedStk() {
		os.Exit(0)
	}
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case netjail.ShimCommand:
			code, err := netjail.Shim(os.Args[2:])
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
			os.Exit(code)
		case netjail.ShimCommand + "-probe":
			if err := netjail.ProbeChild(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}
