package main

import (
	"fmt"
	"os"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/catalog"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

// resolveEntry finds the catalogue record for a service name.
//
// A service defined in the policy file (`kind: forge`) wins over the built-ins,
// because its host exists nowhere but in that file. A missing or unreadable
// policy file is not an error for a built-in name: connecting a built-in has
// never needed one.
func resolveEntry(name string) (*catalog.Entry, error) {
	var loadErr error
	if _, err := os.Stat(configPath()); err == nil {
		cfg, err := policy.Load(configPath())
		if err != nil {
			loadErr = err
		} else if svc, ok := cfg.Service(name); ok {
			return svc.Entry(), nil
		}
	}
	if e, ok := catalog.Lookup(name); ok {
		return e, nil
	}
	msg := fmt.Sprintf("unknown service %q: known services are %s; a git forge is defined in the policy file with `kind: forge`", name, knownServices())
	if loadErr != nil {
		return nil, fmt.Errorf("%s\n  (the policy file could not be read: %v)", msg, loadErr)
	}
	return nil, fmt.Errorf("%s", msg)
}
