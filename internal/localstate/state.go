package localstate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/catalog"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

func KnownServices() string {
	n := catalog.Names()
	sort.Strings(n)
	return strings.Join(n, ", ")
}

// LoadForRun opens everything the broker needs.
func LoadForRun() (*policy.Config, *credential.Store, string, error) {
	cfg, err := policy.Load(ConfigPath())
	if err != nil {
		return nil, nil, "", fmt.Errorf("%w — run `stk init` first", err)
	}
	dir, err := Home()
	if err != nil {
		return nil, nil, "", err
	}
	pass, _, err := credential.StoreKey(dir)
	if err != nil {
		return nil, nil, "", err
	}
	store, err := credential.OpenStore(dir, pass)
	if err != nil {
		return nil, nil, "", err
	}
	return cfg, store, dir, nil
}
