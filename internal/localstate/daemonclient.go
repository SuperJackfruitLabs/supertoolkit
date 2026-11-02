package localstate

import (
	"encoding/json"
	"fmt"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/daemon"
)

// DaemonClient is the narrow view the CLI needs of the control plane.
type DaemonClient interface {
	Call(method string, params json.RawMessage, profile string) (json.RawMessage, error)
	Close() error
}

type RealClient struct{ C *daemon.Client }

func (r RealClient) Call(method string, params json.RawMessage, profile string) (json.RawMessage, error) {
	resp, err := r.C.Call(daemon.Request{Method: method, Params: params, Profile: profile})
	if err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("%s", resp.Error)
	}
	return resp.Result, nil
}

func (r RealClient) Close() error { return r.C.Close() }

func DialDaemon(dir string) (DaemonClient, error) {
	c, err := daemon.Dial(SocketPath(dir))
	if err != nil {
		return nil, err
	}
	return RealClient{C: c}, nil
}
