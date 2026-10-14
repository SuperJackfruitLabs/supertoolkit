package main

import (
	"encoding/json"
	"fmt"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/daemon"
)

// daemonClient is the narrow view the CLI needs of the control plane.
type daemonClient interface {
	Call(method string, params json.RawMessage, profile string) (json.RawMessage, error)
	Close() error
}

type realClient struct{ c *daemon.Client }

func (r realClient) Call(method string, params json.RawMessage, profile string) (json.RawMessage, error) {
	resp, err := r.c.Call(daemon.Request{Method: method, Params: params, Profile: profile})
	if err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("%s", resp.Error)
	}
	return resp.Result, nil
}

func (r realClient) Close() error { return r.c.Close() }

func dialDaemon(dir string) (daemonClient, error) {
	c, err := daemon.Dial(socketPath(dir))
	if err != nil {
		return nil, err
	}
	return realClient{c: c}, nil
}
