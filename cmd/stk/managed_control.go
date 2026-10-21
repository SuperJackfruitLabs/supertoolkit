package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/managedmcp"
)

// This separate command accepts private supervisor input only. It never opens
// a credential store, loads ambient config, or runs a native API executor.
func cmdManagedControl(args []string) error { return cmdManagedRead(args, false) }

func cmdManagedEvidence(args []string) error { return cmdManagedRead(args, true) }

func cmdManagedRead(args []string, evidence bool) error {
	ctx, cancelSignal := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancelSignal()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-ctx.Done():
			_ = os.Stdin.Close()
		case <-finished:
		}
	}()
	return runManagedRead(ctx, args, os.Stdin, os.Stdout, evidence)
}
func runManagedControl(ctx context.Context, args []string, in io.Reader, out io.Writer) error {
	return runManagedRead(ctx, args, in, out, false)
}

func runManagedRead(ctx context.Context, args []string, in io.Reader, out io.Writer, evidence bool) error {
	if len(args) != 4 || args[0] != "--manifest" || args[2] != "--sha256" {
		return managedUnavailable()
	}
	a, err := managedmcp.AdmitControl(args[1], args[3])
	if err != nil {
		return managedUnavailable()
	}
	body, err := io.ReadAll(io.LimitReader(in, 4097))
	if err != nil || len(body) > 4096 || ctx.Err() != nil {
		return managedUnavailable()
	}
	c, err := managedmcp.DecodeControl(body)
	if err != nil {
		return managedUnavailable()
	}
	var v any
	if evidence {
		v, err = a.Evidence(ctx, c)
	} else {
		v, err = a.Apply(ctx, c)
	}
	if err != nil {
		return managedUnavailable()
	}
	body, err = json.Marshal(v)
	if err != nil || len(body) > 2*1024*1024 {
		return managedUnavailable()
	}
	if _, err = out.Write(append(body, '\n')); err != nil {
		return managedUnavailable()
	}
	return nil
}
