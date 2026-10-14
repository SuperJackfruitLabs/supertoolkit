package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/catalog"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/webui"
)

// cmdUI serves the five screens to whoever is running it.
//
// Its own listener, bound to loopback unless the operator says otherwise, with
// a one-time token in the URL. It is started on demand, so the default attack
// surface of a broker is unchanged by this command existing.
func cmdUI(args []string) error {
	bind := "127.0.0.1:7420"
	allowRemote := false
	open := true
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--bind", "-b":
			if i+1 >= len(args) {
				return fmt.Errorf("--bind needs an address")
			}
			bind = args[i+1]
			allowRemote = true // naming an address is saying you mean it
			i++
		case "--no-open":
			open = false
		}
	}

	cfg, store, dir, err := loadForRun()
	if err != nil {
		return err
	}
	svc, err := newService(cfg, store, dir, "ui")
	if err != nil {
		return err
	}
	defer svc.closeHosts()

	token, err := webui.NewToken()
	if err != nil {
		return err
	}
	api := webui.API(webui.Deps{
		Config: cfg, Store: store, Queue: svc.queue,
		Status: func() []webui.Check { return uiChecks(cfg, store, dir) },
		Audit:  auditForUI(dir),
		SetPolicy: func(category, action string, a policy.Action) error {
			return setPolicyInFile(configPath(), category, action, a)
		},
		// Approving here performs the effect here, in this process, which is
		// the whole point: the agent that asked may be long gone.
		Decide: svc.decideAndPerform,
	})
	assets, haveAssets := webui.Assets()
	var assetHandler http.Handler
	if haveAssets {
		assetHandler = assets
	}
	h, err := webui.Handler(webui.Options{Token: token, API: api, Assets: assetHandler})
	if err != nil {
		return err
	}
	ln, err := webui.Listen(bind, allowRemote)
	if err != nil {
		return err
	}
	defer ln.Close()

	url := webui.URL(ln.Addr().String(), token)
	fmt.Printf("  supertoolkit is at %s\n", url)
	fmt.Printf("  the link carries a one-time token; the browser keeps a cookie after that\n")
	if !haveAssets {
		fmt.Printf("  note: this binary has no web assets — build them with `pnpm -C web build`\n")
	}
	fmt.Println("  ctrl-C to stop")
	if open {
		openBrowser(url)
	}

	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errc:
		return err
	case <-sig:
		fmt.Println("\n  stopped")
		return nil
	}
}

// uiChecks are the doctor checks, in the shape the status screen shows.
func uiChecks(cfg *policy.Config, store *credential.Store, dir string) []webui.Check {
	out := []webui.Check{}
	for _, c := range doctorChecks() {
		state := "bad"
		if c.ok {
			state = "ok"
		} else if c.warn {
			state = "warn"
		}
		out = append(out, webui.Check{Label: c.label, State: state, Detail: c.note})
	}
	return out
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	// A browser that will not open is not worth failing the command over; the
	// URL is already printed.
	_ = cmd.Start()
}

var _ = catalog.AuthToken
