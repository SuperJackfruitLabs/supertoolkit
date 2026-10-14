// Package notify reaches the person a machine is waiting on.
//
// A device code and an approval are the same shape: something remote needs a
// specific human and will wait. One adapter serves both, so adding a channel
// improves both at once.
//
// What travels here is never a credential. A user code is useless without the
// person approving it; a device code is not, and never reaches this package.
package notify

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Message is something a person needs to see.
type Message struct {
	// Title is one line: what is waiting.
	Title string
	// Body says what to do.
	Body string
	// Code is a user code, safe to show, read aloud or send.
	Code string
	// URL is where the person goes.
	URL string
	// Expires says how long they have.
	Expires time.Time
}

// Sink is one way of reaching someone.
type Sink interface {
	Name() string
	Send(ctx context.Context, m Message) error
}

// Notifier fans a message out to every configured sink.
type Notifier struct{ Sinks []Sink }

// Notify sends to every sink.
//
// A sink that fails does not stop the others: the code reaching the person by
// *any* route is what matters, and the common failure — a webhook that is
// down — should not cost someone the terminal line they were about to read.
func (n *Notifier) Notify(ctx context.Context, m Message) error {
	var (
		mu     sync.Mutex
		failed []string
		wg     sync.WaitGroup
	)
	for _, s := range n.Sinks {
		wg.Add(1)
		go func(s Sink) {
			defer wg.Done()
			if err := s.Send(ctx, m); err != nil {
				mu.Lock()
				failed = append(failed, fmt.Sprintf("%s: %v", s.Name(), err))
				mu.Unlock()
			}
		}(s)
	}
	wg.Wait()
	if len(failed) == len(n.Sinks) && len(n.Sinks) > 0 {
		return fmt.Errorf("no channel reached you: %s", strings.Join(failed, "; "))
	}
	return nil
}

// Terminal writes to a stream, which is the sink that always exists.
type Terminal struct{ W io.Writer }

func (t Terminal) Name() string { return "terminal" }

func (t Terminal) Send(_ context.Context, m Message) error {
	w := t.W
	if w == nil {
		w = os.Stderr
	}
	fmt.Fprintf(w, "\n  %s\n", m.Title)
	if m.Code != "" {
		fmt.Fprintf(w, "  code  %s\n", m.Code)
	}
	if m.URL != "" {
		fmt.Fprintf(w, "  open  %s\n", m.URL)
	}
	if m.Body != "" {
		fmt.Fprintf(w, "  %s\n", m.Body)
	}
	if !m.Expires.IsZero() {
		fmt.Fprintf(w, "  expires in %s\n", time.Until(m.Expires).Round(time.Second))
	}
	fmt.Fprintln(w)
	return nil
}

// Webhook posts the message as JSON, for ntfy or anything else that accepts one.
type Webhook struct {
	URL    string
	Client *http.Client
}

func (h Webhook) Name() string { return "webhook" }

func (h Webhook) Send(ctx context.Context, m Message) error {
	body := fmt.Sprintf(
		`{"title":%q,"message":%q,"code":%q,"url":%q}`,
		m.Title, m.Body, m.Code, m.URL)
	req, err := http.NewRequestWithContext(ctx, "POST", h.URL, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	c := h.Client
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("the endpoint answered %s", resp.Status)
	}
	return nil
}

// File appends to a path, for a machine where someone tails a log.
type File struct{ Path string }

func (f File) Name() string { return "file" }

func (f File) Send(_ context.Context, m Message) error {
	fh, err := os.OpenFile(f.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer fh.Close()
	_, err = fmt.Fprintf(fh, "%s\t%s\tcode=%s\turl=%s\n",
		time.Now().Format(time.RFC3339), m.Title, m.Code, m.URL)
	return err
}
