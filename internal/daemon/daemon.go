// Package daemon exposes the broker's control plane on a Unix socket.
//
// The socket is the trust boundary. It is created 0600 and owned by the user
// running the daemon, so another OS user cannot open it at all — a kernel
// guarantee rather than a check we might forget. Callers are identified by
// their kernel-reported uid, which needs no shared secret and cannot be forged.
//
// **No method here returns a credential.** There is a test that enumerates the
// method table and fails if one is added, because the invariant is easier to
// keep when breaking it breaks the build.
package daemon

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// Request is one control-plane call.
type Request struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
	// Profile is the caller's claimed identity. It carries no authority of its
	// own: the daemon resolves what it means, and a profile can only narrow.
	Profile string `json:"profile,omitempty"`
}

// Response is one answer.
type Response struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// Handler answers control-plane calls. uid is the kernel-reported caller.
type Handler func(uid int, r Request) Response

// Methods is the complete set of control-plane methods, declared here so a test
// can assert that none of them hands back a credential.
var Methods = []string{
	"discover_server_categories",
	"get_category_actions",
	"get_action_details",
	"execute_action",
	"approvals.list",
	"approvals.decide",
	"status",
	// reload re-reads the operator's policy file; it returns only service
	// names and an error string.
	"reload",
}

// Server is the control plane.
type Server struct {
	sock string
	h    Handler
	ln   net.Listener

	allow []int
	peer  func(net.Conn) (int, error)

	mu     sync.Mutex
	closed bool
}

// Listen binds the socket.
//
// A leftover socket from a dead process is replaced rather than treated as a
// failure, because the alternative is a daemon that will not start after a
// crash and an operator who has to know to delete a file.
func Listen(sock string, h Handler) (*Server, error) {
	return ListenWith(sock, h, Options{})
}

// Options tune the control plane.
type Options struct {
	// AllowUIDs, when non-empty, restricts callers to these kernel-reported
	// uids. A connection from any other uid is closed before a request is read.
	// Empty keeps the socket's own 0600 mode as the only gate.
	AllowUIDs []int
	// PeerUID reads the caller's uid. Nil means the kernel's answer; tests
	// inject a fake.
	PeerUID func(net.Conn) (int, error)
	// SocketMode is the socket file's mode; zero means 0600.
	SocketMode os.FileMode
}

// ListenWith is Listen with options.
func ListenWith(sock string, h Handler, opts Options) (*Server, error) {
	if err := os.MkdirAll(filepath.Dir(sock), 0o700); err != nil {
		return nil, err
	}
	if _, err := os.Stat(sock); err == nil {
		if c, derr := net.Dial("unix", sock); derr == nil {
			c.Close()
			return nil, fmt.Errorf("%s: a daemon is already listening", sock)
		}
		if err := os.Remove(sock); err != nil {
			return nil, fmt.Errorf("removing a stale socket at %s: %w", sock, err)
		}
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return nil, err
	}
	// Mode is set after binding, because the umask applies during Listen.
	mode := opts.SocketMode
	if mode == 0 {
		mode = 0o600
	}
	if err := os.Chmod(sock, mode); err != nil {
		ln.Close()
		return nil, fmt.Errorf("securing %s: %w", sock, err)
	}
	peer := opts.PeerUID
	if peer == nil {
		peer = PeerUID
	}
	return &Server{sock: sock, h: h, ln: ln, allow: append([]int(nil), opts.AllowUIDs...), peer: peer}, nil
}

// Addr is the socket path.
func (s *Server) Addr() string { return s.sock }

// Serve answers calls until Close.
func (s *Server) Serve() error {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			return err
		}
		go s.handle(conn)
	}
}

// Close stops the daemon and removes the socket.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	err := s.ln.Close()
	os.Remove(s.sock)
	return err
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	uid, err := s.peer(conn)
	if len(s.allow) > 0 {
		// Fail closed: an unreadable uid is not on the list. The refusal is
		// only a closed connection, so it tells the caller nothing.
		if err != nil || !s.allowed(uid) {
			return
		}
	} else if err != nil {
		uid = -1
	}
	dec := json.NewDecoder(bufio.NewReader(conn))
	enc := json.NewEncoder(conn)
	for {
		var req Request
		if err := dec.Decode(&req); err != nil {
			return
		}
		resp := s.h(uid, req)
		if err := enc.Encode(resp); err != nil {
			return
		}
	}
}

func (s *Server) allowed(uid int) bool {
	for _, a := range s.allow {
		if a == uid {
			return true
		}
	}
	return false
}

// Client is a connection to the daemon.
type Client struct {
	conn net.Conn
	dec  *json.Decoder
	enc  *json.Encoder
	mu   sync.Mutex
}

// Dial connects to a daemon.
func Dial(sock string) (*Client, error) {
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, fmt.Errorf("%s: %w — is `stk serve` running?", sock, err)
	}
	return &Client{conn: conn, dec: json.NewDecoder(bufio.NewReader(conn)), enc: json.NewEncoder(conn)}, nil
}

// Call makes one request.
func (c *Client) Call(req Request) (Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.enc.Encode(req); err != nil {
		return Response{}, err
	}
	var resp Response
	if err := c.dec.Decode(&resp); err != nil {
		return Response{}, err
	}
	return resp, nil
}

// Close ends the connection.
func (c *Client) Close() error { return c.conn.Close() }

// SortedMethods is Methods, sorted, for stable output.
func SortedMethods() []string {
	out := append([]string(nil), Methods...)
	sort.Strings(out)
	return out
}
