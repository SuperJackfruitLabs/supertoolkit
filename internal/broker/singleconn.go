package broker

import (
	"io"
	"net"
	"sync"
)

// singleConnListener serves exactly one already-accepted connection through
// http.Server.
//
// The second Accept blocks until that connection closes rather than returning
// immediately. Returning an error straight away makes Serve return while the
// request is still being handled, and the caller's deferred Close then tears
// down the connection mid-response — which presents as an empty reply and looks
// like a client fault.
type singleConnListener struct {
	mu     sync.Mutex
	conn   net.Conn
	served bool
	closed chan struct{}
}

func newSingleConnListener(c net.Conn) *singleConnListener {
	return &singleConnListener{conn: c, closed: make(chan struct{})}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.served {
		l.served = true
		c := &notifyOnCloseConn{Conn: l.conn, closed: l.closed}
		l.mu.Unlock()
		return c, nil
	}
	l.mu.Unlock()
	<-l.closed
	return nil, io.EOF
}

func (l *singleConnListener) Close() error   { return nil }
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

type notifyOnCloseConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *notifyOnCloseConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}
