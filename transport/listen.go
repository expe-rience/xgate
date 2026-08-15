package transport

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

// Dial connects to target, preferring QUIC and falling back to TCP+TLS.
//
// QUIC is given a short window. If the network blocks UDP the QUIC dial fails
// fast (or we cut it off at the deadline) and we take the always-open TCP road.
// The caller gets back a Conn and does not learn — or need to learn — which
// road won, except via Conn.Transport() for logging.
func Dial(ctx context.Context, target string, tlsConf *tls.Config) (Conn, error) {
	quicCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	if c, err := dialQUIC(quicCtx, target, tlsConf); err == nil {
		return c, nil
	}
	// QUIC unavailable (UDP blocked, or handshake failed) — fall back.
	return dialTCP(ctx, target, tlsConf)
}

// DialTransport forces a specific road. Useful for testing the fallback path
// deterministically ("tcp") without needing a network that actually blocks
// UDP. An empty string or "auto" behaves like Dial.
func DialTransport(ctx context.Context, target string, tlsConf *tls.Config, road string) (Conn, error) {
	switch road {
	case "quic":
		return dialQUIC(ctx, target, tlsConf)
	case "tcp":
		return dialTCP(ctx, target, tlsConf)
	default:
		return Dial(ctx, target, tlsConf)
	}
}

// Listener runs both a QUIC (UDP) listener and a TCP listener on the same
// address and merges their accepted connections into one channel. The daemon's
// accept loop reads Conns from Accept and handles them identically regardless
// of road.
type Listener struct {
	conns  chan Conn
	errs   chan error
	closeQ func() error
	closeT func() error
}

// Listen binds both roads on addr. QUIC uses UDP, TCP uses TCP, same port.
func Listen(addr string, tlsConf *tls.Config) (*Listener, error) {
	l := &Listener{conns: make(chan Conn, 16), errs: make(chan error, 4)}

	// QUIC (UDP) listener.
	ql, err := listenQUIC(addr, tlsConf, l.conns)
	if err != nil {
		return nil, err
	}
	l.closeQ = ql

	// TCP listener on the same address.
	tl, err := net.Listen("tcp", addr)
	if err != nil {
		ql()
		return nil, err
	}
	l.closeT = tl.Close
	go l.acceptTCP(tl, tlsConf)

	return l, nil
}

func (l *Listener) acceptTCP(tl net.Listener, tlsConf *tls.Config) {
	for {
		raw, err := tl.Accept()
		if err != nil {
			return // listener closed
		}
		go func() {
			tlsConn := tls.Server(raw, tlsConf)
			if err := tlsConn.Handshake(); err != nil {
				raw.Close()
				return
			}
			c, err := serveTCPConn(tlsConn)
			if err != nil {
				return
			}
			l.conns <- c
		}()
	}
}

// Accept returns the next incoming connection from either road.
func (l *Listener) Accept(ctx context.Context) (Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (l *Listener) Close() error {
	if l.closeQ != nil {
		l.closeQ()
	}
	if l.closeT != nil {
		l.closeT()
	}
	return nil
}
