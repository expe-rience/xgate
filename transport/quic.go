package transport

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// ---- QUIC adapter ----

type quicConn struct {
	c quic.Connection
}

func (q *quicConn) OpenStream(ctx context.Context) (Stream, error) {
	return q.c.OpenStreamSync(ctx)
}

func (q *quicConn) AcceptStream(ctx context.Context) (Stream, error) {
	return q.c.AcceptStream(ctx)
}

func (q *quicConn) RemoteAddr() net.Addr { return q.c.RemoteAddr() }
func (q *quicConn) Transport() string    { return "quic" }
func (q *quicConn) Close() error {
	return q.c.CloseWithError(0, "bye")
}

func dialQUIC(ctx context.Context, target string, tlsConf *tls.Config) (Conn, error) {
	c, err := quic.DialAddr(ctx, target, tlsConf, &quic.Config{MaxIdleTimeout: 30 * time.Second})
	if err != nil {
		return nil, err
	}
	return &quicConn{c: c}, nil
}

// listenQUIC starts a QUIC listener that pushes accepted connections into
// `out`. Returns a close function. Runs its own accept goroutine.
func listenQUIC(addr string, tlsConf *tls.Config, out chan<- Conn) (func() error, error) {
	ln, err := quic.ListenAddr(addr, tlsConf, &quic.Config{MaxIdleTimeout: 30 * time.Second})
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			c, err := ln.Accept(context.Background())
			if err != nil {
				return // listener closed
			}
			out <- &quicConn{c: c}
		}
	}()
	return ln.Close, nil
}
