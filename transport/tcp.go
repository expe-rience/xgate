package transport

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/hashicorp/yamux"
)

// ---- TCP + TLS + yamux adapter ----
//
// A raw TCP connection is a single byte pipe. The rest of the tool needs
// several independent streams (stdin, stdout, control), which QUIC provides
// natively. Over TCP we get the same behaviour by running yamux — a small,
// production-proven multiplexer — on top of the TLS connection. yamux hands us
// as many logical streams as we want over the one TCP road.

type tcpConn struct {
	sess *yamux.Session
	raw  net.Conn
}

func (t *tcpConn) OpenStream(ctx context.Context) (Stream, error) {
	// yamux OpenStream doesn't take a context; it's fast (no round trip), so a
	// plain call is fine.
	return t.sess.OpenStream()
}

func (t *tcpConn) AcceptStream(ctx context.Context) (Stream, error) {
	return t.sess.AcceptStream()
}

func (t *tcpConn) RemoteAddr() net.Addr { return t.raw.RemoteAddr() }
func (t *tcpConn) Transport() string    { return "tcp" }
func (t *tcpConn) Close() error         { return t.sess.Close() }

// dialTCP opens TCP, wraps it in TLS 1.3 (same encryption QUIC uses), then in
// yamux for multiplexing. The client is the yamux "client" side.
func dialTCP(ctx context.Context, target string, tlsConf *tls.Config) (Conn, error) {
	d := &net.Dialer{}
	raw, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(raw, tlsConf)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	sess, err := yamux.Client(tlsConn, yamux.DefaultConfig())
	if err != nil {
		tlsConn.Close()
		return nil, err
	}
	return &tcpConn{sess: sess, raw: raw}, nil
}

// serveTCPConn wraps an accepted server-side TLS connection in yamux (server
// side) and returns it as a Conn.
func serveTCPConn(tlsConn net.Conn) (Conn, error) {
	sess, err := yamux.Server(tlsConn, yamux.DefaultConfig())
	if err != nil {
		tlsConn.Close()
		return nil, err
	}
	return &tcpConn{sess: sess, raw: tlsConn}, nil
}
