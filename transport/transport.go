// Package transport provides a road-agnostic connection abstraction so the
// handshake and session code does not care whether it is running over QUIC
// (fast, UDP) or TCP+TLS+yamux (slower, but works where UDP is blocked).
//
// The security layer and the shell/exec layer only need "a thing I can open
// byte-streams on". Both QUIC and TCP satisfy that, so switching roads is a
// transport concern and nothing above it changes.
package transport

import (
	"context"
	"io"
	"net"
)

// Stream is a bidirectional byte pipe with a deadline for closing writes.
type Stream interface {
	io.ReadWriteCloser
}

// Conn is a multiplexed connection: you can open outbound streams and accept
// inbound ones. Both the QUIC and the TCP+yamux implementations satisfy this.
type Conn interface {
	// OpenStream starts a new outbound stream.
	OpenStream(ctx context.Context) (Stream, error)
	// AcceptStream waits for the peer to open a stream.
	AcceptStream(ctx context.Context) (Stream, error)
	// RemoteAddr is the peer address, for audit logging.
	RemoteAddr() net.Addr
	// Transport names the road actually used ("quic" or "tcp"), for logging.
	Transport() string
	Close() error
}
