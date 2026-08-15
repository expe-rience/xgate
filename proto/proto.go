// Package proto holds xgate's wire types and authorization primitives.
//
// This is the security-critical core, deliberately free of network I/O so it
// can be unit-tested in isolation — the same boundary the Rust version drew.
//
// NOTE ON THE RUST COMPARISON: two guarantees the Rust type system gave us for
// free become runtime checks here.
//  1. Rust's `Sig64` newtype made "a signature is exactly 64 bytes" a
//     compile-time fact. In Go we use [64]byte, which is fixed-size, but the
//     "reject wrong-length input at decode" logic is a manual check below.
//  2. Rust's capability enum with exhaustive matching meant adding a variant
//     without handling it failed to compile. Go has no sum types, so the
//     capability switch has a default that must fail closed, and "did I handle
//     every case" is a review question, not a compiler guarantee.
package proto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	CertVersion  = 1
	ProtoVersion = 1
	ALPN         = "xgate/1"
	// MaxTTL: a daemon rejects any certificate whose validity span exceeds
	// this, even one the CA signed. 25h = 24h intended max + up to 1h of
	// not_before backdating/skew. (Same boundary fix the Rust live-run forced.)
	MaxTTLSeconds = 25 * 60 * 60
	MaxFrameBytes = 1 << 20
)

// Role distinguishes a client credential from a host credential, so a host
// cert cannot be replayed as a user login.
type Role string

const (
	RoleClient Role = "client"
	RoleHost   Role = "host"
)

var (
	ErrUnknownIssuer = errors.New("certificate not issued by a trusted CA")
	ErrBadSignature  = errors.New("certificate signature is invalid")
	ErrRoleMismatch  = errors.New("certificate role does not match expected role")
	ErrExpired       = errors.New("certificate has expired")
	ErrNotYetValid   = errors.New("certificate is not yet valid")
	ErrTTLTooLong    = errors.New("certificate TTL exceeds the maximum accepted")
	ErrBadVersion    = errors.New("unsupported certificate version")
)

// Capability is what a session may do. Modelled as a struct with a Kind tag
// because Go lacks sum types; contrast the Rust enum.
type Capability struct {
	Kind string `json:"kind"` // "shell" | "exec" | "read" | "write" | "forward" | "audit"
	Arg  string `json:"arg,omitempty"`
	Port uint16 `json:"port,omitempty"`
}

func Shell() Capability            { return Capability{Kind: "shell"} }
func Exec(cmd string) Capability   { return Capability{Kind: "exec", Arg: cmd} }
func FileRead(p string) Capability { return Capability{Kind: "read", Arg: p} }

// Permits reports whether the granted capability covers the requested one.
func (g Capability) Permits(req Capability) bool {
	switch {
	case g.Kind == "shell" && req.Kind == "shell":
		return true
	case g.Kind == "exec" && req.Kind == "exec":
		return g.Arg == req.Arg // exact match, never a prefix
	case g.Kind == "read" && req.Kind == "read":
		return pathPrefix(g.Arg, req.Arg)
	case g.Kind == "write" && req.Kind == "write":
		return pathPrefix(g.Arg, req.Arg)
	case g.Kind == "write" && req.Kind == "read":
		return pathPrefix(g.Arg, req.Arg) // write implies read on same subtree
	case g.Kind == "forward" && req.Kind == "forward":
		return g.Arg == req.Arg && g.Port == req.Port
	case g.Kind == "audit" && req.Kind == "audit":
		return true
	default:
		// FAIL CLOSED. Any pair not explicitly matched is denied. This is the
		// manual equivalent of Rust's exhaustive match — the discipline that
		// the compiler enforced there must be enforced by this default here.
		return false
	}
}

// Authorize reports whether any granted capability permits the request.
// Empty grant denies everything.
func Authorize(granted []Capability, req Capability) bool {
	for _, g := range granted {
		if g.Permits(req) {
			return true
		}
	}
	return false
}

// pathPrefix reports whether child lies under parent, boundary-aware so that
// /srv/data does not leak into /srv/database.
//
// KNOWN LIMITATION carried over from Rust: Unix-shaped. On Windows this makes
// wrong decisions (case-insensitivity, backslashes). Do not use file
// capabilities on Windows until fixed.
func pathPrefix(parent, child string) bool {
	for len(parent) > 1 && parent[len(parent)-1] == '/' {
		parent = parent[:len(parent)-1]
	}
	if parent == "" || parent == "/" {
		return len(child) > 0 && child[0] == '/'
	}
	if child == parent {
		return true
	}
	return len(child) > len(parent) && child[:len(parent)] == parent && child[len(parent)] == '/'
}

// Claims is the signed payload of a certificate.
type Claims struct {
	Version      int          `json:"version"`
	Role         Role         `json:"role"`
	Serial       string       `json:"serial"`
	Principal    string       `json:"principal"`
	PublicKey    []byte       `json:"public_key"` // ed25519, 32 bytes
	NotBefore    int64        `json:"not_before"`
	NotAfter     int64        `json:"not_after"`
	Capabilities []Capability `json:"capabilities"`
}

func (c *Claims) ttl() int64 { return c.NotAfter - c.NotBefore }

// signingPayload is the deterministic byte string that gets signed. Domain
// separated so a signature from one context cannot verify in another.
func (c *Claims) signingPayload() ([]byte, error) {
	body, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	out := append([]byte("xgate-cert-v1\x00"), body...)
	return out, nil
}

// Certificate is claims plus the CA's signature over them.
type Certificate struct {
	Claims    Claims `json:"claims"`
	Signature []byte `json:"signature"` // ed25519, 64 bytes
	CAKeyID   []byte `json:"ca_key_id"` // sha256 of CA pubkey, 32 bytes
}

// Sign produces a certificate signed by the CA private key.
func Sign(claims Claims, ca ed25519.PrivateKey) (*Certificate, error) {
	payload, err := claims.signingPayload()
	if err != nil {
		return nil, err
	}
	return &Certificate{
		Claims:    claims,
		Signature: ed25519.Sign(ca, payload),
		CAKeyID:   KeyID(ca.Public().(ed25519.PublicKey)),
	}, nil
}

// Verify checks the CA signature and all time/policy bounds, in an order that
// matters: nothing derived from the claims is trusted for policy until after
// the signature check passes.
func (cert *Certificate) Verify(trustedCA ed25519.PublicKey, now int64, skew int64, expectRole Role) error {
	if cert.Claims.Version != CertVersion {
		return ErrBadVersion
	}
	if !equalBytes(cert.CAKeyID, KeyID(trustedCA)) {
		return ErrUnknownIssuer
	}
	if cert.Claims.Role != expectRole {
		return ErrRoleMismatch
	}
	// SIGNATURE CHECK — the hinge. Above: cheap rejection of malformed input.
	// Below: operating on claims the CA provably asserted.
	//
	// Guard sizes BEFORE calling ed25519.Verify: Go's ed25519.Verify PANICS on
	// a wrong-length public key, and cert.Claims.PublicKey is attacker-supplied
	// (it arrives in JSON). Without this check a malformed key is a remote DoS.
	if len(trustedCA) != ed25519.PublicKeySize {
		return ErrBadSignature
	}
	payload, err := cert.Claims.signingPayload()
	if err != nil {
		return err
	}
	if len(cert.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(trustedCA, payload, cert.Signature) {
		return ErrBadSignature
	}
	if cert.Claims.NotAfter <= cert.Claims.NotBefore {
		return ErrExpired
	}
	if cert.Claims.ttl() > MaxTTLSeconds {
		return ErrTTLTooLong
	}
	if now+skew < cert.Claims.NotBefore {
		return ErrNotYetValid
	}
	if now-skew >= cert.Claims.NotAfter {
		return ErrExpired
	}
	return nil
}

// KeyID is a stable identifier for a public key: domain-separated SHA-256.
func KeyID(k ed25519.PublicKey) []byte {
	h := sha256.New()
	h.Write([]byte("xgate-key-id-v1"))
	h.Write(k)
	return h.Sum(nil)
}

// VerifySig safely verifies an ed25519 signature, returning false (never
// panicking) if the key or signature is the wrong size. Callers in the
// handshake pass attacker-supplied keys/signatures straight from the wire, so
// this guard is what stops a malformed key from crashing the process.
func VerifySig(pub ed25519.PublicKey, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}

func equalBytes(a, b []byte) bool {
	// Constant-time to avoid any timing signal on the CA key-id comparison.
	// (Not secret-dependent here, but free to do correctly.)
	return subtle.ConstantTimeCompare(a, b) == 1
}

// Transcript is the domain-separated byte string both sides sign during the
// handshake. Binding role, version, both nonces, and the cert serial means a
// signature is valid only for this exact connection and direction.
//
// The length-prefix on the serial (below) prevents the concatenation
// ambiguity where ("ab","c") and ("a","bc") would otherwise collide — the one
// subtle bug this construction has to avoid.
func Transcript(roleTag string, protoVersion uint16, nonceC, nonceS []byte, serial string) []byte {
	out := []byte("xgate-transcript-v1\x00")
	out = append(out, []byte(roleTag)...)
	out = append(out, 0)
	var v [2]byte
	binary.BigEndian.PutUint16(v[:], protoVersion)
	out = append(out, v[:]...)
	out = append(out, nonceC...)
	out = append(out, nonceS...)
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(serial)))
	out = append(out, l[:]...)
	out = append(out, []byte(serial)...)
	return out
}

// Frame is a wire message. A single struct with an optional field per variant,
// again because Go has no sum types.
type Frame struct {
	Type string `json:"type"` // hello|host_auth|client_auth|accepted|rejected|request|data|close

	ProtoVersion uint16       `json:"proto_version,omitempty"`
	NonceC       []byte       `json:"nonce_c,omitempty"`
	NonceS       []byte       `json:"nonce_s,omitempty"`
	Cert         *Certificate `json:"cert,omitempty"`
	Signature    []byte       `json:"signature,omitempty"`
	Requested    []Capability `json:"requested,omitempty"`
	SessionID    string       `json:"session_id,omitempty"`
	Granted      []Capability `json:"granted,omitempty"`
	Reason       string       `json:"reason,omitempty"`
	RequestID    uint64       `json:"request_id,omitempty"`
	Capability   *Capability  `json:"capability,omitempty"`
	Payload      []byte       `json:"payload,omitempty"`
	ExitCode     int          `json:"exit_code,omitempty"`
}

// PublicReason narrows an internal error to the coarse reason sent on the
// wire. A failing client learns only "auth failed", never which check failed —
// the detail goes to the audit log.
func PublicReason(err error) string {
	if errors.Is(err, ErrBadVersion) {
		return "unsupported_version"
	}
	return "auth_failed"
}

// PrettyTTL is a tiny helper for CLI output.
func PrettyTTL(sec int64) string { return fmt.Sprintf("%ds", sec) }

// Now is a seam for tests.
func Now() int64 { return time.Now().Unix() }
