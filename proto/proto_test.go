package proto

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func newCA(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func clientClaims(now, ttl int64) Claims {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	return Claims{
		Version: CertVersion, Role: RoleClient, Serial: "test-0001",
		Principal: "alice", PublicKey: pub,
		NotBefore: now, NotAfter: now + ttl,
		Capabilities: []Capability{Shell()},
	}
}

func TestRoundTripVerifies(t *testing.T) {
	caPub, caPriv := newCA(t)
	cert, err := Sign(clientClaims(1000, 600), caPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.Verify(caPub, 1200, 30, RoleClient); err != nil {
		t.Fatalf("valid cert rejected: %v", err)
	}
}

func TestRejectsExpired(t *testing.T) {
	caPub, caPriv := newCA(t)
	cert, _ := Sign(clientClaims(1000, 600), caPriv)
	if err := cert.Verify(caPub, 5000, 30, RoleClient); err != ErrExpired {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}

func TestRejectsWrongCA(t *testing.T) {
	_, caPriv := newCA(t)
	otherPub, _ := newCA(t)
	cert, _ := Sign(clientClaims(1000, 600), caPriv)
	if err := cert.Verify(otherPub, 1200, 30, RoleClient); err != ErrUnknownIssuer {
		t.Fatalf("expected ErrUnknownIssuer, got %v", err)
	}
}

func TestRejectsTamperedPrincipal(t *testing.T) {
	caPub, caPriv := newCA(t)
	cert, _ := Sign(clientClaims(1000, 600), caPriv)
	cert.Claims.Principal = "root" // escalate after signing
	if err := cert.Verify(caPub, 1200, 30, RoleClient); err != ErrBadSignature {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

func TestRejectsRoleConfusion(t *testing.T) {
	caPub, caPriv := newCA(t)
	cert, _ := Sign(clientClaims(1000, 600), caPriv)
	if err := cert.Verify(caPub, 1200, 30, RoleHost); err != ErrRoleMismatch {
		t.Fatalf("expected ErrRoleMismatch, got %v", err)
	}
}

func TestRejectsOverlongTTL(t *testing.T) {
	caPub, caPriv := newCA(t)
	cert, _ := Sign(clientClaims(1000, MaxTTLSeconds+1), caPriv)
	if err := cert.Verify(caPub, 1200, 30, RoleClient); err != ErrTTLTooLong {
		t.Fatalf("expected ErrTTLTooLong, got %v", err)
	}
}

func TestEmptyGrantDenies(t *testing.T) {
	if Authorize(nil, Shell()) {
		t.Fatal("empty grant must deny")
	}
}

func TestExecIsPerCommand(t *testing.T) {
	granted := []Capability{Exec("/usr/bin/uptime"), Exec("/usr/bin/whoami")}
	if !Authorize(granted, Exec("/usr/bin/uptime")) {
		t.Fatal("granted command should be allowed")
	}
	if Authorize(granted, Exec("/bin/sh")) {
		t.Fatal("ungranted command must be denied")
	}
	if Authorize(granted, Shell()) {
		t.Fatal("exec grant must not imply shell")
	}
}

func TestPathPrefixBoundaryAware(t *testing.T) {
	granted := []Capability{FileRead("/srv/data")}
	if !Authorize(granted, FileRead("/srv/data/a.txt")) {
		t.Fatal("file under grant should be allowed")
	}
	if Authorize(granted, FileRead("/srv/database/a.txt")) {
		t.Fatal("sibling directory must not be covered (prefix escape)")
	}
}

func TestTranscriptBindsRole(t *testing.T) {
	nc, ns := []byte("cccccccccccccccccccccccccccccccc"), []byte("ssssssssssssssssssssssssssssssss")
	h := Transcript("host", 1, nc, ns, "s1")
	c := Transcript("client", 1, nc, ns, "s1")
	if string(h) == string(c) {
		t.Fatal("host and client transcripts must differ (reflection defense)")
	}
}

func TestTranscriptSerialLengthPrefixed(t *testing.T) {
	z := make([]byte, 32)
	a := Transcript("client", 1, z, z, "ab")
	b := Transcript("client", 1, z, z, "a")
	if string(a) == string(b) {
		t.Fatal("serials of different length must not collide")
	}
}

func TestVerifyRejectsMalformedKeySizes(t *testing.T) {
	// A wrong-length public key must NOT panic ed25519.Verify — it must be
	// rejected cleanly. This is the remote-DoS guard.
	caPub, caPriv := newCA(t)
	cert, _ := Sign(clientClaims(1000, 600), caPriv)

	// tamper: give the cert a too-short embedded public key and re-check that
	// Verify returns an error rather than panicking.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Verify panicked on malformed key: %v", r)
		}
	}()
	// truncated trusted CA key
	if err := cert.Verify(caPub[:10], 1200, 30, RoleClient); err == nil {
		t.Fatal("expected rejection of truncated CA key")
	}
}

func TestVerifySigRejectsBadSizes(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	msg := []byte("hello")
	sig := ed25519.Sign(priv, msg)
	if !VerifySig(pub, msg, sig) {
		t.Fatal("valid sig should verify")
	}
	if VerifySig(pub[:5], msg, sig) {
		t.Fatal("short key must be rejected, not panic")
	}
	if VerifySig(pub, msg, sig[:10]) {
		t.Fatal("short sig must be rejected")
	}
}
