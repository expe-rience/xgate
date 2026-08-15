# Security updates

A running log of security-relevant changes, so users and reviewers can see what
was addressed and when.

## govulncheck sweep — dependency & toolchain updates

`govulncheck` flagged 25 reachable vulnerabilities. All were in the Go standard
library (via an old toolchain) or in one dependency — none were flaws in xgate's
own code. Addressed by:

- **quic-go: v0.42.0 → v0.49.1.** Fixes two reachable issues:
  - GO-2025-4017 (panic queuing undecryptable packets after handshake)
  - GO-2024-3302 (ICMP Packet-Too-Large injection on Linux)
- **Build toolchain: Go 1.22 → Go 1.24 in CI**, and the module's minimum raised
  to Go 1.23. This pulls in patched standard-library packages, clearing the
  ~23 stdlib findings (crypto/tls, crypto/x509, net/url, net/http, os, encoding/*,
  os/exec, net). These were all "the compiler's stdlib is a few versions behind,"
  fixed by building with a current Go release.

Verified after the update: full build, unit tests, cross-compile to all targets,
and a live QUIC + TCP-fallback handshake/exec regression all pass. No code
changes were required for the quic-go bump (API compatible).

## Design-review hardening (pre-audit)

- Guarded `ed25519.Verify` against wrong-length keys (was a remote-DoS panic
  vector); added `proto.VerifySig` used at all handshake sites.
- Checked `rand.Read` error returns in the handshake.
- Constant-time CA key-id comparison (`crypto/subtle`).
- Validated handshake nonce lengths.

See the disclosure policy in [SECURITY.md](SECURITY.md).

---

**Reminder:** this project remains **unaudited**. These updates remove known
issues but are not a substitute for an independent security review.
