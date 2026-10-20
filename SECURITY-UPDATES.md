# Security updates

A running log of security-relevant changes, so users and reviewers can see what
was addressed and when.

## Policy-as-config and a tamper-evident audit log

**Previously:** grants were decided by a hard-coded Go map inside
`xgate-policy`, and both audit logs were plain append-only JSONL that anyone
with file access could silently edit.

**Now:**

- **Policy file.** `xgate-policy issue --policy policy.json …` (or
  `$XGATE_POLICY`) loads rules from JSON — see `policy.example.json`. Default-deny;
  explicit deny beats allow; per-agent TTL (max 1h); boundary-aware `/*` path
  rules; `..` and non-clean paths refused; `restart`/`deploy` resources must be
  plain service names so they can never splice a path into the exec target.
  Unknown JSON fields, bare `*`, mid-string wildcards and unknown actions are
  rejected at load, so a typo can't silently weaken or empty a policy. A broken
  policy file is a hard error, never a silent fall-back. With no file, the
  built-in demo policy is used, so existing scripts keep working.
  `xgate-policy check` validates a file; `xgate-policy explain` dry-runs a decision.
- **Hash-chained, signed audit.** New stdlib-only package `auditchain`. Each
  record carries `seq`, `prev`, `hash` and an Ed25519 `sig`. Policy decisions
  are signed with the CA key, daemon events with the host key. `verify-audit`
  (on both binaries) pinpoints the first edited/deleted/reordered record. The
  daemon and policy engine refuse to append to a log that fails verification,
  and the policy engine writes its record *before* issuing a credential (no log,
  no credential). A pre-existing unchained log is moved aside to
  `<file>.legacy-<unix>`, not overwritten.
- **Serial uniqueness fix.** Certificate serials now include a random suffix, so
  two grants to the same agent within one second can no longer collide with the
  replay guard.

Verified: 25+ new unit tests (policy rules, traversal/injection, edit/delete/
reorder/forged-chain detection, concurrent appends, restart resume) and a live
run: legit grant executed; replay rejected; injected write/delete/traversal
denied with no credential issued; a flipped decision and a deleted record both
detected; daemon refused to start on the tampered log.

Residual limits are in `docs/limitations.md` (tail truncation and key-holder
forgery are not detectable by the chain alone).

## Real single-use enforcement for capability certificates

**Previously:** a granted certificate's "single-use" property was advisory
only — logged as intent, not enforced. Direct testing confirmed the exact
same certificate could authenticate more than once within its TTL.

**Now:** `xgated` tracks certificate serials that have already authenticated
(a `replayGuard`, added in `cmd/xgated/replay.go`) and rejects any repeat
presentation of an already-used serial with `replay_denied` — independent of
whether the certificate has expired. This is persisted to disk (next to the
audit log by default) so it survives a daemon restart, and existing
`xgated.json` configs need no changes to pick it up.

Verified: 5 new unit tests (including a simulated daemon restart) plus a live
end-to-end regression — a certificate used once, then presented again,
correctly rejected; a fresh grant issued afterward still works; the rejection
survives an actual process restart, not just an in-memory check. Full existing
test suite (20 tests total) still passes; cross-compiles clean to all targets.

See `docs/limitations.md` for the residual caveat (persistence is best-effort,
not transactional) and the design note in `cmd/xgated/replay.go` for why this
logic lives in the daemon rather than the I/O-free `proto/` package.

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
