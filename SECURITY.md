# Security Policy

## Status: pre-alpha, UNAUDITED

xgate has **not** had a professional security review. It is a remote-access tool,
so an undiscovered flaw could expose the machines it runs on. **Do not use it to
manage real or production systems.** This policy exists so that as people test
and review it, issues can be reported responsibly.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.** Public
issues are visible to everyone before a fix exists, which puts users at risk.

Instead, report privately using **GitHub's private vulnerability reporting**:

1. Go to the **Security** tab of this repository.
2. Click **Report a vulnerability**.
3. Describe the issue, steps to reproduce, and impact.

If private reporting is unavailable, email **YOUR-CONTACT-EMAIL** with the
details. (Replace this with a real address before publishing.)

Please include:
- What the vulnerability is and its impact.
- Steps to reproduce (or a proof of concept).
- The version / commit you tested.
- Which direction you were running (which machine was the daemon vs client).

## What to expect

This is a personal/open-source project, not a company with a security team, so
please set expectations accordingly:

- Acknowledgement of your report as soon as reasonably possible.
- An honest assessment of whether it's a real issue and its severity.
- A fix on a best-effort basis, with credit to you if you'd like it.
- Please allow reasonable time to address an issue before disclosing it
  publicly (responsible disclosure).

## Scope — where review is most valuable

If you're looking for where to focus, these are the highest-value targets:

- **`proto/proto.go`** — the security core. Especially:
  - the ordering in `Certificate.Verify` (nothing derived from claims is
    trusted for policy until after the CA signature check),
  - the signed handshake **`Transcript`** construction (role/version/nonce/
    serial binding, and the length-prefixed serial),
  - the fail-closed `default` in `Capability.Permits`.
- **The handshake** in `cmd/xgated/main.go` and `cmd/xgate/main.go` — confirm the
  client refuses to send its certificate before verifying the host, and that
  requested capabilities are enforced as a subset of the grant.
- **`transport/`** — the QUIC/TCP fallback. The design assumption is that TLS
  carries **no** trust and all identity is the app-layer cert exchange; verify
  nothing depends on TLS peer identity, and that the yamux/TCP path doesn't
  weaken this.
- **`cmd/xgate-gui/`** — the newest, least-reviewed code. The local websocket
  bridge and the loopback-only binding are worth probing.

## Known limitations (already documented, not new findings)

These are known and don't need reporting (see the repo's status notes):

- File capabilities (`read:`/`write:`) use a Unix-shaped path check and are
  unsafe on Windows.
- The `quickstart` enrollment token carries the client private key — a test
  convenience, not a production pattern.
- No rate limiting, no password auth, no real CA tooling yet.

## Cryptography

xgate uses Ed25519 signatures and TLS 1.3 (via QUIC, and via TCP in the fallback)
from the Go standard library. It does **not** implement its own primitives. The
one non-standard construction is the signed handshake transcript in
`proto.Transcript` — that is the first thing to scrutinize.
