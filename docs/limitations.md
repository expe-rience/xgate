# How xgate limits access — and its current limitations

An honest, single-page account of how xgate restricts access today, and exactly
where it falls short. **xgate is pre-alpha and unaudited.** This page is the
thing to read before trusting it with anything.

## How access is limited (what works today)

xgate replaces "hold a standing credential" with "carry a narrowly-scoped,
short-lived certificate." The mechanisms that enforce this, and that are
implemented and tested:

- **Capability scoping.** A certificate authorizes a specific capability —
  `exec:/exact/path` (one command, no shell, no caller-supplied arguments),
  `shell`, `read:/path`, `write:/path`, or `forward:port`. The daemon checks
  every request against the capability and **denies by default** — anything not
  explicitly granted is refused.
- **Short-lived certificates.** Certs carry `NotBefore`/`NotAfter`. Access
  expires on its own; expiry *is* revocation. There are no long-lived keys to
  rotate or forget.
- **Mutual authentication.** The daemon proves its identity (CA-signed) before
  the client sends anything, so there's no trust-on-first-use and no fingerprint
  to click through. Both sides sign a handshake transcript binding role,
  protocol version, both nonces, and the certificate serial — which resists
  replay and role-confusion.
- **No lateral movement from an exec grant.** An `exec` capability runs one
  program directly — no shell is spawned, so there's no shell to pivot from and
  no command-injection surface.
- **Signed audit trail.** The daemon records what happened; the policy engine
  records every grant and denial.

The result: even a compromised client (or a prompt-injected agent) can do only
what its current capability allows, for the few minutes it's valid.

## What is NOT implemented yet (honest gaps)

These are missing by design at this stage — not bugs, just not built:

- **The policy engine is a proof-of-concept.** `xgate-policy` decides grants
  from a small, hard-coded table. There is **no** real policy language,
  approval workflow, or integration with existing IAM/PAM. The production-grade
  policy → capability broker is the main thing still to build.
- **The enrollment token carries the client key.** `quickstart` and the token
  are test conveniences for easy setup; a real system must never ship a private
  key inside a token. This is fine for testing, unacceptable for production.
- **No real CA service.** `mint` bootstraps a CA for testing only. There's no
  key rotation, no CA hardening, no HSM support.
- **No rate limiting.** The daemon does not throttle connection or handshake
  attempts.
- **No mid-session revocation.** Revocation is by expiry only — you can't yet
  kill an in-flight capability before its TTL ends (an emergency kill-switch is
  on the roadmap).
- **File capabilities are Unix-shaped and unsafe on Windows.** The `read:` /
  `write:` path check assumes Unix path semantics; do not rely on it on Windows.
  (The interactive shell and `exec` are unaffected.)
- **No file transfer, no port forwarding** implemented yet.
- **No MCP server / agent SDK yet.** The AI-agent integration path (an MCP
  server, a Python SDK) is designed but not built — see the roadmap.

## What is built but under-tested

Works in testing, but needs more real-world exercise — treat with caution:

- **macOS and Raspberry Pi** runtime (binaries build; lightly run).
- **Long Windows (ConPTY) sessions**, mid-session resize, full-screen TUI apps.
- **GUI on-screen rendering** — the backend is verified; the browser terminal's
  visual behaviour has had limited testing on a real display.
- **TCP fallback on genuinely UDP-blocked networks** (verified with a forced
  `--transport tcp`; less tested on a network that actually blocks UDP).

## The big one: not audited

xgate has had automated scanning (govulncheck, gosec, CodeQL) and a self-review
pass, but **no independent security audit.** For a remote-access / execution
tool, that means: **do not use it to manage real or production systems.** It is
for learning, testing, and feedback until a real review happens. See
[SECURITY.md](../SECURITY.md).

## In one sentence

xgate already enforces scoped, expiring, audited access at the machine — the
enforcement layer is real; the policy layer is a PoC, the whole thing is
unaudited, and it should be treated as a demonstration of the idea, not a
product to deploy.
