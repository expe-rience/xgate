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
- **Real single-use enforcement.** Each certificate carries a unique serial
  assigned at issuance. The daemon tracks which serials have already
  authenticated and rejects a repeat — even well within the certificate's
  TTL — and this is persisted to disk, so it survives a daemon restart. A
  captured or replayed certificate is good for exactly one session, not one
  TTL window.
- **Tamper-evident audit trail.** The daemon and the policy engine each write a
  hash-chained, Ed25519-signed log (every record carries its sequence number,
  the previous record's hash, its own hash, and a signature). Editing or
  deleting a record is detected by `xgated verify-audit` /
  `xgate-policy verify-audit`, and a daemon refuses to start on a log that
  fails verification. The policy engine writes its audit record *before*
  issuing anything — if it can't log, it issues nothing.

The result: even a compromised client (or a prompt-injected agent) can do only
what its current capability allows, for the few minutes it's valid.

## What is NOT implemented yet (honest gaps)

These are missing by design at this stage — not bugs, just not built:

- **The policy engine is early.** `xgate-policy` now reads an operator-editable
  JSON policy file (default-deny, deny-beats-allow, per-agent TTL, boundary-aware
  `/*` path rules, strict validation). It is still **not** a policy language:
  no conditions (time of day, target host, arguments), no human approval
  workflow, no max-uses beyond the single-use replay guard, and no integration
  with existing IAM/PAM. Policy files are trusted input — whoever can edit the
  file defines what agents may do, so protect it like the CA key.
- **Audit tamper-evidence has limits.** The hash chain detects edits and
  deletions *inside* the log. It cannot detect truncation of the tail (the
  remaining prefix is still a valid chain), and an attacker who holds the
  signing key (the CA key for the policy log, the host key for the daemon log)
  can forge a whole new chain. Ship the head hash (printed by `verify-audit`)
  to a system the attacker can't reach to close the first gap; keep the keys
  safe for the second. There is no remote log shipping built in.
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
- **Replay-guard persistence is best-effort, not transactional.** The
  used-serial store is a simple append-only file, matching how the audit log
  itself is handled. If a disk write to it fails, the in-memory guard still
  holds for that process's lifetime, but a restart immediately afterward could
  theoretically reopen a window for that one serial. Worth hardening (e.g. an
  fsync or a small embedded DB) before this is load-bearing in production.
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
