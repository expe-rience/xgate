# xgate for AI agents

**The problem:** AI agents are increasingly given the ability to *act* — run
commands, deploy, restart services, manage infrastructure. To do that, they need
access to real machines. Today that access is almost always **standing and
broad**: an API key, an SSH key, a service account the agent holds indefinitely.

That's dangerous in a way it wasn't for traditional automation, because the
thing holding the credential can be **prompt-injected, can hallucinate, or can
take an action nobody intended** — and if it holds a broad key, it has broad
power to do damage.

**The question nobody has a clean answer to:** how do you let an agent do its job
without giving it persistent, over-broad access to your systems?

## What xgate offers

xgate's model maps almost exactly onto what safe agent access needs:

| Agent needs | xgate provides |
|---|---|
| Least privilege | Capabilities: grant exactly `exec:/usr/bin/deploy`, not a shell |
| Time-boxed access | Short-lived certificates (minutes), not long-lived keys |
| Revocable | Expiry *is* revocation — nothing to clean up or forget |
| Auditable | Signed, structured log of every action the identity took |
| No lateral movement | An `exec` grant is one command — no shell to pivot from |
| Strong identity | CA-signed mutual auth, no trust-on-first-use |

Instead of "here's a key, please behave," an agent gets: *you may run this one
command, on this host, for the next N minutes, and every call is logged.* When
the certificate expires, the access is simply gone.

## How it fits an agent architecture

A typical shape (illustrative — building blocks exist today, the CA tooling is
still minimal):

```
  ┌─────────────┐     mints a short-lived, scoped cert
  │  Your CA /  │────────────────────────────────────────┐
  │  policy     │   "agent-X may exec:/usr/bin/deploy      │
  │  service    │    on host Y for 15 min"                 │
  └─────────────┘                                          ▼
                                                    ┌─────────────┐
  ┌─────────────┐   presents the scoped cert        │   xgated      │
  │  AI agent   │─────────────────────────────────▶ │  (on host Y)│
  │  (client)   │   runs the one allowed command    │  enforces + │
  └─────────────┘ ◀─────────────────────────────────│  audits     │
                     output + signed audit trail     └─────────────┘
```

The agent never holds standing credentials. Your policy layer decides what to
grant, per task, just-in-time. xgate enforces it and records it.

## Why not just use SSH / existing tools?

- **SSH keys are all-or-nothing and long-lived** — exactly the wrong shape for
  an autonomous, occasionally-unpredictable actor.
- **Broad API tokens** have the same standing-power problem.
- **Heavier access platforms** (Teleport, Boundary) can do scoped access but are
  built around human/enterprise workflows and are a lot to adopt. xgate is trying
  to be the small, simple, agent-friendly primitive.

## Honest status

This is the **direction** xgate is being pointed, and the primitives (scoped
caps, short-lived certs, mutual auth, audit log) work today. What's **not** done:
a real policy/CA service for minting per-task certs (today's `mint`/`quickstart`
are test tools), rate limiting, and — critically — a **security audit**. This is
pre-alpha. Do not put it in a production agent loop yet.

## This is where feedback is most wanted

If you build AI agents that act on real systems, the most useful thing you can
tell us:

- How do you handle giving your agents access to machines today?
- What scares you about it?
- Would per-task, expiring, capability-scoped access actually fit your
  architecture — or what's missing?

Open an issue, or reply to the launch thread. This wedge lives or dies on
whether it matches real agent-builders' pain — so your input directly shapes it.
