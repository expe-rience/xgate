# xgate — test kit

Prebuilt binaries so you can try xgate without building. **Pre-alpha,
unaudited — test on machines you don't mind experimenting with.**

xgate gives an identity (an AI agent, or a human) a certificate to run exactly
one command, on one host, for a few minutes — then it expires. Two ways to try
it: as a **remote-admin tool** (human driving), or as an **agent execution
boundary** (the demo).

## Pick your binaries (in `binaries/`)

Files are named `<tool>-<os>-<arch>`. Tools:
- **xgated** — the daemon (runs on the machine you want to reach/control)
- **xgate** — the client (runs on the machine you connect from)
- **xgate-gui** — optional browser GUI instead of the client CLI
- **xgate-policy** — the policy engine (for the agent demo)

| Your machine | daemon | client |
|---|---|---|
| Windows (Intel/AMD) | `xgated-windows-amd64.exe` | `xgate-windows-amd64.exe` |
| Linux PC/server | `xgated-linux-amd64` | `xgate-linux-amd64` |
| Mac (Apple Silicon) | `xgated-darwin-arm64` | `xgate-darwin-arm64` |
| Mac (Intel) | `xgated-darwin-amd64` | `xgate-darwin-amd64` |
| Raspberry Pi 64-bit | `xgated-linux-arm64` | `xgate-linux-arm64` |

(`uname -m`: `x86_64`=amd64, `aarch64`/`arm64`=arm64, `armv7l`=arm.)
Verify downloads: `sha256sum -c SHA256SUMS.txt` in `binaries/`.

These binaries were built from the current source (policy-as-config, tamper-evident
audit, replay protection). Known limits are in `docs/limitations.md`.

## A) Try it as remote admin (2 minutes)

On the machine you want to reach (Linux/Mac shown; Windows uses PowerShell as
Admin and the `.exe`):

```bash
chmod +x xgated-<os>-<arch>
./xgated-<os>-<arch> quickstart
```

It prints a firewall command, a start command, and an `xgate --enroll <token>`
line. Run the firewall command, run the start command (leave it running), copy
the token.

On the machine you connect from:

```bash
chmod +x xgate-<os>-<arch>
./xgate-<os>-<arch> --enroll <paste the token>
```

You get a live shell. Try `whoami`, `ls`, then `exit`.

macOS note: Gatekeeper blocks unsigned binaries — clear them first:
`xattr -d com.apple.quarantine ./xgate-darwin-* ./xgated-darwin-*`

## B) Try it as the AI-agent execution boundary (the demo)

Linux or macOS (or WSL on Windows). The demo installs a harmless stub command in
`/usr/local/bin`, so run it with `sudo` if you are not root:

```bash
cd agent-demo
sudo ./run-demo.sh
```

(`agent-demo/` holds Linux x86-64 binaries, including `mint`, which is only prebuilt
there. On another platform build the four tools from source:
`go build -o agent-demo/ ./cmd/mint ./cmd/xgate ./cmd/xgated ./cmd/xgate-policy`.)

Watch: a legit "restart payments-service" task is allowed by `policy.json` and gets
a 60-second single-use capability, and runs; prompt-injected requests (read prod DB
credentials, a `../../bin/sh` path trick, a shell) are **denied at the policy layer**
before any credential exists; a valid capability can't run a different command; a
captured certificate can't be replayed; and every decision lands in a hash-chained,
signed audit log, which the demo then verifies, edits, and shows the edit being caught.

### Writing your own policy

Edit `agent-demo/policy.json` (format and rules: `policy.example.json` in the repo):

```bash
./xgate-policy check policy.json                       # validate
./xgate-policy explain policy.json sre-agent restart nginx   # dry-run a decision
./xgate-policy issue --policy policy.json <agent> <action> <resource> ca.key <outdir>
./xgate-policy verify-audit policy-audit.jsonl <ca-public-key-hex>
./xgated verify-audit xgate-audit.jsonl host.cert
```

Default-deny; explicit deny beats allow; typos in the file are errors, not silent gaps.

## What to report

Especially valuable: does the agent-boundary demo land clearly? If you build AI
agents, does this match a real problem you have? Also: macOS/Pi runtime, GUI
rendering, long Windows sessions. Open an issue with what you ran and what you
saw (the daemon window logs the reason for most failures).
