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

```bash
cd agent-demo
./run-demo.sh
```

Watch: a legit "restart payments-service" task gets a 60-second single-use
capability and runs; a prompt-injected "read prod DB creds / open a shell"
request is **denied at the policy layer** before it ever reaches xgate; even a
valid capability can't be used for a different command; and every decision is in
a signed audit trail. This is the story of the whole project in 90 seconds.

## What to report

Especially valuable: does the agent-boundary demo land clearly? If you build AI
agents, does this match a real problem you have? Also: macOS/Pi runtime, GUI
rendering, long Windows sessions. Open an issue with what you ran and what you
saw (the daemon window logs the reason for most failures).
