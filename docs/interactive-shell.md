# Interactive shell — status and setup

You asked for full interactive shells (type live, run `top`/`vim`) in both
directions: Windows→Linux and Linux→Windows. Here is exactly where that stands.

## What is verified

**The Unix PTY shell works, live.** A real pseudo-terminal session was run end
to end over QUIC on Linux:

- A live `bash` prompt rendered over the connection
- Interactive commands ran: `whoami`, `pwd`, `uname -a`, arithmetic
- `tty` returned `/dev/pts/0` — a **real PTY**, which is what `top` and `vim`
  require to work
- Terminal control sequences (bracketed-paste, etc.) flowed through, so
  full-screen apps will render
- Clean `exit` with code 0

This covers the **Linux-daemon half of Windows→Linux** completely, plus the
entire client path (raw-terminal handling, stdin/stdout streaming, resize).

**All seven platforms compile**, including the Windows daemon with ConPTY — a
genuine PE32+ executable. `windows/amd64`, `windows/arm64`, `darwin/*`,
`linux/*`, and the Raspberry Pi `linux/arm` target all build from one Linux
machine.

## What is NOT verified

**The Windows ConPTY shell has never been run.** There is no Windows machine in
the build environment. The code compiles and uses a maintained ConPTY library
(`go-pty`), but "compiles" and "works" are different claims, and I will not
pretend otherwise. The Linux→Windows direction — where the Windows box runs the
daemon and allocates a ConPTY — is **unproven at runtime**.

Honest per-direction status:

| Direction | Daemon side | Client side | Status |
|---|---|---|---|
| **Windows → Linux** | Linux PTY — **verified** | Windows client — compiles, unrun | Daemon proven; client needs a real run |
| **Linux → Windows** | Windows ConPTY — compiles, unrun | Linux client — **verified** | Client proven; ConPTY daemon needs a real run |

So between the two, every *component* is either verified or compiles — but
neither *full direction* has been run on the actual Windows hardware yet. The
Unix PTY path and the client path are solid; the ConPTY path is the remaining
unknown.

## Known rough edges on Windows

1. **Shell choice.** The daemon spawns `powershell.exe` on Windows. If you want
   `cmd.exe` or `pwsh`, change `defaultShell()` in `cmd/xgated/shell.go`.
2. **ConPTY needs Windows 10 1809+** (older Windows has no pseudo-console API).
3. **File capabilities are still unsafe on Windows** — the `pathPrefix` check
   is Unix-shaped. This does not affect shell/exec, only `read:`/`write:`.
4. **Windows client raw mode** relies on `x/term`, which handles the Windows
   console — but this specific path is unrun, so expect to smooth out key
   handling (e.g. Ctrl-C, arrow keys) on first real use.

## Setup for both directions

The same two binaries run everywhere. "Direction" is just which machine runs
the daemon.

### Windows → Linux (shell on the Linux box)

On the **Linux** machine (the daemon):

```bash
./mint .                       # prints the CA public key; note it
cat > xgated.json <<EOF
{"listen":"0.0.0.0:7847","trusted_ca":"<CA_HEX>","host_cert_path":"host.cert",
 "host_key_path":"host.key","skew_seconds":30,"audit_path":"audit.jsonl"}
EOF
sudo ufw allow 7847/udp        # QUIC is UDP
./xgated --config xgated.json
```

On the **Windows** machine (the client), in PowerShell:

```powershell
$env:XRM_CA = "<CA_HEX>"
.\xgate-windows-amd64.exe --cert client.cert --key client.key --cap shell LINUX_HOST:7847
```

(Copy `client.cert` and `client.key` to the Windows box; they were written by
`mint` on the Linux side. In a real deployment the client generates its own key
and the CA signs it — the shared-file shortcut is for the demo.)

### Linux → Windows (shell on the Windows box)

On the **Windows** machine (the daemon), PowerShell as Administrator:

```powershell
.\mint-windows.exe .
# write xgated.json with a Windows audit_path, e.g. C:\ProgramData\xgate\audit.jsonl
New-NetFirewallRule -DisplayName "xgate" -Direction Inbound -Protocol UDP -LocalPort 7847 -Action Allow
.\xgated-windows-amd64.exe --config xgated.json
```

On the **Linux** machine (the client):

```bash
export XRM_CA="<CA_HEX>"
./xgate --cert client.cert --key client.key --cap shell WINDOWS_HOST:7847
```

This is the direction whose daemon (ConPTY) is unrun — expect to debug the
Windows shell spawn on first try.

## The honest bottom line

You have a working interactive remote shell **today for Windows→Linux** (the
Linux daemon PTY is proven, the Windows client compiles and the client logic is
proven on Linux). **Linux→Windows compiles but the ConPTY daemon needs a real
Windows machine to confirm.** The fastest way to close that gap is to copy
`xgated-windows-amd64.exe` to a Windows 10/11 box and run the setup above — if
the shell spawns and echoes, you are done; if not, the fix is almost certainly
in `defaultShell()` or the ConPTY resize call, both in `cmd/xgated/shell.go`.

## Build it yourself

```bash
cd xgate-go-poc
go build ./...           # all three binaries for your OS
./build-all.sh           # cross-compile to all 7 targets -> dist/
go test ./proto/         # security-core tests
```
