# GUI (browser-based) — `xgate-gui`

Windows and Mac users often want a window to click rather than a command line.
`xgate-gui` provides that **without a native GUI toolkit** (which would need a C
toolchain and break cross-compilation). Instead it runs a tiny local web app —
a connection manager plus a real terminal — that only ever listens on
`127.0.0.1`.

The Linux CLI (`xgate`) is unchanged; the GUI is an additional, optional binary.

## What it is

- A saved-hosts list with one-click connect.
- A real terminal (xterm.js — the same emulator VS Code uses), so `top`, `vim`,
  colours, and cursor movement work.
- The exact same security path as the CLI: it calls the same `proto` and
  `transport` code, runs the same mutual-auth handshake, and cannot bypass any
  check. The GUI is a front-end over the verified client, not a reimplementation.

## Why browser-based, not a native window

A native terminal widget in a Go GUI toolkit needs CGO and platform graphics
libraries, which would end the "one machine builds every target, no C
toolchain" property. The browser approach is pure Go + embedded HTML/JS, so
`xgate-gui` cross-compiles to Windows/Mac/Linux exactly like the other binaries.
This is how many modern cross-platform tools ship a GUI.

## Running it

```bash
go build -o xgate-gui ./cmd/xgate-gui   # or use a prebuilt xgate-gui.exe on Windows
./xgate-gui
```

It prints a `http://127.0.0.1:PORT/` address and opens your default browser
there. If the browser doesn't open automatically, paste that address in
yourself.

**Fastest — paste an enrollment token:**
1. Click **Paste token**, give the host a name, and paste the token from
   `xgated quickstart` (the whole `xgate --enroll ...` line is accepted too).
2. Click **Add & connect** — it decodes the token, saves the host, and connects
   immediately. No separate fields to fill.

**Or add a host manually:**
1. Click **+ Add** and fill in a host: a name, `host:port`, the paths to your
   `client.cert` and `client.key`, the CA public key (hex), and the transport
   (leave on **auto**).
2. Click the host, then **Connect.**
3. A terminal opens with a live shell on the remote machine.

Saved hosts are stored in your user config dir (`%AppData%\xgate\hosts.json` on
Windows, `~/.config/xgate/hosts.json` on Linux). **Only file paths and the CA
public key are stored — never your private key.**

## Security notes

- The web server binds `127.0.0.1` on a random port — it is not reachable from
  the network, only from your own machine.
- Your client key never leaves your machine and is never stored by the GUI; it
  is read from the path you gave, exactly as the CLI does.
- Because the browser talks to a local server that then makes the real
  connection, the terminal you see is bridged over a localhost websocket. That
  hop is on your own machine only.

## Status

- **Backend verified** (Linux): host storage, the connection manager API, and
  the full websocket→handshake→PTY-shell bridge all work end to end. A real
  shell (`/dev/pts`, live commands) runs through the browser terminal.
- **Frontend rendering** (the xterm.js display in an actual browser window) has
  not been visually verified in the build environment — there is no display
  there. xterm.js is a mature, widely used emulator, and the byte stream
  reaching it is correct, but expect to smooth out small UI details (sizing,
  focus, copy/paste) on first real use.
- Cross-compiles to Windows/Mac/Linux with no CGO.

## Building a Windows GUI exe

```bash
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o xgate-gui.exe ./cmd/xgate-gui
```

Double-clicking `xgate-gui.exe` on Windows opens the connection manager in the
default browser.
