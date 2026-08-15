# Go proof-of-concept — findings

A working Go port of xgate's security-critical core, built to answer one
question: **is Go's cross-platform story worth a full port?** Short answer for
your stated priority (easier cross-platform builds): **yes, clearly.**

## What this PoC contains

The same security-critical path as the Rust version, verified end to end:

- Certificate format, signing, verification (`proto/proto.go`)
- Capability model with per-command `exec` authorization
- The domain-separated signed handshake transcript
- Mutual-auth handshake over QUIC (`quic-go`)
- `exec` execution — run an authorized command, stream output
- Structured JSON audit log
- 12 unit tests, all passing; `go vet` clean; `gofmt` clean

Not included (same as the Rust PoC): interactive shell/PTY, file transfer,
port forwarding, password auth, rate limiting.

## The headline result: cross-compilation

From **one Linux x86-64 machine**, with no C toolchain and no per-platform
setup, `./build-all.sh` produced working binaries for all of these:

| Target | Binary type | Size |
|---|---|---|
| linux/amd64 | ELF x86-64 | 8.0M |
| linux/arm64 | ELF ARM64 | 7.6M |
| **linux/arm** (Raspberry Pi) | ELF 32-bit ARM | 7.6M |
| **windows/amd64** | PE32+ .exe | 8.1M |
| windows/arm64 | PE32+ .exe | 7.6M |
| **darwin/amd64** | Mach-O x86-64 | 7.9M |
| **darwin/arm64** (Apple Silicon) | Mach-O ARM64 | 7.6M |

`file` confirmed each is a genuine native executable for its platform. This is
one `go build` per target, no cross-linker, no C dependency.

**Contrast with Rust:** the Rust version depends on `ring`, which needs a C
toolchain and platform-native builds. In this same sandbox, only the Linux
Rust binary could ever be produced. Cross-compiling the Rust version to
Windows/macOS requires either those OSes or a configured cross-toolchain
(`cross`, MinGW, osxcross). For a tool whose whole pitch is "same binary
everywhere," **Go removes the single biggest operational friction.**

## Functional parity — verified live

Identical behaviour to the Rust build, on real binaries over QUIC:

```
$ xgate --cap exec:/usr/bin/whoami 127.0.0.1:7849
root

$ xgate --cap exec:/usr/bin/uptime 127.0.0.1:7849
 15:41:19 up 6 min,  load average: 0.17, 0.16, 0.09

$ xgate --cap exec:/bin/sh 127.0.0.1:7849
authentication rejected: capability_denied
```

The audit log recorded `auth_accepted` (with cert serial and CA key id),
`capability_used`, and `auth_rejected` — the reason stays server-side while the
client sees only the generic rejection. Same security posture as Rust.

## What Go costs you — honestly

The Rust version used the type system to make security mistakes hard to write.
Go does not have those tools, so the same guarantees become discipline:

1. **No sum types.** Rust's `Capability` enum with exhaustive matching meant
   adding a variant without handling it *failed to compile*. In Go,
   `Capability` is a struct with a `Kind` string, and `Permits` is a `switch`
   with a `default: return false`. It fails closed — but "did I handle every
   case" is now a code-review question, not a compiler guarantee. For
   authorization logic this is the most meaningful loss.

2. **No newtype enforcement.** Rust's `Sig64` made "a signature is exactly 64
   bytes" a compile-time fact. Go uses `[]byte` with a runtime length check
   (`len(sig) != ed25519.SignatureSize`). Correct, but checked at runtime and
   only where remembered.

3. **`nil` exists.** The `*Certificate` pointer in a frame can be nil; the code
   checks `ca.Cert == nil`, but Rust's `Option`/borrow rules made whole classes
   of this impossible.

4. **Errors are values, not enforced.** Go won't stop you ignoring a returned
   error. Rust's `Result` + `?` made the fail-closed paths harder to skip.

None of these are showstoppers — the PoC implements every check correctly. They
are a shift from "compiler catches it" to "reviewer and tests catch it." For a
security tool, that shift is the real trade.

## What Go gains you beyond cross-compilation

- **Standard-library crypto.** Ed25519, X25519, ChaCha20-Poly1305, TLS 1.3 are
  all in Go's stdlib. The `proto` package has **zero external dependencies** —
  its tests need nothing fetched. The Rust core needed `ed25519-dalek`,
  `sha2`, etc. Fewer supply-chain surfaces for the security core.
- **Simpler concurrency.** The daemon's accept loop is `for { go handle() }`.
  No async runtime, no lifetimes on shared state.
- **Smaller, faster builds.** ~8 MB binaries, seconds to compile, one tool
  (`go`) for build/test/fmt/vet.

## Recommendation

If **effortless cross-platform distribution** is the deciding factor — and you
said it is — Go is the better choice for this project, and the stdlib crypto is
a genuine bonus. You give up compile-time enforcement of some security
invariants; you buy it back with disciplined `default: deny`, thorough tests,
and code review.

If you had said the priority was *maximum assurance that the compiler prevents
authorization bugs*, the recommendation would flip to Rust. But for "same
binary on Linux, Mac, Windows, Pi, with the least friction," this PoC makes the
case for Go concretely rather than theoretically.

## Try it

```bash
cd xgate-go-poc
go test ./...            # 12 tests
go build ./...           # all three binaries
./build-all.sh           # cross-compile to all 7 targets -> dist/
```

Then the same demo as Rust: `go build -o mint ./cmd/mint`, mint certs, write a
JSON config, run `xgated`, connect with `xgate --cap exec:/usr/bin/uptime`.

## PoC scope caveats

- This proves the *architecture ports cleanly and cross-compiles*. It is not a
  finished tool any more than the Rust version is.
- The `go.mod` in this folder has a note about `replace` directives — those
  were only needed inside a restricted-network sandbox. On a normal machine,
  plain `go build` fetches everything. Delete the note; keep the file.
- Same known limitation as Rust: `pathPrefix` is Unix-shaped and unsafe for
  file capabilities on Windows.
