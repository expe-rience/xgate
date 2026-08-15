# Contributing

## Branch workflow

`main` is protected. You cannot push to it directly — all changes land through
pull requests that a maintainer reviews and approves.

1. **Never commit to `main`.** Create a branch:
   ```bash
   git checkout -b your-feature-name
   ```
2. Make your change. Keep it focused — one topic per branch.
3. Before pushing, make sure it's green:
   ```bash
   go build ./...
   go test ./...
   go vet ./...
   gofmt -w .
   ```
4. Push your branch and open a pull request against `main`:
   ```bash
   git push -u origin your-feature-name
   ```
5. CI runs automatically (build + test on Linux/macOS/Windows, cross-compile,
   gofmt). A maintainer reviews. Once approved and CI is green, it merges.

Direct pushes to `main` are rejected by branch protection, so working on a
branch isn't optional — it's the only path in.

## What review looks for

- Anything touching `proto/` needs a test, including the **denial** path, not
  just the success case. That package is the security core.
- The `Permits` default in `proto/proto.go` must stay `return false` (fail
  closed). A PR that changes it will be declined.
- `go vet` and `gofmt` must pass — CI enforces both.

## For anything touching the handshake, certificates, or capabilities

Open an issue first to discuss the design. At this stage the protocol isn't
frozen, and getting the shape right matters more than getting a patch merged
fast.
