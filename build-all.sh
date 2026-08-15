#!/usr/bin/env bash
# Cross-compile xgate + xgated for every target from one machine. No C toolchain.
set -euo pipefail
mkdir -p dist
for t in linux/amd64 linux/arm64 linux/arm windows/amd64 windows/arm64 darwin/amd64 darwin/arm64; do
  os=${t%/*}; arch=${t#*/}; ext=""; [ "$os" = windows ] && ext=.exe
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -o "dist/xgated-$os-$arch$ext" ./cmd/xgated
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -o "dist/xgate-$os-$arch$ext"  ./cmd/xgate
  echo "built $t"
done
echo "all targets in dist/"
