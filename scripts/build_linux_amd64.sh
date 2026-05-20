#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export GOOS=linux
export GOARCH=amd64
export CGO_ENABLED=0
go build -trimpath -ldflags="-s -w" -o ultraSpoof ./cmd/ultraSpoof
echo "built: ./ultraSpoof (linux/amd64, Ubuntu Server 22.04/24.04 amd64 compatible; tunmod needs root + iproute2)"
