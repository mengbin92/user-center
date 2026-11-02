#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
gofmt -l . | grep -v '^$' && { echo "gofmt required"; exit 1; } || true
go vet ./...
go test ./...
cd web && npm run build
