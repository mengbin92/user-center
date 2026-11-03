#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
unformatted="$(gofmt -l .)"
if [[ -n "$unformatted" ]]; then
  echo "$unformatted"
  echo "gofmt required"
  exit 1
fi
go vet ./...
go test ./...
cd web
npm test
npm run build
