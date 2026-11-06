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

# MySQL-backed tests are gated on an isolated database. CI always provides one.
if [[ -n "${USER_CENTER_MYSQL_TEST_DSN:-}" ]]; then
  echo "check: running MySQL-backed tests"
  go test -count=1 -run MySQL ./cmd/migrate/
  go test -count=1 -run MySQL ./internal/data/
else
  echo "check: skipped MySQL-backed tests (USER_CENTER_MYSQL_TEST_DSN unset)"
fi

cd web
npm test
npm run build
