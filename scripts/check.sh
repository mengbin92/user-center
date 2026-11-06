#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

unformatted="$(gofmt -l .)"
if [[ -n "$unformatted" ]]; then
  echo "$unformatted"
  echo "gofmt required"
  exit 1
fi

# Generated-code drift. Needs buf/wire and a clean tree; skipped (with a
# warning) rather than failed when either precondition is missing, so the
# script stays usable for people who only touched hand-written code.
if [[ "${SKIP_GEN_CHECK:-0}" == "1" ]]; then
  echo "check: skipped generated-code drift check (SKIP_GEN_CHECK=1)"
elif ! command -v buf >/dev/null 2>&1 || ! command -v wire >/dev/null 2>&1; then
  echo "check: skipped generated-code drift check (buf or wire not in PATH)"
elif [[ -n "$(git status --porcelain)" ]]; then
  echo "check: skipped generated-code drift check (working tree is dirty)"
else
  ./scripts/gen-check.sh
fi

go vet ./...
go test ./...

# MySQL-backed tests are gated on an isolated database. CI always provides one.
# The -run filter means a new MySQL-only test needs "MySQL" in its name.
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
