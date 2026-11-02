#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
CONF="${CONF_PATH:-configs/config.dev.yaml}"
go run ./cmd/migrate -config "$CONF"
if [[ -n "${USER_CENTER_BOOTSTRAP_USERNAME:-}" && -n "${USER_CENTER_BOOTSTRAP_PASSWORD:-}" ]]; then
  go run ./cmd/admin-rescue -config "$CONF" -action bootstrap \
    -username "$USER_CENTER_BOOTSTRAP_USERNAME" \
    -password "$USER_CENTER_BOOTSTRAP_PASSWORD" \
    -email "${USER_CENTER_BOOTSTRAP_EMAIL:-}" || true
fi
go run ./cmd/user-center -config "$CONF"
