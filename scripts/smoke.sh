#!/usr/bin/env bash
# End-to-end smoke test against a running dev instance.
set -euo pipefail
BASE="${BASE_URL:-http://127.0.0.1:8080}"
JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT

curl -fsS -c "$JAR" "$BASE/api/v1/auth/context" >/dev/null
CSRF="$(awk '$6=="uc_csrf"{print $7}' "$JAR")"
: "${SMOKE_USER:?set SMOKE_USER}"
: "${SMOKE_PASSWORD:?set SMOKE_PASSWORD}"

curl -fsS -b "$JAR" -c "$JAR" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$SMOKE_USER\",\"password\":\"$SMOKE_PASSWORD\"}" \
  "$BASE/api/v1/auth/login" | tee /tmp/uc-login.json

curl -fsS -b "$JAR" "$BASE/api/v1/me" >/dev/null
curl -fsS -b "$JAR" "$BASE/api/v1/me/authorization" >/dev/null
echo "OK: login, /me and /me/authorization"
