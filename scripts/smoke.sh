#!/usr/bin/env bash
# End-to-end smoke test against a running dev instance.
set -euo pipefail
BASE="${BASE_URL:-http://127.0.0.1:8080}"
JAR="$(mktemp)"
LOGIN_REPLY="$(mktemp)"
trap 'rm -f "$JAR" "$LOGIN_REPLY"' EXIT

curl -fsS -c "$JAR" "$BASE/api/v1/auth/context" >/dev/null
CSRF="$(awk '$6=="uc_csrf"{print $7}' "$JAR")"
: "${SMOKE_USER:?set SMOKE_USER}"
: "${SMOKE_PASSWORD:?set SMOKE_PASSWORD}"

# Encode credentials as JSON instead of interpolating quotes or backslashes.
python3 -c 'import json, os; print(json.dumps({"username": os.environ["SMOKE_USER"], "password": os.environ["SMOKE_PASSWORD"]}))' |
  curl -fsS -b "$JAR" -c "$JAR" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' \
    --data-binary @- "$BASE/api/v1/auth/login" >"$LOGIN_REPLY"

python3 - "$LOGIN_REPLY" <<'PY'
import json, sys
with open(sys.argv[1]) as reply_file:
    reply = json.load(reply_file)
if reply.get("status") != "authenticated":
    sys.exit("Smoke login requires a password-only test account; complete MFA separately.")
PY

curl -fsS -b "$JAR" "$BASE/api/v1/me" >/dev/null
curl -fsS -b "$JAR" "$BASE/api/v1/me/authorization" >/dev/null
echo "OK: login, /me and /me/authorization"
