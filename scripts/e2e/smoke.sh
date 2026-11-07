#!/usr/bin/env bash
# V2.4 end-to-end smoke test against a running instance (dev or compose).
# Supports --base-url, automatic cleanup of temporary files, and a failure
# snapshot directory containing the last response, headers and (optionally)
# docker compose logs. No ad-hoc temp directories are left behind.
set -euo pipefail

BASE_URL="http://127.0.0.1:8080"
SNAPSHOT_DIR=""
COMPOSE_FILE=""
COMPOSE_ENV=""
KEEP=0
SKIP_READYZ=0
SMOKE_USER="${SMOKE_USER:-root}"
SMOKE_PASSWORD="${SMOKE_PASSWORD:-ChangeMe-12345}"

usage() {
  cat <<'USAGE'
Usage: scripts/e2e/smoke.sh [options]
  --base-url URL       target instance (default http://127.0.0.1:8080)
  --snapshot-dir DIR   where to write the failure snapshot
  --compose FILE       docker compose file; capture logs on failure
  --compose-env FILE   env file for the compose file (required when the
                       compose file uses :? interpolation, e.g. secrets)
  --keep               keep temporary request artifacts on success
  --skip-readyz        skip the /readyz assertion (for releases predating S13)
  -h, --help           show this help
Environment: SMOKE_USER, SMOKE_PASSWORD (password-only account, no MFA).
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-url) BASE_URL="$2"; shift 2 ;;
    --snapshot-dir) SNAPSHOT_DIR="$2"; shift 2 ;;
    --compose) COMPOSE_FILE="$2"; shift 2 ;;
    --compose-env) COMPOSE_ENV="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    --skip-readyz) SKIP_READYZ=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/user-center-e2e.XXXXXX")"
JAR="$WORK/cookies"
BODY="$WORK/last-body"
HEADERS="$WORK/last-headers"
STAMP="$(date +%Y%m%d-%H%M%S)"
SNAPSHOT_DIR="${SNAPSHOT_DIR:-$ROOT/artifacts/e2e-fail-$STAMP}"
mkdir -p "$WORK"

step="bootstrap"
cleanup() {
  rc=$?
  if [[ $rc -ne 0 ]]; then
    mkdir -p "$SNAPSHOT_DIR"
    {
      echo "failed_step=$step"
      echo "base_url=$BASE_URL"
      echo "timestamp=$STAMP"
    } >"$SNAPSHOT_DIR/meta.txt"
    cp "$BODY" "$SNAPSHOT_DIR/last-body" 2>/dev/null || true
    cp "$HEADERS" "$SNAPSHOT_DIR/last-headers" 2>/dev/null || true
    cp "$JAR" "$SNAPSHOT_DIR/cookies" 2>/dev/null || true
    if [[ -n "$COMPOSE_FILE" ]] && command -v docker >/dev/null 2>&1; then
      # The compose file interpolates required secrets, so the env file is
      # needed even for `logs`; without it compose refuses to parse the file.
      local compose_args=(-f "$COMPOSE_FILE")
      if [[ -n "$COMPOSE_ENV" ]]; then
        compose_args=(--env-file "$COMPOSE_ENV" "${compose_args[@]}")
      fi
      docker compose "${compose_args[@]}" logs --no-color >"$SNAPSHOT_DIR/compose.log" 2>&1 || true
    fi
    echo "E2E failed at '$step'; snapshot: $SNAPSHOT_DIR" >&2
  fi
  if [[ $KEEP -eq 0 ]]; then
    rm -rf "$WORK"
  else
    echo "E2E artifacts kept at $WORK" >&2
  fi
  exit $rc
}
trap cleanup EXIT

request() {
  local method="$1" path="$2" expected="$3"; shift 3
  step="$method $path"
  local status
  status="$(curl -sS -o "$BODY" -D "$HEADERS" -b "$JAR" -c "$JAR" \
    -w '%{http_code}' "$@" "${BASE_URL}${path}")"
  if [[ "$status" != "$expected" ]]; then
    echo "expected HTTP $expected for $method $path, got $status" >&2
    cat "$BODY" >&2
    return 1
  fi
}

json_field() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2], ""))' "$BODY" "$1"
}

# 1. Health and unauthenticated gate.
step="healthz"
request GET /healthz 200
# Liveness alone would pass with a dead database; readiness is what the
# deployment actually depends on, so the smoke test asserts both. Rollback
# drills run this against releases that predate /readyz and pass
# --skip-readyz explicitly -- silent omission would hide a real regression.
if [[ $SKIP_READYZ -eq 0 ]]; then
  step="readyz"
  request GET /readyz 200
fi
step="unauthenticated /me"
request GET /api/v1/me 401

# 2. CSRF bootstrap.
step="auth context"
request GET /api/v1/auth/context 200
CSRF="$(awk '$6=="uc_csrf"{print $7}' "$JAR")"
if [[ -z "$CSRF" ]]; then echo "CSRF cookie missing" >&2; exit 1; fi

# 3. Login (password-only account).
step="login"
python3 -c 'import json,os; print(json.dumps({"username":os.environ["SMOKE_USER"],"password":os.environ["SMOKE_PASSWORD"]}))' >"$WORK/login.json"
request POST /api/v1/auth/login 200 -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' --data-binary "@$WORK/login.json"
STATUS="$(json_field status)"
if [[ "$STATUS" != "authenticated" ]]; then
  echo "smoke account must be password-only (got status=$STATUS)" >&2; exit 1
fi
step="authenticated /me"
request GET /api/v1/me 200
step="authorization projection"
request GET /api/v1/me/authorization 200

# 4. V2.4 self-service surfaces.
step="oidc consents"
request GET /api/v1/me/oidc-consents 200
step="webauthn credentials"
request GET /api/v1/me/webauthn/credentials 200
step="discovery end_session_endpoint"
request GET /.well-known/openid-configuration 200
if ! grep -q 'end_session_endpoint' "$BODY"; then
  echo "discovery is missing end_session_endpoint" >&2; exit 1
fi

# 5. Step-up (password-only account) and a protected tenant write.
step="step-up proof"
python3 -c 'import json,os; print(json.dumps({"current_password":os.environ["SMOKE_PASSWORD"]}))' >"$WORK/stepup.json"
request POST /api/v1/me/security:verify 200 -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' --data-binary "@$WORK/stepup.json"

step="create organization"
CODE="e2e-$STAMP"
SMOKE_ORG_CODE="$CODE" python3 -c 'import json,os; print(json.dumps({"code":os.environ["SMOKE_ORG_CODE"],"name":"E2E Smoke"}))' >"$WORK/org.json"
request POST /api/v1/orgs 200 -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' --data-binary "@$WORK/org.json"
ORG_ID="$(json_field id)"
if [[ -z "$ORG_ID" ]]; then echo "organization id missing" >&2; exit 1; fi

step="tenant audit"
request GET "/api/v1/orgs/$ORG_ID/audits" 200
step="tenant invitations"
request GET "/api/v1/orgs/$ORG_ID/invitations" 200
step="tenant authorization explain (non-member)"
request GET "/api/v1/orgs/$ORG_ID/iam/authorization:explain?user_id=999999&operation=organization.member.read" 404
step="organization quota settings"
request GET /api/v1/admin/settings/organization 200
step="provider configuration view"
request GET /api/v1/admin/settings/providers 200
step="cross-tenant unknown organization"
request GET /api/v1/orgs/999999 404

# 6. Logout and post-logout session invalidation.
step="logout"
request POST /api/v1/auth/logout 200 -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' --data-binary '{}'
step="post-logout /me"
request GET /api/v1/me 401

echo "E2E OK: health, 401 gate, login, self-service, V2.4 discovery, Step-up, tenant boundary, audit, logout"
