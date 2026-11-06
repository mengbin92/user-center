#!/usr/bin/env bash
# Full-stack E2E against the real compose stack (MySQL 8.4 + Redis 7).
#
# The CI workflow calls this script so the pipeline and a local run execute
# exactly the same steps; a workflow that only ever ran in CI could not be
# debugged. Everything it creates lives under --work-dir.
#
# Exit codes: 0 pass, 1 any check failed.
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT="$(pwd)"

COMPOSE_FILE="${COMPOSE_FILE:-deployments/docker-compose/docker-compose.yml}"
WORK="${WORK:-}"
KEEP=0
SKIP_BUILD=0
SMOKE_USER="${SMOKE_USER:-root}"
SMOKE_PASSWORD="${SMOKE_PASSWORD:-ChangeMe-12345}"

usage() {
  cat <<'USAGE'
Usage: scripts/e2e/compose-e2e.sh [options]
  --work-dir DIR   keep artefacts here (default: a temp dir, removed on exit)
  --keep           leave the stack running after a successful run
  --skip-build     reuse the existing user-center:latest image
  -h, --help       show this help

Requires docker with compose v2, openssl, curl.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --work-dir) WORK="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$WORK" ]]; then
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/user-center-compose-e2e.XXXXXX")"
  KEEP_WORK=0
else
  mkdir -p "$WORK"
  KEEP_WORK=1
fi
COMPOSE_ENV="$WORK/compose.env"
export COMPOSE_FILE COMPOSE_ENV WORK

compose() { docker compose --env-file "$COMPOSE_ENV" -f "$COMPOSE_FILE" "$@"; }

teardown() {
  local rc=$?
  # Grab the logs before tearing the stack down when a step failed earlier:
  # "container log" never ran, and the artifact would be empty.
  if [[ $rc -ne 0 && ! -f "$WORK/compose.log" ]]; then
    compose logs --no-color >"$WORK/compose.log" 2>&1 || true
  fi
  if [[ $KEEP -eq 0 ]]; then
    compose down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  if [[ $KEEP_WORK -eq 0 && $KEEP -eq 0 && $rc -eq 0 ]]; then
    rm -rf "$WORK"
  else
    echo "artefacts kept in $WORK"
  fi
}
trap teardown EXIT

step() { printf '\n== %s\n' "$*"; }

step "environment"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$WORK/oidc.pem" 2>/dev/null
chmod 600 "$WORK/oidc.pem"
MYSQL_PASSWORD="$(openssl rand -hex 16)"
# COOKIE_SECURE must be false: the smoke test talks plain http to 127.0.0.1 and
# curl will not send a Secure cookie over http. OIDC_ISSUER must be https
# because the MySQL driver disables the loopback-http development shortcut.
{
  printf 'MYSQL_PASSWORD=%s\n' "$MYSQL_PASSWORD"
  printf 'MYSQL_ROOT_PASSWORD=%s\n' "$(openssl rand -hex 16)"
  printf 'SESSION_SECRET=%s\n' "$(openssl rand -base64 48 | tr -d '\n')"
  printf 'CSRF_SECRET=%s\n' "$(openssl rand -base64 48 | tr -d '\n')"
  printf 'MFA_ENCRYPTION_KEY=%s\n' "$(openssl rand -base64 48 | tr -d '\n')"
  printf 'COOKIE_SECURE=false\n'
  printf 'PUBLIC_BASE_URL=http://127.0.0.1:8080\n'
  printf 'OIDC_ISSUER=https://e2e.local\n'
  printf 'OIDC_SIGNING_KEY_FILE=%s/oidc.pem\n' "$WORK"
} >"$COMPOSE_ENV"
chmod 600 "$COMPOSE_ENV"
echo "work dir: $WORK"

if [[ $SKIP_BUILD -eq 0 ]]; then
  step "build image"
  START=$(date -u +%s)
  # v0.6.0 burned a release on `docker compose build | tail`: the pipe made the
  # exit code always 0, the failure was swallowed, and `up -d` silently reused
  # a stale image. Never pipe the build; keep the log and read PIPESTATUS.
  set +e
  compose build 2>&1 | tee "$WORK/build.log"
  status=${PIPESTATUS[0]}
  set -e
  if [[ $status -ne 0 ]]; then
    echo "compose build failed with exit $status" >&2
    exit "$status"
  fi
  created=$(docker image inspect user-center:latest --format '{{.Created}}')
  if (( $(date -u -d "$created" +%s) < START )); then
    echo "image predates this build ($created); refusing to smoke a stale image" >&2
    exit 1
  fi
  echo "image built at $created"
fi

step "start stack"
compose up -d

# migrate is a one-shot service, so it is already Exited by the time `up -d`
# returns; without -a, ps lists only running services and this lookup is empty.
migrate_id=$(compose ps -a -q migrate)
if [[ -z "$migrate_id" ]]; then
  echo "migrate container not found" >&2
  compose ps -a >&2
  exit 1
fi
migrate_status=$(docker wait "$migrate_id")
compose logs migrate | tee "$WORK/migrate.log"
if [[ "$migrate_status" != "0" ]]; then
  echo "migrate exited with $migrate_status" >&2
  exit 1
fi

ready=0
for _ in $(seq 1 90); do
  if curl -fsS http://127.0.0.1:8080/healthz >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 2
done
if [[ $ready -ne 1 ]]; then
  echo "service did not become healthy" >&2
  compose ps >&2
  exit 1
fi
echo "service is up"

step "smoke account"
compose exec -T user-center /app/admin-rescue -config /app/configs/config.docker.yaml \
  -action bootstrap -username "$SMOKE_USER" -email root@example.com -password "$SMOKE_PASSWORD"
# Platform default demands MFA for admins; the smoke account is a password
# account. Fixture for this throwaway stack only — MFA itself is covered by the
# Go test suite.
compose exec -T mysql mysql -uusercenter -p"$MYSQL_PASSWORD" usercenter -e \
  "INSERT INTO auth_settings (name,value,revision,updated_at)
   VALUES ('auth','{\"MFARequiredForAdmins\":false}',1,UTC_TIMESTAMP(3))
   ON DUPLICATE KEY UPDATE value=VALUES(value);"

step "smoke test"
SMOKE_USER="$SMOKE_USER" SMOKE_PASSWORD="$SMOKE_PASSWORD" scripts/e2e/smoke.sh \
  --base-url http://127.0.0.1:8080 \
  --snapshot-dir "$WORK/snapshot" \
  --compose "$COMPOSE_FILE" \
  --compose-env "$COMPOSE_ENV" 2>&1 | tee "$WORK/smoke.log"

step "database evidence"
compose exec -T mysql mysql -uusercenter -p"$MYSQL_PASSWORD" usercenter \
  -e "SELECT 'organizations' AS tbl, COUNT(*) AS rows_written FROM organizations
      UNION ALL SELECT 'audit_events', COUNT(*) FROM iam_audit_events
      UNION ALL SELECT 'outbox_events', COUNT(*) FROM event_outbox
      UNION ALL SELECT 'sessions', COUNT(*) FROM iam_sessions;" | tee "$WORK/evidence.txt"

step "container log"
compose logs --no-color >"$WORK/compose.log" 2>&1 || true
# A green smoke over a service that logged 5xx is worse than a red build.
if grep -Eq '"status":5[0-9][0-9]|panic:' "$WORK/compose.log"; then
  echo "service log contains 5xx or panic" >&2
  grep -En '"status":5[0-9][0-9]|panic:' "$WORK/compose.log" >&2 || true
  exit 1
fi
echo "no 5xx or panic in the container log"

step "pass"
