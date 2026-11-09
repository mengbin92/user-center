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

# The stack MUST live in its own compose project. The teardown below runs
# `down -v --remove-orphans`, and compose derives the project name from the
# directory when nothing overrides it: running this script from a checkout that
# also hosts a real deployment (project "docker-compose") would delete that
# deployment's containers *and* its mysql-data volume.
#
# The name is generated unconditionally, never inherited. `${COMPOSE_PROJECT_NAME:-...}`
# looked safe but is not: a shell that already exports the *deployment's* project
# name (a plausible thing to have in your environment) would put this run back in
# the real project, and a failed build would then tear it down. An inherited name
# is not a reuse switch here.
#
# It is exported so nested commands (smoke.sh and its compose calls) inherit it.
export COMPOSE_PROJECT_NAME="uc-e2e-$(openssl rand -hex 6)"

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
# The container runs as an unprivileged user (see Dockerfile USER app). A 0600
# key is unreadable there: on Linux the bind mount keeps the source permission,
# so the service fails with "permission denied" while macOS Docker Desktop
# silently relaxes it — that is exactly how this passed locally and failed in
# CI. Keep the directory 0700 and make the key world-readable inside it, the
# same shape Kubernetes uses for secret volumes (0444).
SECRETS_DIR="$WORK/secrets"
mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$SECRETS_DIR/oidc.pem" 2>/dev/null
chmod 444 "$SECRETS_DIR/oidc.pem"
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
  printf 'OIDC_SIGNING_KEY_FILE=%s/oidc.pem\n' "$SECRETS_DIR"
} >"$COMPOSE_ENV"
chmod 600 "$COMPOSE_ENV"
echo "work dir: $WORK"

if [[ $SKIP_BUILD -eq 0 ]]; then
  step "build image"
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
  # Do not compare the image's Created timestamp with the build start time: on
  # a full cache hit Docker keeps the original timestamp, so that check fails a
  # perfectly good build. Content addressing already guarantees the image
  # matches the sources — the exit code above is the real gate. Record the id
  # so a failure can be traced to the exact image.
  image_id=$(docker image inspect user-center:latest --format '{{.Id}}')
  echo "image: $image_id"
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
  # The reason is almost always one line in this log; without it the artifact
  # only shows "Restarting (1)".
  compose logs --no-color user-center 2>&1 | tail -40 >&2
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

step "metrics endpoint"
# The scrape listener is only useful if it is reachable from outside the
# container; a bound-but-unpublished port is invisible until an alert is needed.
metrics_body=$(curl -fsS http://127.0.0.1:9091/metrics)
for family in usercenter_http_requests_total usercenter_dependency_up usercenter_db_pool_connections; do
  if ! grep -q "^$family" <<<"$metrics_body"; then
    echo "metric family missing from the scrape: $family" >&2
    exit 1
  fi
done
grep -E '^usercenter_(dependency_up|db_pool_connections|schema_migrations_applied)' <<<"$metrics_body" | tee "$WORK/metrics.txt"

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
