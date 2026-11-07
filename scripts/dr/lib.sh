#!/usr/bin/env bash
# Shared helpers for the disaster-recovery drills (V2.5 S13).
#
# The drills exist because docs/operations.md described backup and upgrade
# procedures that had never been executed. A procedure nobody has run is a
# guess; the scripts here make the guess falsifiable and keep it that way.
#
# Sourced, never executed directly.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$ROOT/deployments/docker-compose/docker-compose.yml}"
SMOKE_USER="${SMOKE_USER:-root}"
SMOKE_PASSWORD="${SMOKE_PASSWORD:-ChangeMe-12345}"
# Exported because the seed helper hands them to python via the environment
# rather than interpolating them into a shell string (a password with quotes
# would break the JSON otherwise).
export SMOKE_USER SMOKE_PASSWORD

# Marks every line of drill output so timings can be extracted afterwards and
# to make it obvious in a transcript that this is a rehearsal, not production.
step() { printf '\n== [%s] %s\n' "$(date -u +%H:%M:%SZ)" "$*"; }
info() { printf '   %s\n' "$*"; }

now_ms() {
  if date +%s%3N >/dev/null 2>&1 && [[ "$(date +%s%3N)" =~ ^[0-9]+$ ]]; then
    date +%s%3N
  else
    python3 -c 'import time; print(int(time.time()*1000))'
  fi
}

# elapsed_ms prints "$((end-start))" without leaking subshell state.
elapsed_ms() { echo $(( $2 - $1 )); }

compose() { docker compose --env-file "$COMPOSE_ENV" -p "$PROJECT" -f "$COMPOSE_FILE" "$@"; }

# write_env generates throwaway secrets. COOKIE_SECURE=false because the drills
# talk plain http to 127.0.0.1; OIDC_ISSUER must still be https because the
# driver rejects loopback-http issuers.
write_env() {
  local dir="$1"
  local secrets="$dir/secrets"
  mkdir -p "$secrets"
  chmod 700 "$secrets"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$secrets/oidc.pem" 2>/dev/null
  # 0444 inside a 0700 directory: the container runs as a non-root user and a
  # 0600 bind mount is unreadable there (this failed the first real CI run).
  chmod 444 "$secrets/oidc.pem"
  COMPOSE_ENV="$dir/compose.env"
  export COMPOSE_ENV
  {
    printf 'MYSQL_PASSWORD=%s\n' "$(openssl rand -hex 16)"
    printf 'MYSQL_ROOT_PASSWORD=%s\n' "$(openssl rand -hex 16)"
    printf 'SESSION_SECRET=%s\n' "$(openssl rand -base64 48 | tr -d '\n')"
    printf 'CSRF_SECRET=%s\n' "$(openssl rand -base64 48 | tr -d '\n')"
    printf 'MFA_ENCRYPTION_KEY=%s\n' "$(openssl rand -base64 48 | tr -d '\n')"
    printf 'COOKIE_SECURE=false\n'
    printf 'PUBLIC_BASE_URL=http://127.0.0.1:8080\n'
    printf 'OIDC_ISSUER=https://drill.local\n'
    printf 'OIDC_SIGNING_KEY_FILE=%s/oidc.pem\n' "$secrets"
  } >"$COMPOSE_ENV"
  chmod 600 "$COMPOSE_ENV"
  MYSQL_PASSWORD="$(sed -n 's/^MYSQL_PASSWORD=//p' "$COMPOSE_ENV")"
  export MYSQL_PASSWORD
}

# env_value reads one key from the generated env file.
env_value() { sed -n "s/^$1=//p" "$COMPOSE_ENV"; }

# mysql_exec runs SQL as the application user. -N -B keeps the output parseable.
mysql_exec() { compose exec -T mysql mysql -uusercenter -p"$MYSQL_PASSWORD" usercenter -N -B -e "$1"; }

# wait_ready polls /readyz, the endpoint that actually verifies MySQL. Polling
# /healthz here would report success against a dead database -- that is the bug
# the restore drill found and /readyz exists to fix.
#
# The body is checked, not just the status code: releases before S13 do not have
# /readyz and their SPA fallback answers 200 with index.html for any unknown
# path. A status-only check would pass against that HTML and claim the old
# version is "ready" when it never answered a readiness probe at all.
wait_ready() {
  local budget="${1:-90}"
  for _ in $(seq 1 "$budget"); do
    if curl -fsS --max-time 3 http://127.0.0.1:8080/readyz 2>/dev/null \
      | grep -q '"status":"ok"'; then
      return 0
    fi
    sleep 2
  done
  return 1
}

# wait_legacy_ready polls a release that predates /readyz (v0.6.1 and anything
# else without the endpoint). Liveness plus a real database query is the closest
# honest equivalent: the process is up and the schema is reachable.
wait_legacy_ready() {
  local budget="${1:-90}"
  for _ in $(seq 1 "$budget"); do
    if curl -fsS --max-time 3 http://127.0.0.1:8080/healthz 2>/dev/null \
      | grep -q '"status":"ok"' \
      && mysql_exec "SELECT COUNT(*) FROM schema_migrations;" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  return 1
}

# wait_migrate waits for the one-shot migrate service and returns its exit code.
wait_migrate() {
  local id status
  id="$(compose ps -a -q migrate)"
  if [[ -z "$id" ]]; then
    echo "migrate container not found" >&2
    compose ps -a >&2
    return 1
  fi
  status="$(docker wait "$id")"
  compose logs --no-color migrate
  return "$status"
}

# bootstrap_account creates the password-only smoke account and turns off the
# admin MFA requirement. This is a throwaway stack; MFA itself is covered by the
# Go suite. Both steps are idempotent, so a drill can re-run them.
bootstrap_account() {
  compose exec -T user-center /app/admin-rescue -config /app/configs/config.docker.yaml \
    -action bootstrap -username "$SMOKE_USER" -email root@example.com -password "$SMOKE_PASSWORD" >/dev/null
  mysql_exec "INSERT INTO auth_settings (name,value,revision,updated_at)
    VALUES ('auth','{\"MFARequiredForAdmins\":false}',1,UTC_TIMESTAMP(3))
    ON DUPLICATE KEY UPDATE value=VALUES(value);" >/dev/null
}

# seed_workload writes data through the running service so the dump contains
# rows produced by the real write path (a dump of an empty database proves
# nothing about a restore).
#
# It needs a session cookie, so it goes through smoke.sh's login flow shape
# rather than the database: the point is that the data survives, including the
# audit rows the service generated.
seed_workload() {
  local tag="$1"
  local jar body csrf status code
  jar="$(mktemp)"
  body="$(mktemp)"
  curl -sS -c "$jar" -o /dev/null http://127.0.0.1:8080/api/v1/auth/context
  csrf="$(awk '$6=="uc_csrf"{print $7}' "$jar")"
  python3 -c 'import json,os; print(json.dumps({"username":os.environ["SMOKE_USER"],"password":os.environ["SMOKE_PASSWORD"]}))' \
    >"$body.login"
  status="$(curl -sS -b "$jar" -c "$jar" -o "$body" -w '%{http_code}' \
    -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' \
    --data-binary "@$body.login" http://127.0.0.1:8080/api/v1/auth/login)"
  [[ "$status" == "200" ]] || { echo "seed login failed: $status" >&2; cat "$body" >&2; return 1; }
  rm -f "$body.login"

  # A step-up proof is required before tenant creation; the drill reuses the
  # same password proof the smoke test uses.
  status="$(curl -sS -b "$jar" -c "$jar" -o "$body" -w '%{http_code}' \
    -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' \
    --data "{\"current_password\":\"$SMOKE_PASSWORD\"}" \
    http://127.0.0.1:8080/api/v1/me/security:verify)"
  [[ "$status" == "200" ]] || { echo "seed step-up failed: $status" >&2; cat "$body" >&2; return 1; }

  code="drill-$(printf '%s' "$tag" | tr -cd 'a-z0-9-' | cut -c1-24)"
  status="$(curl -sS -b "$jar" -c "$jar" -o "$body" -w '%{http_code}' \
    -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' \
    --data "{\"code\":\"$code\",\"name\":\"Drill $tag\"}" http://127.0.0.1:8080/api/v1/orgs)"
  rm -f "$jar" "$body"
  if [[ "$status" != "200" ]]; then
    echo "seed organization failed: $status" >&2
    return 1
  fi
  return 0
}

# fingerprint prints the row counts that must survive a restore, plus the
# maximum id where a surrogate key exists. Counts alone can match while the
# newest rows are missing (a dump truncated mid-table), so the high-water mark
# is the assertion that actually catches a partial restore.
#
# iam_audit_events and event_outbox use a string primary key (event_id), so they
# contribute a count only: their "latest row" needs created_at, which would make
# this query depend on each table's column names for little extra signal.
fingerprint() {
  # Built dynamically: a drill that starts on v0.6.1 must not query a table that
  # only exists after 012, and a hardcoded list would silently stop covering
  # tables added later. Tables absent from this schema are skipped rather than
  # reported as zero, because "0 rows" and "no such table" are different facts.
  local parts=()
  local spec tbl col
  for spec in \
    "users:id" \
    "user_credentials:user_id" \
    "organizations:id" \
    "organization_members:id" \
    "iam_sessions:id" \
    "iam_roles:id" \
    "password_history:id" \
    "user_oauth_identities:id"; do
    tbl="${spec%%:*}"
    col="${spec##*:}"
    if [[ "$(mysql_exec "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='usercenter' AND table_name='$tbl';")" == "1" ]]; then
      parts+=("SELECT '$tbl', COUNT(*), COALESCE(MAX($col),0) FROM $tbl")
    fi
  done
  # String-keyed tables: count only.
  for tbl in iam_audit_events event_outbox schema_migrations; do
    if [[ "$(mysql_exec "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='usercenter' AND table_name='$tbl';")" == "1" ]]; then
      parts+=("SELECT '$tbl', COUNT(*), 0 FROM $tbl")
    fi
  done
  local joined
  joined="$(printf '%s\n' "${parts[@]}" | paste -sd'|' - | sed 's/|/ UNION ALL /g')"
  mysql_exec "$joined"
}

# volatile_note documents what the fingerprint deliberately does not assert.
volatile_note() {
  info "note: session rows may differ in last_seen_at; counts are what is asserted"
}
