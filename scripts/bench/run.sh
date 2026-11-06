#!/usr/bin/env bash
# Reproducible load baseline for a single instance backed by MySQL 8.4.
#
# What it does, in order: start (or reuse) a mysql:8.4 container, apply the
# migrations, bootstrap the benchmark accounts, start the service, build the
# session pool over the public API, run the k6 scenarios one at a time, and
# print a markdown table. The container is left running so the next run skips
# the cold start; the service process is always stopped on exit.
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT="$(pwd)"

MYSQL_CONTAINER="${MYSQL_CONTAINER:-uc-bench-mysql}"
MYSQL_PORT="${MYSQL_PORT:-3307}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-benchroot}"
DB_NAME="${DB_NAME:-usercenter_bench}"
PREFIX="${PREFIX:-bench}"
ACCOUNTS="${ACCOUNTS:-24}"
PASSWORD="${PASSWORD:-BenchPass-12345}"
VUS="${VUS:-16}"
DURATION="${DURATION:-30s}"
SCENARIOS="${SCENARIOS:-context,me,admin,org,login}"
HTTP_PORT="${HTTP_PORT:-18080}"
GRPC_PORT="${GRPC_PORT:-19090}"
KEEP=0

usage() {
  cat <<'USAGE'
Usage: scripts/bench/run.sh [options]
  --vu N              virtual users for read scenarios (default 16)
  --duration D        read scenario duration (default 30s)
  --scenarios LIST    comma separated: context,me,admin,org,login
  --accounts N        session pool size, max 28 (login is capped at 30/5min)
  --http-port PORT    service port (default 18080)
  --out DIR           result directory (default artifacts/bench-<stamp>)
  --keep              keep the temporary server log and sqlite-free work dir
  -h, --help          show this help

Environment: MYSQL_PORT, MYSQL_PASSWORD, DB_NAME, PREFIX, PASSWORD, VUS,
DURATION, SCENARIOS, HTTP_PORT. Requires docker, k6, go and python3.
USAGE
}

OUT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vu) VUS="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --scenarios) SCENARIOS="$2"; shift 2 ;;
    --accounts) ACCOUNTS="$2"; shift 2 ;;
    --http-port) HTTP_PORT="$2"; shift 2 ;;
    --out) OUT_DIR="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ "$ACCOUNTS" -gt 28 ]]; then
  echo "accounts is capped at 28: the login endpoint allows 30 attempts per 5 minutes per IP" >&2
  exit 2
fi

BASE_URL="http://127.0.0.1:${HTTP_PORT}"
CONFIG="scripts/bench/config.mysql.yaml"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="${OUT_DIR:-$ROOT/artifacts/bench-$STAMP}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/user-center-bench.XXXXXX")"
SESSIONS="$WORK/sessions.json"
SERVER_PID=""

cleanup() {
  local rc=$?
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  if [[ $rc -ne 0 && -f "$WORK/server.log" ]]; then
    mkdir -p "$OUT_DIR"
    cp "$WORK/server.log" "$OUT_DIR/server.log" 2>/dev/null || true
    tail -20 "$WORK/server.log" >&2 || true
  fi
  if [[ $KEEP -eq 0 ]]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }

step "mysql $MYSQL_CONTAINER (port $MYSQL_PORT)"
if ! docker ps -a --format '{{.Names}}' | grep -qx "$MYSQL_CONTAINER"; then
  docker run -d --name "$MYSQL_CONTAINER" \
    -e MYSQL_ROOT_PASSWORD="$MYSQL_PASSWORD" -e MYSQL_DATABASE="$DB_NAME" \
    -p "${MYSQL_PORT}:3306" mysql:8.4 >/dev/null
elif ! docker ps --format '{{.Names}}' | grep -qx "$MYSQL_CONTAINER"; then
  docker start "$MYSQL_CONTAINER" >/dev/null
fi
mysql_ready=0
for _ in $(seq 1 90); do
  if docker exec "$MYSQL_CONTAINER" mysqladmin ping -h 127.0.0.1 -uroot -p"$MYSQL_PASSWORD" --silent >/dev/null 2>&1; then
    mysql_ready=1
    break
  fi
  sleep 1
done
if [[ $mysql_ready -ne 1 ]]; then
  echo "mysql did not become ready" >&2
  exit 1
fi

export DB_DRIVER=mysql
export DB_DSN="root:${MYSQL_PASSWORD}@tcp(127.0.0.1:${MYSQL_PORT})/${DB_NAME}?parseTime=true&loc=UTC&charset=utf8mb4"
export HTTP_ADDR="127.0.0.1:${HTTP_PORT}"
export GRPC_ADDR="127.0.0.1:${GRPC_PORT}"
export METRICS_ADDR=off           # keep scrape overhead out of the baseline
export ALLOW_INSECURE_DEV=1       # dev config secrets, local instance only
# data.NewData enforces >=32 byte secrets whenever the driver is MySQL (the
# dev yaml values are shorter), so the benchmark supplies its own throwaway ones.
export SESSION_SECRET="bench-session-secret-0123456789abcdef"
export CSRF_SECRET="bench-csrf-secret-0123456789abcdef"
export MFA_ENCRYPTION_KEY="bench-mfa-encryption-key-0123456789abcdef"
# MySQL is not the dev mode, so the signer insists on a real RSA key and an
# https issuer. Neither is exercised by the scenarios; the key only has to be
# stable for the duration of the run.
export OIDC_ISSUER="https://bench.local"
if [[ ! -f "$WORK/oidc.pem" ]]; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$WORK/oidc.pem" >/dev/null 2>&1
fi
export OIDC_SIGNING_KEY_PATH="$WORK/oidc.pem"

step "build binaries"
mkdir -p "$WORK/bin"
for cmd in user-center migrate admin-rescue; do
  go build -o "$WORK/bin/$cmd" "./cmd/$cmd"
done

step "migrate"
"$WORK/bin/migrate" -config "$CONFIG" >"$WORK/migrate.log" 2>&1 || {
  tail -20 "$WORK/migrate.log" >&2
  exit 1
}

step "fixtures: disable the admin MFA requirement"
# The bench accounts are root and root must enrol TOTP before /admin/* opens.
# The scenarios measure query cost, so the gate is switched off in this
# throwaway database; without it every admin request is a 403.
docker exec -i -e MYSQL_PWD="$MYSQL_PASSWORD" "$MYSQL_CONTAINER" \
  mysql -uroot "$DB_NAME" >/dev/null <<'SQL'
INSERT INTO auth_settings (name, value, revision, updated_at)
VALUES ('auth', '{"MFARequiredForAdmins":false}', 1, UTC_TIMESTAMP(3))
ON DUPLICATE KEY UPDATE value = JSON_SET(value, '$.MFARequiredForAdmins', false),
                        revision = revision + 1;
SQL

step "bootstrap $ACCOUNTS accounts"
created=0
for i in $(seq 1 "$ACCOUNTS"); do
  name=$(printf '%s%02d' "$PREFIX" "$i")
  if "$WORK/bin/admin-rescue" -config "$CONFIG" -action bootstrap \
      -username "$name" -password "$PASSWORD" -email "${name}@bench.local" \
      >/dev/null 2>"$WORK/rescue.err"; then
    created=$((created + 1))
  elif ! grep -qi "already exists" "$WORK/rescue.err"; then
    cat "$WORK/rescue.err" >&2
    exit 1
  fi
done
echo "   new accounts: $created (existing reused)"

step "start service on $BASE_URL"
"$WORK/bin/user-center" -config "$CONFIG" >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
ready=0
for _ in $(seq 1 60); do
  if curl -fsS "$BASE_URL/healthz" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.5
done
if [[ $ready -ne 1 ]]; then
  echo "service did not become ready" >&2
  exit 1
fi

step "prepare sessions and organization"
# The login endpoint allows 30 attempts per 5 minutes per IP, so a fresh 24
# account pool cannot be built on every invocation. Reuse a recent pool, but
# only for half of the service's idle timeout (60 min by default): past that the
# sessions are rejected and every scenario silently turns into 401s.
CACHE_DIR="${BENCH_CACHE:-$ROOT/artifacts/.bench-cache}"
SESSIONS_CACHE="$CACHE_DIR/sessions.json"
ORG_CACHE="$CACHE_DIR/org_id"
POOL_MAX_AGE="${POOL_MAX_AGE:-1800}"
pool_age() {
  python3 -c 'import os,sys,time; print(int(time.time()-os.path.getmtime(sys.argv[1])))' "$1" 2>/dev/null || echo 999999
}
if [[ -s "$SESSIONS_CACHE" && -s "$ORG_CACHE" ]] && [[ "$(pool_age "$SESSIONS_CACHE")" -lt "$POOL_MAX_AGE" ]]; then
  cp "$SESSIONS_CACHE" "$SESSIONS"
  ORG_ID="$(cat "$ORG_CACHE")"
  echo "   reused session pool (age $(pool_age "$SESSIONS_CACHE")s), org_id=$ORG_ID"
else
  FIXTURES=$(python3 scripts/bench/prepare.py \
    --base-url "$BASE_URL" --prefix "$PREFIX" --accounts "$ACCOUNTS" \
    --password "$PASSWORD" --org-code bench --sessions-out "$SESSIONS")
  ORG_ID=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["org_id"])' "$FIXTURES")
  mkdir -p "$CACHE_DIR"
  cp "$SESSIONS" "$SESSIONS_CACHE"
  echo "$ORG_ID" >"$ORG_CACHE"
  echo "   built session pool: org_id=$ORG_ID sessions=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["sessions"])' "$FIXTURES")"
fi

mkdir -p "$OUT_DIR"

run_scenario() {
  local name="$1" script vus duration log rc
  case "$name" in
    context|login)
      script="scripts/bench/k6/login.js"
      vus="$VUS"
      if [[ "$vus" -gt 8 ]]; then vus=8; fi
      duration="20s"
      ;;
    me|admin|org)
      script="scripts/bench/k6/read.js"
      vus="$VUS"
      duration="$DURATION"
      ;;
    *)
      echo "unknown scenario: $name" >&2
      return 1
      ;;
  esac
  log="$OUT_DIR/${name}.log"
  rm -f "$OUT_DIR/${name}.json"
  echo "   $name: vus=$vus duration=$duration"
  set +e
  k6 run --quiet \
    -e BASE_URL="$BASE_URL" -e SCENARIO="$name" -e VUS="$vus" -e DURATION="$duration" \
    -e SESSIONS_FILE="$SESSIONS" -e ORG_ID="$ORG_ID" \
    -e PREFIX="$PREFIX" -e PASSWORD="$PASSWORD" -e POOL="$ACCOUNTS" \
    -e USER="${PREFIX}01" -e RESULT_FILE="$OUT_DIR/${name}.json" \
    "$script" >"$log" 2>&1
  rc=$?
  set -e
  # 99 means a threshold was crossed; keep the numbers either way.
  if [[ $rc -ne 0 && $rc -ne 99 ]]; then
    echo "k6 failed for $name (exit $rc)" >&2
    tail -20 "$log" >&2
    return 1
  fi
  # A read scenario with failures is not a baseline: an expired session pool
  # otherwise reports thousands of 401s as if they were throughput.
  if [[ "$name" != "login" ]]; then
    if ! python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1]))["failed_pct"] < 0.01 else 1)' "$OUT_DIR/${name}.json" 2>/dev/null; then
      echo "scenario $name reported failures; refusing to record it as a baseline" >&2
      echo "  hint: delete $CACHE_DIR and rerun to rebuild the session pool" >&2
      return 1
    fi
  fi
}

step "run scenarios: $SCENARIOS"
IFS=',' read -r -a scenario_list <<<"$SCENARIOS"
for scenario in "${scenario_list[@]}"; do
  run_scenario "$scenario"
done

step "results"
python3 scripts/bench/summarise.py "$OUT_DIR" | tee "$OUT_DIR/summary.md"

echo
echo "raw logs: $OUT_DIR"
echo "mysql container left running as $MYSQL_CONTAINER (docker rm -f $MYSQL_CONTAINER to remove)"
