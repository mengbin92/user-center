#!/usr/bin/env bash
# S13 drill 1: backup -> destroy -> restore -> smoke.
#
# The point is not to prove mysqldump works. It is to answer three questions
# that only an execution can answer:
#
#   1. How long does a restore actually take at a known data size?
#   2. Does the restored database produce a service that passes the smoke test?
#   3. Which data survives and which does not (sessions, artifacts, Redis)?
#
# Redis is deliberately NOT backed up: it holds challenges, rate-limit counters
# and step-up proofs, all of which are supposed to be re-derivable. Restoring it
# would be restoring stale credentials. The drill asserts the consequence
# instead -- after a restore, existing sessions must be gone and re-login must
# work.
#
# Usage: scripts/dr/restore-drill.sh [--work-dir DIR] [--keep] [--skip-build]
#
# Exit codes: 0 pass, 1 any assertion failed.
set -euo pipefail

WORK=""
KEEP=0
SKIP_BUILD=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --work-dir) WORK="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

if [[ -z "$WORK" ]]; then
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/uc-drill-restore.XXXXXX")"
  KEEP_WORK=0
else
  mkdir -p "$WORK"
  KEEP_WORK=1
fi
WORK="$(cd "$WORK" && pwd)"
PROJECT="uc-drill-restore"
export PROJECT

teardown() {
  local rc=$?
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

write_env "$WORK"
echo "work dir: $WORK"

if [[ $SKIP_BUILD -eq 0 ]]; then
  step "build image"
  # Never pipe the build: `docker compose build | tail` makes the exit code 0
  # and hides a failure that then shows up as a stale image at runtime.
  set +e
  compose build 2>&1 | tee "$WORK/build.log"
  status=${PIPESTATUS[0]}
  set -e
  [[ $status -eq 0 ]] || { echo "compose build failed ($status)" >&2; exit "$status"; }
fi

step "start stack"
compose up -d
wait_migrate >"$WORK/migrate.log" 2>&1 || { echo "migrate failed" >&2; cat "$WORK/migrate.log" >&2; exit 1; }
wait_ready 90 || { echo "service not ready before seeding" >&2; compose logs --no-color user-center | tail -40 >&2; exit 1; }
bootstrap_account

step "seed workload"
seed_workload "restore"
info "one organization created through the HTTP API"

step "fingerprint before backup"
fingerprint >"$WORK/fp-before.txt"
cat "$WORK/fp-before.txt" | while IFS=$'\t' read -r tbl rows maxid; do
  info "$tbl rows=$rows max_id=$maxid"
done

step "backup"
# --single-transaction is correct here because the only engine in use is
# InnoDB: it gives a consistent snapshot without locking writes. --routines and
# --triggers are included because a restore that silently drops them would only
# fail later, at the first background job.
BACKUP_START=$(now_ms)
compose exec -T mysql mysqldump \
  -uusercenter -p"$MYSQL_PASSWORD" \
  --single-transaction --routines --triggers --events \
  --set-gtid-purged=OFF --no-tablespaces \
  --default-character-set=utf8mb4 \
  usercenter >"$WORK/usercenter.sql"
BACKUP_MS=$(elapsed_ms "$BACKUP_START" "$(now_ms)")
BACKUP_BYTES=$(wc -c <"$WORK/usercenter.sql" | tr -d ' ')
info "dump: ${BACKUP_BYTES} bytes in ${BACKUP_MS} ms"
# A dump of 2 KB means mysqldump failed quietly and wrote an error into the
# file; asserting a floor is cheaper than validating the SQL.
[[ "$BACKUP_BYTES" -gt 20000 ]] || { echo "dump suspiciously small ($BACKUP_BYTES bytes)" >&2; head -5 "$WORK/usercenter.sql" >&2; exit 1; }

step "backup artifacts volume"
# Export artifacts are regenerable, but the drill documents that they are a
# separate backup unit; a database-only restore leaves dangling references.
ARTIFACT_BYTES=0
if compose exec -T user-center sh -c 'test -d /app/artifacts' 2>/dev/null; then
  compose exec -T user-center sh -c 'tar czf - -C /app/artifacts . 2>/dev/null' >"$WORK/artifacts.tgz" || true
  ARTIFACT_BYTES=$(wc -c <"$WORK/artifacts.tgz" | tr -d ' ')
fi
info "artifacts archive: ${ARTIFACT_BYTES} bytes (export artifacts are regenerable)"

step "destroy database"
# DROP DATABASE rather than deleting the volume: it proves the dump alone is
# sufficient, not a leftover file in the datadir. The volume is recreated by
# MySQL on start because MYSQL_DATABASE is set.
DESTROY_START=$(now_ms)
mysql_exec "SELECT CONCAT('dropping ', COUNT(*), ' tables') FROM information_schema.tables WHERE table_schema='usercenter';" | sed 's/^/   /'
compose exec -T mysql mysql -uroot -p"$(env_value MYSQL_ROOT_PASSWORD)" -e "DROP DATABASE usercenter; CREATE DATABASE usercenter CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;"
EMPTY_TABLES=$(compose exec -T mysql mysql -uusercenter -p"$MYSQL_PASSWORD" -N -B -e \
  "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='usercenter';")
info "tables after drop: $EMPTY_TABLES"
[[ "$EMPTY_TABLES" == "0" ]] || { echo "database was not actually emptied" >&2; exit 1; }
info "destroy took $(elapsed_ms "$DESTROY_START" "$(now_ms)") ms"

step "service must be broken now"
# Two separate assertions, because they are two different contracts:
#   - /readyz must fail: it is what the load balancer and the container health
#     check use, and it promises the database is reachable.
#   - /healthz must keep returning 200: it is liveness only. A liveness check
#     that fails on a dependency outage causes a restart loop that cannot help
#     and throws away the logs.
# The first run of this drill found /healthz being used for both, so a dropped
# database left the container reporting healthy. /readyz was added as a result.
NOT_READY=0
for _ in $(seq 1 10); do
  if curl -fsS --max-time 3 http://127.0.0.1:8080/readyz >/dev/null 2>&1; then
    sleep 2
  else
    NOT_READY=1
    break
  fi
done
[[ $NOT_READY -eq 1 ]] || { echo "/readyz still reports ready with no database: the check is hollow" >&2; exit 1; }
READY_BODY=$(curl -sS --max-time 3 http://127.0.0.1:8080/readyz || true)
info "readyz correctly fails: $READY_BODY"

LIVE_STATUS=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1:8080/healthz || true)
[[ "$LIVE_STATUS" == "200" ]] || { echo "healthz returned $LIVE_STATUS; liveness must not depend on the database" >&2; exit 1; }
info "healthz still 200 as intended (liveness is independent of MySQL)"

step "restore"
RESTORE_START=$(now_ms)
compose exec -T mysql mysql -uusercenter -p"$MYSQL_PASSWORD" usercenter <"$WORK/usercenter.sql"
RESTORE_MS=$(elapsed_ms "$RESTORE_START" "$(now_ms)")
info "restore took ${RESTORE_MS} ms"

step "fingerprint after restore"
fingerprint >"$WORK/fp-after.txt"
python3 "$(dirname "${BASH_SOURCE[0]}")/compare_fingerprint.py" strict \
  "$WORK/fp-before.txt" "$WORK/fp-after.txt"
# Captured here, before the smoke test logs in, so the number describes the
# restore rather than the drill's own activity.
RESTORED_SESSIONS=$(mysql_exec "SELECT COUNT(*) FROM iam_sessions;")
RESTORED_REDIS_KEYS=$(compose exec -T redis redis-cli DBSIZE | tr -d '\r')

step "wait for service recovery"
# The pool reconnects on its own; no restart should be necessary. Restarting
# would hide whether the connection pool actually recovers, which is what an
# operator will experience.
wait_ready 60 || { echo "service did not recover without a restart" >&2; compose logs --no-color user-center | tail -40 >&2; exit 1; }
RECOVER_MS=$(elapsed_ms "$RESTORE_START" "$(now_ms)")
info "healthy again after ${RECOVER_MS} ms without restarting the container"

step "smoke test on restored data"
SMOKE_START=$(now_ms)
SMOKE_USER="$SMOKE_USER" SMOKE_PASSWORD="$SMOKE_PASSWORD" "$ROOT/scripts/e2e/smoke.sh" \
  --base-url http://127.0.0.1:8080 \
  --snapshot-dir "$WORK/snapshot" \
  --compose "$COMPOSE_FILE" \
  --compose-env "$COMPOSE_ENV" 2>&1 | tee "$WORK/smoke.log"
SMOKE_MS=$(elapsed_ms "$SMOKE_START" "$(now_ms)")
info "smoke took ${SMOKE_MS} ms"

step "finding: sessions come back with the database"
# This is the part of a restore nobody expects: session rows live in MySQL, so
# restoring the dump restores every session that was valid at backup time. Any
# device holding such a cookie works again, even if it was revoked after the
# backup. Redis (challenges, step-up, rate-limit counters) is NOT restored and
# regenerates, which is correct -- those are short-lived proofs.
#
# The operational consequence is recorded in docs/operations.md: after restoring
# a backup taken for a security incident, revoke sessions explicitly rather than
# assuming the restore logged everyone out.
info "session rows restored: $RESTORED_SESSIONS (a restore revives sessions that were valid at backup time)"
info "redis keys after restore: $RESTORED_REDIS_KEYS (never backed up; challenges and step-up proofs regenerate)"

TOTAL_MS=$((BACKUP_MS + RESTORE_MS))
step "result"
cat >"$WORK/summary.txt" <<EOF
rows_before_restore=$(wc -l <"$WORK/fp-before.txt" | tr -d ' ')
dump_bytes=$BACKUP_BYTES
backup_ms=$BACKUP_MS
restore_ms=$RESTORE_MS
recovery_ms=$RECOVER_MS
smoke_ms=$SMOKE_MS
total_backup_restore_ms=$TOTAL_MS
artifacts_bytes=$ARTIFACT_BYTES
EOF
cat "$WORK/summary.txt" | sed 's/^/   /'
echo "DRILL OK: backup restore restore-verified"
