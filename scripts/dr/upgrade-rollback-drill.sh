#!/usr/bin/env bash
# S13 drill 2: upgrade v0.6.1 -> current, then roll back.
#
# The roadmap asked a narrow question -- "can we roll back to the old image and
# the old schema after a failed upgrade" -- and the honest answer needs the
# migration inventory, not an opinion. This script performs the upgrade for
# real, then performs the rollback for real (stop, restore the pre-upgrade dump,
# run the old image), and reports the two things an operator must know:
#
#   - time to upgrade, and whether the new version serves requests afterwards
#   - whether the old binary still serves requests against the restored schema
#
# It also records what CANNOT be rolled back, derived from the migration files
# rather than assumed: every migration that drops or narrows something is
# listed, because those are the steps where restoring the dump is mandatory and
# replaying is not an option.
#
# Usage: scripts/dr/upgrade-rollback-drill.sh [--work-dir DIR] [--keep]
#
# Requires: user-center:v0.6.1 already built (see the note printed on failure).
set -euo pipefail

WORK=""
KEEP=0
OLD_TAG="${OLD_TAG:-v0.6.1}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --work-dir) WORK="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

if [[ -z "$WORK" ]]; then
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/uc-drill-upgrade.XXXXXX")"
  KEEP_WORK=0
else
  mkdir -p "$WORK"
  KEEP_WORK=1
fi
WORK="$(cd "$WORK" && pwd)"
PROJECT="uc-drill-upgrade"
export PROJECT

if ! docker image inspect "user-center:${OLD_TAG}" >/dev/null 2>&1; then
  cat >&2 <<EOF
missing image user-center:${OLD_TAG}
build it from a worktree of that tag first:
  git worktree add --detach /tmp/uc-${OLD_TAG} ${OLD_TAG}
  (cd /tmp/uc-${OLD_TAG} && docker build -t user-center:${OLD_TAG} .)
EOF
  exit 1
fi

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

step "migration inventory: what cannot be replayed backwards"
# Derived from the files, not hardcoded: if a future migration adds a DROP, this
# table picks it up and the rollback advice stays accurate.
DESTRUCTIVE=$(grep -nE 'DROP TABLE|DROP COLUMN|MODIFY COLUMN|CHANGE COLUMN|DROP INDEX|RENAME COLUMN' \
  "$ROOT"/migrations/mysql/*.sql | sed "s#$ROOT/##" || true)
if [[ -z "$DESTRUCTIVE" ]]; then
  info "no destructive DDL in 001..$(ls "$ROOT"/migrations/mysql/*.sql | wc -l | tr -d ' ')"
else
  echo "$DESTRUCTIVE" | while IFS= read -r line; do info "$line"; done
  info "each line above is a step that CANNOT be undone by replaying migrations;"
  info "rollback after it requires restoring the pre-upgrade dump."
fi
MIGRATION_COUNT=$(ls "$ROOT"/migrations/mysql/*.sql | wc -l | tr -d ' ')
info "current release ships $MIGRATION_COUNT migration files"

step "start OLD stack ($OLD_TAG)"
# The compose file is the current one (it is the deployment contract), but the
# image is pinned back. Using the old compose file instead would hide whether
# the new deployment manifest works with the old binary -- and it is the
# manifest that operators actually roll back together with the image.
USER_CENTER_IMAGE="user-center:${OLD_TAG}" compose up -d
wait_migrate >"$WORK/migrate-old.log" 2>&1 || { echo "old migrate failed" >&2; cat "$WORK/migrate-old.log" >&2; exit 1; }
wait_legacy_ready 90 || { echo "old stack not ready" >&2; compose logs --no-color user-center | tail -40 >&2; exit 1; }
bootstrap_account
OLD_SCHEMA=$(mysql_exec "SELECT COUNT(*) FROM schema_migrations;")
info "old release applied $OLD_SCHEMA migration steps"
info "old version: $(curl -sS http://127.0.0.1:8080/api/v1/auth/context | head -c 120)"

step "seed data on the old version"
seed_workload "upgrade"
fingerprint >"$WORK/fp-old.txt"
info "seed data written; fingerprint captured"

step "backup before upgrade"
# This dump is the rollback artifact. Without it, rolling back means replaying a
# schema backwards, which the inventory above shows is not generally possible.
BACKUP_START=$(now_ms)
compose exec -T mysql mysqldump -uusercenter -p"$MYSQL_PASSWORD" \
  --single-transaction --routines --triggers --events \
  --set-gtid-purged=OFF --no-tablespaces --default-character-set=utf8mb4 \
  usercenter >"$WORK/pre-upgrade.sql"
BACKUP_MS=$(elapsed_ms "$BACKUP_START" "$(now_ms)")
info "pre-upgrade dump: $(wc -c <"$WORK/pre-upgrade.sql" | tr -d ' ') bytes in ${BACKUP_MS} ms"

step "upgrade: run NEW migrate against the OLD data"
UPGRADE_START=$(now_ms)
USER_CENTER_IMAGE="user-center:latest" compose run --rm --no-deps -T migrate 2>&1 | tee "$WORK/migrate-up.log"
MIGRATE_MS=$(elapsed_ms "$UPGRADE_START" "$(now_ms)")
NEW_SCHEMA=$(mysql_exec "SELECT COUNT(*) FROM schema_migrations;")
info "migrations applied: $OLD_SCHEMA -> $NEW_SCHEMA (${MIGRATE_MS} ms)"
[[ "$NEW_SCHEMA" -gt "$OLD_SCHEMA" ]] || { echo "upgrade applied no migrations" >&2; exit 1; }

step "start NEW service against the upgraded schema"
USER_CENTER_IMAGE="user-center:latest" compose up -d --no-deps user-center
NEW_READY_START=$(now_ms)
wait_ready 90 || { echo "new version not ready" >&2; compose logs --no-color user-center | tail -40 >&2; exit 1; }
info "new version ready in $(elapsed_ms "$NEW_READY_START" "$(now_ms)") ms"

step "smoke on the new version"
SMOKE_USER="$SMOKE_USER" SMOKE_PASSWORD="$SMOKE_PASSWORD" "$ROOT/scripts/e2e/smoke.sh" \
  --base-url http://127.0.0.1:8080 --snapshot-dir "$WORK/snapshot-up" \
  --compose "$COMPOSE_FILE" --compose-env "$COMPOSE_ENV" 2>&1 | tee "$WORK/smoke-up.log"

step "no data lost by the upgrade"
fingerprint >"$WORK/fp-upgraded.txt"
# The upgrade must not DELETE anything, but counts may grow: the smoke test that
# just ran created an organization (plus its built-in roles, member, audit and
# outbox rows). Equality is asserted after the rollback instead, where the
# pre-upgrade dump is the reference.
python3 "$(dirname "${BASH_SOURCE[0]}")/compare_fingerprint.py" no-loss \
  "$WORK/fp-old.txt" "$WORK/fp-upgraded.txt"

step "ROLLBACK: restore pre-upgrade dump and start the OLD image"
# Order matters and is the part docs never stated: the old binary cannot read
# columns it does not know about only if they are NOT NULL without defaults, but
# it also cannot cope with a schema that is ahead of it in general (the ORM
# selects explicit column lists only for known models; migrations 012/013 add
# nullable/defaulted columns, so the old binary would in fact still run -- but
# relying on that is a coincidence, not a contract). Restoring first is the
# only sequence that is guaranteed correct.
ROLLBACK_START=$(now_ms)
compose stop user-center >/dev/null
info "service stopped"

compose exec -T mysql mysql -uroot -p"$(env_value MYSQL_ROOT_PASSWORD)" -e \
  "DROP DATABASE usercenter; CREATE DATABASE usercenter CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;"
compose exec -T mysql mysql -uusercenter -p"$MYSQL_PASSWORD" usercenter <"$WORK/pre-upgrade.sql"
ROLLBACK_DB_MS=$(elapsed_ms "$ROLLBACK_START" "$(now_ms)")
RESTORED_SCHEMA=$(mysql_exec "SELECT COUNT(*) FROM schema_migrations;")
info "schema after restore: $RESTORED_SCHEMA steps (expected $OLD_SCHEMA)"
[[ "$RESTORED_SCHEMA" == "$OLD_SCHEMA" ]] || { echo "restore did not return to the old schema version" >&2; exit 1; }

USER_CENTER_IMAGE="user-center:${OLD_TAG}" compose up -d --no-deps user-center
wait_legacy_ready 90 || { echo "rolled-back version not ready" >&2; compose logs --no-color user-center | tail -40 >&2; exit 1; }
ROLLBACK_MS=$(elapsed_ms "$ROLLBACK_START" "$(now_ms)")
info "rollback complete in ${ROLLBACK_MS} ms (database restore ${ROLLBACK_DB_MS} ms)"

step "data restored exactly (before any drill traffic)"
# Ordered before the smoke test: the smoke run logs in and creates an
# organization, which would make a strict comparison fail on the drill's own
# writes. Here the pre-upgrade dump is the reference and nothing else has
# touched the database since the restore.
fingerprint >"$WORK/fp-rolledback.txt"
python3 "$(dirname "${BASH_SOURCE[0]}")/compare_fingerprint.py" strict \
  "$WORK/fp-old.txt" "$WORK/fp-rolledback.txt"

step "smoke on the rolled-back version"
SMOKE_USER="$SMOKE_USER" SMOKE_PASSWORD="$SMOKE_PASSWORD" "$ROOT/scripts/e2e/smoke.sh" \
  --base-url http://127.0.0.1:8080 --snapshot-dir "$WORK/snapshot-down" \
  --skip-readyz \
  --compose "$COMPOSE_FILE" --compose-env "$COMPOSE_ENV" 2>&1 | tee "$WORK/smoke-down.log"

TOTAL_UP=$((BACKUP_MS + MIGRATE_MS))
step "result"
cat >"$WORK/summary.txt" <<EOF
old_tag=$OLD_TAG
old_schema_steps=$OLD_SCHEMA
new_schema_steps=$NEW_SCHEMA
pre_upgrade_dump_ms=$BACKUP_MS
migrate_ms=$MIGRATE_MS
rollback_total_ms=$ROLLBACK_MS
rollback_db_restore_ms=$ROLLBACK_DB_MS
upgrade_without_backup_ms=$TOTAL_UP
destructive_ddl_count=$(printf '%s' "$DESTRUCTIVE" | grep -c . || true)
EOF
cat "$WORK/summary.txt" | sed 's/^/   /'
echo "DRILL OK: upgrade-and-rollback"
