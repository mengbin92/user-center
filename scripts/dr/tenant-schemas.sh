#!/usr/bin/env bash
# List and back up every per-organization tenant schema.
#
# The platform backup alone is incomplete once tenant isolation is enabled: an
# organization's members, roles, delegations and audit rows live in
# usercenter_org_<id>. This script enumerates the registry and dumps each
# schema, so a restore drill can verify the registry matches the files.
#
# Usage:
#   MYSQL_HOST=... MYSQL_USER=... MYSQL_PWD=... ./scripts/dr/tenant-schemas.sh list
#   MYSQL_HOST=... MYSQL_USER=... MYSQL_PWD=... ./scripts/dr/tenant-schemas.sh backup /backups
set -euo pipefail

MYSQL_HOST="${MYSQL_HOST:-127.0.0.1}"
MYSQL_PORT="${MYSQL_PORT:-3306}"
MYSQL_USER="${MYSQL_USER:-root}"
PLATFORM_DB="${PLATFORM_DB:-usercenter}"
MYSQL_BIN="${MYSQL_BIN:-mysql}"
DUMP_BIN="${DUMP_BIN:-mysqldump}"
PREFIX="${TENANT_SCHEMA_PREFIX:-usercenter_org_}"

mysql_cmd() {
  "$MYSQL_BIN" -h"$MYSQL_HOST" -P"$MYSQL_PORT" -u"$MYSQL_USER" --batch --skip-column-names "$@"
}

schemas() {
  # Prefer the registry: it is the authoritative list the router uses. Fall
  # back to SHOW DATABASES so a dangling database is still discovered.
  local from_registry
  from_registry="$(mysql_cmd "$PLATFORM_DB" -e \
    "SELECT schema_name FROM tenant_schemas WHERE status='ready' ORDER BY organization_id" 2>/dev/null || true)"
  if [[ -n "$from_registry" ]]; then
    printf '%s\n' "$from_registry"
  else
    mysql_cmd -e "SHOW DATABASES LIKE '${PREFIX}%'" | sed 's/`//g'
  fi
}

case "${1:-list}" in
  list)
    schemas
    ;;
  backup)
    out="${2:?usage: tenant-schemas.sh backup <dir>}"
    mkdir -p "$out"
    count=0
    while IFS= read -r schema; do
      [[ -z "$schema" ]] && continue
      "$DUMP_BIN" -h"$MYSQL_HOST" -P"$MYSQL_PORT" -u"$MYSQL_USER" \
        --single-transaction --routines --triggers "$schema" > "$out/$schema.sql"
      count=$((count + 1))
      printf 'dumped %s\n' "$schema"
    done < <(schemas)
    printf 'tenant schemas backed up: %d\n' "$count"
    ;;
  *)
    printf 'usage: %s [list|backup <dir>]\n' "$0" >&2
    exit 2
    ;;
esac
