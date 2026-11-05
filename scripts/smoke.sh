#!/usr/bin/env bash
# Compatibility wrapper: the maintained E2E smoke test lives in scripts/e2e/.
set -euo pipefail
exec "$(dirname "$0")/e2e/smoke.sh" "$@"
