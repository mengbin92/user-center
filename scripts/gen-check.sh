#!/usr/bin/env bash
# Verify that committed generated code matches its proto/wire sources.
#
# Requires buf and wire in PATH. Runs make api / make config / make wire and
# fails when the regenerated output differs from what is committed.
#
# Exit codes:
#   0  generated code is up to date
#   1  generated code is stale (regenerate and commit)
#   2  cannot run (dirty working tree or missing toolchain)
set -euo pipefail
cd "$(dirname "$0")/.."

for tool in buf wire; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "gen-check: $tool not found in PATH" >&2
    exit 2
  fi
done

# A dirty tree makes the post-generation diff meaningless.
if [[ -n "$(git status --porcelain)" ]]; then
  echo "gen-check: working tree is dirty; commit or stash before verifying generated code" >&2
  exit 2
fi

make api >/dev/null
make config >/dev/null
make wire >/dev/null

if [[ -n "$(git status --porcelain)" ]]; then
  echo "gen-check: generated code is out of date. Run make api / make config / make wire and commit the result." >&2
  git status --porcelain >&2
  git --no-pager diff --stat >&2 || true
  exit 1
fi

echo "gen-check: generated code is up to date"
