#!/usr/bin/env bash
# authority.sh — run the grant-authority service (scripts/grant-authority.mjs)
# with lane wiring from the environment and the coordinator operator token
# from doppler (canopy/dev) unless already provided. See grant-authority.mjs.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -z "${COORDINATOR_APP_TOKEN:-}" ]; then
  COORDINATOR_APP_TOKEN=$(doppler secrets get COORDINATOR_APP_TOKEN \
    --project canopy --config dev --plain 2>/dev/null || true)
  export COORDINATOR_APP_TOKEN
  [ -n "$COORDINATOR_APP_TOKEN" ] || \
    echo "authority.sh: no COORDINATOR_APP_TOKEN (doppler fetch failed) — user grants will fail" >&2
fi

exec node scripts/grant-authority.mjs "$@"
