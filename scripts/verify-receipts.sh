#!/usr/bin/env bash
# verify-receipts.sh — offline receipt verification (Auditor stand-in) via
# @forestrie/receipt-verify under a known log key. Verifies inclusion with the
# log absent — the demo's payoff (plan §2, T8). See verify-receipts.mjs for
# the checks and options; this wrapper exists so the plan's named entry point
# works from anywhere.
set -euo pipefail
exec node "$(dirname "$0")/verify-receipts.mjs" "$@"
