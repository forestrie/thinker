#!/usr/bin/env bash
# tamper.sh — the tamper beat (plan §2, M4): rewrite the Scribe DO's memory
# of a conversation by editing its SQLite state directly, the way a
# compromised or dishonest operator would. The DO happily serves the edited
# transcript afterwards — but verify-receipts.sh now diverges on
# transcript-binding, because the receipted work statement committed the
# ORIGINAL output hash to the public log.
#
# Targets the local `wrangler dev` state (.wrangler/state/v3 DO SQLite).
# The dev server must be STOPPED while editing: workerd holds the database
# open and caches reads, so a live edit is both unsafe and invisible.
#
# Usage:
#   tamper.sh [--state-dir DIR] (--leaf <messageId> | --latest) <find> <replace>
#
#   --leaf     tamper the assistant message with this id (a work unit's leafId)
#   --latest   tamper the most recent assistant message across instances
#   find       substring of the message text to rewrite
#   replace    what to write instead
#
# Demo flow:
#   1. chat via an attested turn; wait for state=receipted; verify → all pass
#   2. stop wrangler dev
#   3. scripts/tamper.sh --leaf <leafId> "original phrase" "rewritten phrase"
#   4. restart wrangler dev
#   5. scripts/verify-receipts.sh … → ✗ transcript-binding: tampered
set -euo pipefail
cd "$(dirname "$0")/.."

STATE_DIR="apps/scribe-worker/.wrangler/state/v3/do/thinker-scribe-Scribe"
MODE="" LEAF="" FIND="" REPLACE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --state-dir) STATE_DIR="$2"; shift 2 ;;
    --leaf) MODE="leaf"; LEAF="$2"; shift 2 ;;
    --latest) MODE="latest"; shift ;;
    *)
      if [ -z "$FIND" ]; then FIND="$1"; elif [ -z "$REPLACE" ]; then REPLACE="$1"; else
        echo "tamper.sh: unexpected argument $1" >&2; exit 2
      fi
      shift ;;
  esac
done
[ -n "$MODE" ] && [ -n "$FIND" ] && [ -n "$REPLACE" ] || {
  sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
[ -d "$STATE_DIR" ] || { echo "tamper.sh: no DO state at $STATE_DIR (run wrangler dev first)" >&2; exit 1; }

# Find the instance database holding the target message.
DB="" ID="$LEAF" LATEST_AT=""
for candidate in "$STATE_DIR"/*.sqlite; do
  [ "$(basename "$candidate")" = "metadata.sqlite" ] && continue
  if lsof -t "$candidate" >/dev/null 2>&1; then
    echo "tamper.sh: $candidate is open (wrangler dev running?) — stop it first" >&2
    exit 1
  fi
  sqlite3 "$candidate" "SELECT 1 FROM sqlite_master WHERE name='assistant_messages'" | grep -q 1 || continue
  if [ "$MODE" = "leaf" ]; then
    if [ "$(sqlite3 "$candidate" "SELECT count(*) FROM assistant_messages WHERE id='$LEAF'")" = "1" ]; then
      DB="$candidate"; break
    fi
  else
    row=$(sqlite3 "$candidate" \
      "SELECT id || '|' || created_at FROM assistant_messages WHERE role='assistant' ORDER BY created_at DESC, rowid DESC LIMIT 1")
    [ -n "$row" ] || continue
    if [ -z "$DB" ] || [ "${row#*|}" \> "$LATEST_AT" ]; then
      DB="$candidate"; ID="${row%%|*}"; LATEST_AT="${row#*|}"
    fi
  fi
done
[ -n "$DB" ] || { echo "tamper.sh: no matching assistant message found under $STATE_DIR" >&2; exit 1; }

before=$(sqlite3 "$DB" "SELECT content FROM assistant_messages WHERE id='$ID'")
case "$before" in
  *"$FIND"*) ;;
  *) echo "tamper.sh: message $ID does not contain \"$FIND\"" >&2; exit 1 ;;
esac

sqlite3 "$DB" "UPDATE assistant_messages
  SET content = replace(content, '$(printf %s "$FIND" | sed "s/'/''/g")',
                                 '$(printf %s "$REPLACE" | sed "s/'/''/g")')
  WHERE id='$ID'"

echo "tampered $ID in $(basename "$DB")"
echo "  - $FIND"
echo "  + $REPLACE"
echo "restart wrangler dev, then run verify-receipts.sh — transcript-binding will diverge"
