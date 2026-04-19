#!/usr/bin/env bash
set -euo pipefail
ROOT=/home/kali
CURRENT_REAL=$(readlink -f "$ROOT/current" 2>/dev/null || printf '%s' "$ROOT/current")
NOTES_DIR="$CURRENT_REAL/notes"
STATE_FILE="$NOTES_DIR/session_state.md"
EDIT_LOG="$NOTES_DIR/edit_log.md"
TOUCHED=${1:-}
NOW=$(date -Is)
mkdir -p "$NOTES_DIR"
[ -f "$EDIT_LOG" ] || printf '# Edit Log\n\n' > "$EDIT_LOG"
{
  printf '## %s\n' "$NOW"
  if [ -n "$TOUCHED" ]; then printf -- '- Touched: `%s`\n' "$TOUCHED"; else printf -- '- Touched: `(unspecified)`\n'; fi
  printf -- '- Reminder: refresh session_state.md if the world model, queue, or next action changed.\n\n'
} >> "$EDIT_LOG"
if [ -f "$STATE_FILE" ]; then
  tmp=$(mktemp)
  awk -v now="$NOW" '
    /^## Last Updated/ {print; inblock=1; next}
    inblock && /^- Timestamp:/ {print "- Timestamp: " now; next}
    inblock && /^## / {inblock=0}
    {print}
  ' "$STATE_FILE" > "$tmp"
  mv "$tmp" "$STATE_FILE"
fi
