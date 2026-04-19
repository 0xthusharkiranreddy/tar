#!/usr/bin/env bash
set -euo pipefail
ROOT=/home/kali
CURRENT_REAL=$(readlink -f "$ROOT/current" 2>/dev/null || printf '%s' "$ROOT/current")
STATE_DIR="$CURRENT_REAL/notes"
STATE_FILE="$STATE_DIR/session_state.md"
TEMPLATE="$ROOT/knowledge/workflows/templates/session_state.template.md"
COMPACT_FILE="$STATE_DIR/compaction_state.md"
mkdir -p "$STATE_DIR"
[ -f "$STATE_FILE" ] || cp "$TEMPLATE" "$STATE_FILE"
printf 'Core: %s\n' "/root/.claude/CLAUDE.md"
printf 'State: %s\n' "$STATE_FILE"
[ -f "$COMPACT_FILE" ] && printf 'Compaction snapshot: %s\n' "$COMPACT_FILE"
awk '
  /^## Engagement/ || /^## Target/ || /^## Next Action/ || /^## Falsifier/ {print; keep=1; next}
  keep && /^## / {keep=0}
  keep && /^- [A-Za-z ]+: *$/ {next}
  keep && /^$/ {next}
  keep {print}
' "$STATE_FILE"
