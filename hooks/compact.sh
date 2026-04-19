#!/usr/bin/env bash
set -euo pipefail
ROOT=/home/kali
CURRENT_REAL=$(readlink -f "$ROOT/current" 2>/dev/null || printf '%s' "$ROOT/current")
STATE_FILE="$CURRENT_REAL/notes/session_state.md"
OUT_FILE="$CURRENT_REAL/notes/compaction_state.md"
[ -f "$STATE_FILE" ] || { echo "session_state.md not found: $STATE_FILE" >&2; exit 1; }
{
  echo '# Compaction State'
  echo
  echo "Generated: $(date -Is)"
  echo
  awk '
    /^## Engagement/ || /^## Target/ || /^## World Model/ || /^## Active Hypotheses/ || /^## Opportunity Queue/ || /^## Recent Confirmations/ || /^## Ruled Out/ || /^## Next Action/ || /^## Falsifier/ || /^## Evidence Pointers/ {print; keep=1; next}
    keep && /^## / {keep=0}
    keep {print}
  ' "$STATE_FILE"
  echo
  echo '## Restore Order'
  echo '1. Load /home/kali/CLAUDE.md'
  echo '2. Read /home/kali/current/notes/session_state.md'
  echo '3. Load relevant skills from /home/kali/.claude/skills/'
  echo '4. Load only the necessary files from /home/kali/knowledge/'
} > "$OUT_FILE"
printf 'Wrote %s\n' "$OUT_FILE"
