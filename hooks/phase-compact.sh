#!/usr/bin/env bash
set -euo pipefail

# TAR Phase Compact Hook (Stop + phase transitions)
# Delegates to phase_compact.py for actual generation.

ROOT=/home/kali
CURRENT_REAL=$(readlink -f "$ROOT/current" 2>/dev/null || printf '%s' "$ROOT/current")
WM_DB="$CURRENT_REAL/world_model.db"
NOTES_DIR="$CURRENT_REAL/notes"
COMPACT_FILE="$NOTES_DIR/compaction_state.md"
MODE="${1:-session-end}"

[ -f "$WM_DB" ] || exit 0
mkdir -p "$NOTES_DIR"

if [ "$MODE" = "phase-boundary" ]; then
    # Append phase delta to compaction file
    DELTA=$(python3 "$ROOT/.claude/scripts/phase_compact.py" "$WM_DB" phase-boundary 2>/dev/null || echo '')
    if [ -n "$DELTA" ]; then
        if [ -f "$COMPACT_FILE" ]; then
            printf '\n\n%s' "$DELTA" >> "$COMPACT_FILE"
        else
            printf '%s' "$DELTA" > "$COMPACT_FILE"
        fi
        printf '[TAR COMPACT] Phase boundary delta written\n'
    fi
else
    # Full session-end compaction
    python3 "$ROOT/.claude/scripts/phase_compact.py" "$WM_DB" session-end > "$COMPACT_FILE" 2>/dev/null || true
    printf '[TAR] Session compaction saved to %s\n' "$COMPACT_FILE"
fi
