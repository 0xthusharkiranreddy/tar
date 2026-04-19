#!/usr/bin/env bash
set -euo pipefail

# TAR Session Init Hook (part of session startup)
# Initializes world_model.db if engagement has a target IP.

ROOT=/home/kali
CURRENT_REAL=$(readlink -f "$ROOT/current" 2>/dev/null || printf '%s' "$ROOT/current")
STATE_FILE="$CURRENT_REAL/notes/session_state.md"
WM_DB="$CURRENT_REAL/world_model.db"

# Only proceed if session_state exists
[ -f "$STATE_FILE" ] || exit 0

# Check if world_model already exists
[ -f "$WM_DB" ] && exit 0

# Extract target IP from session_state
TARGET_IP=$(grep -oP '(?<=Scope:\s)\d+\.\d+\.\d+\.\d+' "$STATE_FILE" 2>/dev/null || echo '')
[ -n "$TARGET_IP" ] || exit 0

# Extract engagement name
ENG_NAME=$(grep -oP '(?<=Name:\s).*' "$STATE_FILE" 2>/dev/null | head -1 | tr ' ' '-' | tr '[:upper:]' '[:lower:]' || echo 'unknown')

# Initialize world model
python3 -c "
import sys
sys.path.insert(0, '$ROOT/.claude/scripts')
from world_model import WorldModel

wm = WorldModel('$WM_DB')
wm.init_engagement('$ENG_NAME', '$TARGET_IP')
wm.add_host('$TARGET_IP')
wm.close()
" 2>/dev/null

printf '[TAR] World model initialized for %s (%s)\n' "$ENG_NAME" "$TARGET_IP"
