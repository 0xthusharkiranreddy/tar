#!/usr/bin/env bash
set -euo pipefail

# TAR Fuzz Subagent — directory/vhost fuzzing pipeline.
# Writes structured results to world_model via parsers.
#
# Usage: fuzz-agent.sh <target_url> <engagement_dir> [mode]
# Modes: dir (default), vhost, param
# Example: fuzz-agent.sh http://10.10.11.50 /home/kali/engagements/htb-box dir

TARGET_URL="${1:?Usage: fuzz-agent.sh <target_url> <engagement_dir> [mode]}"
ENG_DIR="${2:?Usage: fuzz-agent.sh <target_url> <engagement_dir>}"
MODE="${3:-dir}"
WM_DB="$ENG_DIR/world_model.db"
LOGS_DIR="$ENG_DIR/subagent_logs"
PARSERS="/home/kali/.claude/scripts/parsers"

mkdir -p "$LOGS_DIR"
TIMESTAMP=$(date +%s)
LOG_FILE="$LOGS_DIR/fuzz-${TIMESTAMP}.json"

echo "[fuzz-agent] Starting $MODE fuzzing on $TARGET_URL"

RESULTS_FILE=$(mktemp)

case "$MODE" in
    dir)
        # Phase 1: Quick common wordlist
        echo "[fuzz-agent] Phase 1: Common directories..."
        feroxbuster -u "$TARGET_URL" \
            -w /usr/share/seclists/Discovery/Web-Content/common.txt \
            -t 50 --no-state -q -o "$RESULTS_FILE" 2>/dev/null || true

        # Phase 2: Medium wordlist with extensions
        echo "[fuzz-agent] Phase 2: Medium wordlist with extensions..."
        feroxbuster -u "$TARGET_URL" \
            -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
            -x php,txt,html,asp,aspx,jsp -t 50 --no-state -q \
            -o "${RESULTS_FILE}.2" 2>/dev/null || true
        cat "${RESULTS_FILE}.2" >> "$RESULTS_FILE" 2>/dev/null || true
        rm -f "${RESULTS_FILE}.2"
        ;;
    vhost)
        # Extract domain from URL
        DOMAIN=$(echo "$TARGET_URL" | sed -E 's|https?://||; s|[:/].*||')
        TARGET_IP=$(echo "$TARGET_URL" | sed -E 's|https?://||; s|[:/].*||')

        echo "[fuzz-agent] VHost fuzzing for $DOMAIN..."
        ffuf -u "$TARGET_URL" \
            -H "Host: FUZZ.$DOMAIN" \
            -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
            -mc all -fc 302 -fs 0 \
            -o "${RESULTS_FILE}" -of json 2>/dev/null || true
        ;;
    param)
        echo "[fuzz-agent] Parameter fuzzing..."
        ffuf -u "${TARGET_URL}?FUZZ=test" \
            -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
            -mc all -fc 404 \
            -o "${RESULTS_FILE}" -of json 2>/dev/null || true
        ;;
esac

# Parse results into world_model
if [ -s "$RESULTS_FILE" ]; then
    python3 "$PARSERS/gobuster_parser.py" \
        --db "$WM_DB" "$RESULTS_FILE" 2>/dev/null || true
fi

# Build summary
SUMMARY=$(python3 -c "
import json
try:
    with open('$RESULTS_FILE') as f:
        content = f.read()
    # Count lines/entries
    lines = [l for l in content.strip().split('\n') if l.strip()]
    print(json.dumps({'mode': '$MODE', 'findings': len(lines), 'target': '$TARGET_URL'}))
except:
    print(json.dumps({'mode': '$MODE', 'findings': 0, 'target': '$TARGET_URL'}))
" 2>/dev/null || echo '{"findings": 0}')

printf '%s\n' "$SUMMARY" > "$LOG_FILE"
rm -f "$RESULTS_FILE"

echo "[fuzz-agent] Complete. $SUMMARY"
