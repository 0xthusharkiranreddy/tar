#!/usr/bin/env bash
set -euo pipefail

# TAR Web Subagent — multi-step web enumeration pipeline.
# Fingerprint → fuzz → vuln scan → findings to world_model.
# This is a Sonnet-tier subagent (more complex analysis).
#
# Usage: web-agent.sh <target_url> <engagement_dir>
# Example: web-agent.sh http://10.10.11.50 /home/kali/engagements/htb-box

TARGET_URL="${1:?Usage: web-agent.sh <target_url> <engagement_dir>}"
ENG_DIR="${2:?Usage: web-agent.sh <target_url> <engagement_dir>}"
WM_DB="$ENG_DIR/world_model.db"
LOGS_DIR="$ENG_DIR/subagent_logs"
PARSERS="/home/kali/.claude/scripts/parsers"

mkdir -p "$LOGS_DIR"
TIMESTAMP=$(date +%s)
LOG_FILE="$LOGS_DIR/web-${TIMESTAMP}.json"
SCAN_DIR="$ENG_DIR/scans/web"
mkdir -p "$SCAN_DIR"

echo "[web-agent] Starting web enumeration pipeline for $TARGET_URL"

# Extract host for vhost fuzzing
HOST=$(echo "$TARGET_URL" | sed -E 's|https?://||; s|[:/].*||')

# ── Phase 1: Technology fingerprinting ────────────────────────
echo "[web-agent] Phase 1: Fingerprinting..."
whatweb -a 3 "$TARGET_URL" > "$SCAN_DIR/whatweb.txt" 2>/dev/null || true

# Grab headers
curl -sI -k "$TARGET_URL" > "$SCAN_DIR/headers.txt" 2>/dev/null || true

# ── Phase 2: Directory brute-force ────────────────────────────
echo "[web-agent] Phase 2: Directory fuzzing..."
feroxbuster -u "$TARGET_URL" \
    -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
    -x php,txt,html,asp,aspx,jsp,json,xml,bak \
    -t 50 --no-state -q \
    -o "$SCAN_DIR/ferox_output.txt" 2>/dev/null || true

if [ -s "$SCAN_DIR/ferox_output.txt" ]; then
    python3 "$PARSERS/gobuster_parser.py" \
        --db "$WM_DB" "$SCAN_DIR/ferox_output.txt" 2>/dev/null || true
fi

# ── Phase 3: VHost enumeration ────────────────────────────────
echo "[web-agent] Phase 3: VHost fuzzing..."
# Get default response size for filtering
DEFAULT_SIZE=$(curl -s -o /dev/null -w '%{size_download}' -H "Host: nonexistent12345.$HOST" "$TARGET_URL" 2>/dev/null || echo "0")

if [ "$DEFAULT_SIZE" != "0" ]; then
    ffuf -u "$TARGET_URL" \
        -H "Host: FUZZ.$HOST" \
        -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
        -mc all -fs "$DEFAULT_SIZE" \
        -o "$SCAN_DIR/vhosts.json" -of json 2>/dev/null || true
fi

# ── Phase 4: Check common paths ──────────────────────────────
echo "[web-agent] Phase 4: Checking common sensitive paths..."
SENSITIVE_PATHS=(
    "/.git/HEAD" "/.env" "/robots.txt" "/sitemap.xml"
    "/wp-login.php" "/administrator/" "/phpmyadmin/"
    "/api/" "/graphql" "/swagger.json" "/openapi.json"
    "/.well-known/security.txt" "/server-status" "/server-info"
    "/backup/" "/debug/" "/console/" "/actuator/"
)

for path in "${SENSITIVE_PATHS[@]}"; do
    STATUS=$(curl -s -o /dev/null -w '%{http_code}' -k "${TARGET_URL}${path}" 2>/dev/null || echo "000")
    if [ "$STATUS" != "404" ] && [ "$STATUS" != "000" ] && [ "$STATUS" != "403" ]; then
        echo "  [+] Found: ${path} (${STATUS})"
        python3 -c "
import sys
sys.path.insert(0, '/home/kali/.claude/scripts')
from world_model import WorldModel
wm = WorldModel('$WM_DB')
wm.add_finding('web_path', 'info', 'Accessible path: ${path} (HTTP ${STATUS})', '${TARGET_URL}${path}')
wm.close()
" 2>/dev/null || true
    fi
done

# ── Build summary ────────────────────────────────────────────
SUMMARY=$(python3 -c "
import sys, json
sys.path.insert(0, '/home/kali/.claude/scripts')
try:
    from world_model import WorldModel
    wm = WorldModel('$WM_DB')
    findings = wm.conn.execute(\"SELECT COUNT(*) FROM findings WHERE category LIKE 'web%'\").fetchone()[0]
    wm.close()
    print(json.dumps({'web_findings': findings, 'target': '$TARGET_URL'}))
except Exception as e:
    print(json.dumps({'error': str(e)}))
" 2>/dev/null || echo '{"error": "summary failed"}')

printf '%s\n' "$SUMMARY" > "$LOG_FILE"

echo "[web-agent] Complete. $SUMMARY"
