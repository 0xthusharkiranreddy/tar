#!/usr/bin/env bash
set -euo pipefail

# TAR Recon Subagent — full nmap + service enum pipeline.
# Writes structured results to world_model via parsers.
# Designed for Haiku tier — runs in background.
#
# Usage: recon-agent.sh <target_ip> <engagement_dir>
# Example: recon-agent.sh 10.10.11.50 /home/kali/engagements/htb-box

TARGET_IP="${1:?Usage: recon-agent.sh <target_ip> <engagement_dir>}"
ENG_DIR="${2:?Usage: recon-agent.sh <target_ip> <engagement_dir>}"
WM_DB="$ENG_DIR/world_model.db"
LOGS_DIR="$ENG_DIR/subagent_logs"
PARSERS="/home/kali/.claude/scripts/parsers"

mkdir -p "$LOGS_DIR"
TIMESTAMP=$(date +%s)
LOG_FILE="$LOGS_DIR/recon-${TIMESTAMP}.json"
SCAN_DIR="$ENG_DIR/scans"
mkdir -p "$SCAN_DIR"

echo "[recon-agent] Starting full recon pipeline for $TARGET_IP"

# ── Phase 1: Full TCP port scan ──────────────────────────────
echo "[recon-agent] Phase 1: Full TCP port scan..."
nmap -p- --min-rate 5000 -T4 "$TARGET_IP" \
    -oX "$SCAN_DIR/nmap_full_${TARGET_IP}.xml" \
    -oN "$SCAN_DIR/nmap_full_${TARGET_IP}.txt" 2>/dev/null

# Extract open ports
OPEN_PORTS=$(grep -oP 'portid="\K[0-9]+' "$SCAN_DIR/nmap_full_${TARGET_IP}.xml" 2>/dev/null | sort -un | paste -sd,)

if [ -z "$OPEN_PORTS" ]; then
    echo "[recon-agent] No open ports found. Host may be down."
    printf '{"phase":"recon","target":"%s","open_ports":[],"services":[],"error":"no_open_ports"}\n' "$TARGET_IP" > "$LOG_FILE"
    echo "$(<"$LOG_FILE")"
    exit 0
fi

echo "[recon-agent] Open ports: $OPEN_PORTS"

# Parse full scan into world_model
python3 "$PARSERS/nmap_parser.py" \
    --xml "$SCAN_DIR/nmap_full_${TARGET_IP}.xml" \
    --db "$WM_DB" 2>/dev/null || true

# ── Phase 2: Version + script scan on open ports ─────────────
echo "[recon-agent] Phase 2: Version/script scan on $OPEN_PORTS..."
nmap -sCV -p "$OPEN_PORTS" "$TARGET_IP" \
    -oX "$SCAN_DIR/nmap_sCV_${TARGET_IP}.xml" \
    -oN "$SCAN_DIR/nmap_sCV_${TARGET_IP}.txt" 2>/dev/null

# Parse version scan into world_model (updates existing service records)
python3 "$PARSERS/nmap_parser.py" \
    --xml "$SCAN_DIR/nmap_sCV_${TARGET_IP}.xml" \
    --db "$WM_DB" 2>/dev/null || true

# ── Phase 3: SMB enumeration if port 445 open ────────────────
if echo "$OPEN_PORTS" | grep -qE '(^|,)445(,|$)'; then
    echo "[recon-agent] Phase 3: SMB enumeration..."

    # Null session share listing
    SMB_OUT=$(smbclient -N -L "//$TARGET_IP" 2>/dev/null || true)
    if [ -n "$SMB_OUT" ]; then
        echo "$SMB_OUT" | python3 "$PARSERS/smbclient_parser.py" \
            --db "$WM_DB" --host "$TARGET_IP" 2>/dev/null || true
    fi

    # NetExec SMB fingerprint
    NXC_OUT=$(netexec smb "$TARGET_IP" 2>/dev/null || crackmapexec smb "$TARGET_IP" 2>/dev/null || true)
    if [ -n "$NXC_OUT" ]; then
        echo "$NXC_OUT" | python3 "$PARSERS/crackmapexec_parser.py" \
            --db "$WM_DB" 2>/dev/null || true
    fi

    # Guest access share check
    NXC_SHARES=$(netexec smb "$TARGET_IP" -u 'guest' -p '' --shares 2>/dev/null || \
                 crackmapexec smb "$TARGET_IP" -u 'guest' -p '' --shares 2>/dev/null || true)
    if [ -n "$NXC_SHARES" ]; then
        echo "$NXC_SHARES" | python3 "$PARSERS/crackmapexec_parser.py" \
            --db "$WM_DB" 2>/dev/null || true
    fi
fi

# ── Phase 4: UDP top-20 scan (quick) ─────────────────────────
echo "[recon-agent] Phase 4: Quick UDP scan..."
nmap -sU --top-ports 20 --min-rate 1000 "$TARGET_IP" \
    -oX "$SCAN_DIR/nmap_udp_${TARGET_IP}.xml" 2>/dev/null || true

python3 "$PARSERS/nmap_parser.py" \
    --xml "$SCAN_DIR/nmap_udp_${TARGET_IP}.xml" \
    --db "$WM_DB" 2>/dev/null || true

# ── Build summary from world_model ───────────────────────────
SUMMARY=$(python3 -c "
import sys, json
sys.path.insert(0, '/home/kali/.claude/scripts')
try:
    from world_model import WorldModel
    wm = WorldModel('$WM_DB')
    summary = wm.get_state_summary()
    wm.close()
    print(json.dumps(summary))
except Exception as e:
    print(json.dumps({'error': str(e)}))
" 2>/dev/null || echo '{"error": "world_model unavailable"}')

printf '%s\n' "$SUMMARY" > "$LOG_FILE"

echo "[recon-agent] Complete. Summary:"
echo "$SUMMARY" | python3 -m json.tool 2>/dev/null || echo "$SUMMARY"
