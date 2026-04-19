#!/usr/bin/env bash
set -euo pipefail

# TAR Enum Subagent — privilege escalation enumeration pipeline.
# Runs linpeas/winpeas and writes findings to world_model.
#
# Usage: enum-agent.sh <os_type> <engagement_dir> [target_ip]
# Example: enum-agent.sh linux /home/kali/engagements/htb-box 10.10.11.50

OS_TYPE="${1:?Usage: enum-agent.sh <linux|windows> <engagement_dir> [target_ip]}"
ENG_DIR="${2:?Usage: enum-agent.sh <os_type> <engagement_dir>}"
TARGET_IP="${3:-}"
WM_DB="$ENG_DIR/world_model.db"
LOGS_DIR="$ENG_DIR/subagent_logs"
PARSERS="/home/kali/.claude/scripts/parsers"

mkdir -p "$LOGS_DIR"
TIMESTAMP=$(date +%s)
LOG_FILE="$LOGS_DIR/enum-${TIMESTAMP}.json"

echo "[enum-agent] Starting $OS_TYPE enumeration"

RESULTS_FILE=$(mktemp)

case "$OS_TYPE" in
    linux)
        echo "[enum-agent] Running Linux enumeration checks..."

        # Sudo permissions
        echo "=== SUDO ===" >> "$RESULTS_FILE"
        sudo -l 2>/dev/null >> "$RESULTS_FILE" || true

        # SUID binaries
        echo "=== SUID ===" >> "$RESULTS_FILE"
        find / -perm -4000 -type f 2>/dev/null >> "$RESULTS_FILE" || true

        # Capabilities
        echo "=== CAPABILITIES ===" >> "$RESULTS_FILE"
        getcap -r / 2>/dev/null >> "$RESULTS_FILE" || true

        # Cron jobs
        echo "=== CRON ===" >> "$RESULTS_FILE"
        cat /etc/crontab 2>/dev/null >> "$RESULTS_FILE" || true
        ls -la /etc/cron.d/ 2>/dev/null >> "$RESULTS_FILE" || true

        # Writable files/dirs
        echo "=== WRITABLE ===" >> "$RESULTS_FILE"
        find / -writable -type f 2>/dev/null | grep -vE '/proc|/sys|/dev|/run' | head -50 >> "$RESULTS_FILE" || true

        # Docker/LXD groups
        echo "=== GROUPS ===" >> "$RESULTS_FILE"
        id 2>/dev/null >> "$RESULTS_FILE" || true
        groups 2>/dev/null >> "$RESULTS_FILE" || true

        # Interesting files
        echo "=== FILES ===" >> "$RESULTS_FILE"
        find / -name "*.bak" -o -name "*.conf" -o -name "*.db" -o -name "*.sqlite" -o -name "id_rsa" -o -name "*.key" 2>/dev/null | head -30 >> "$RESULTS_FILE" || true

        # Parse results
        python3 "$PARSERS/linpeas_parser.py" --type linux --db "$WM_DB" "$RESULTS_FILE" 2>/dev/null || true
        ;;

    windows)
        echo "[enum-agent] Running Windows enumeration checks..."
        # This runs on the attacker side — actual enum runs on target
        # Log the commands to execute on target
        cat > "$RESULTS_FILE" << 'WINEOF'
whoami /all
systeminfo
net user
net localgroup administrators
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
cmdkey /list
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows\\"
WINEOF
        echo "[enum-agent] Windows commands prepared in $RESULTS_FILE"
        ;;
esac

# Build summary
FINDING_COUNT=$(wc -l < "$RESULTS_FILE" 2>/dev/null || echo "0")
SUMMARY=$(printf '{"os":"%s","lines":%s}' "$OS_TYPE" "$FINDING_COUNT")

printf '%s\n' "$SUMMARY" > "$LOG_FILE"
rm -f "$RESULTS_FILE"

echo "[enum-agent] Complete. $SUMMARY"
