#!/usr/bin/env bash
set -euo pipefail

# TAR Crack Subagent — runs hashcat/john in background.
# Writes cracked creds to subagent_logs/ and world_model.
# Designed for Haiku tier — potentially long-running.
#
# Usage: crack-agent.sh <hash_file> <hash_type> <engagement_dir> [wordlist]
# Example: crack-agent.sh /tmp/hashes.txt 13100 /home/kali/engagements/htb-box

HASH_FILE="${1:?Usage: crack-agent.sh <hash_file> <hash_type> <engagement_dir> [wordlist]}"
HASH_TYPE="${2:?Usage: crack-agent.sh <hash_file> <hash_type> <engagement_dir>}"
ENG_DIR="${3:?Usage: crack-agent.sh <hash_file> <hash_type> <engagement_dir>}"
WORDLIST="${4:-/usr/share/wordlists/rockyou.txt}"
WM_DB="$ENG_DIR/world_model.db"
LOGS_DIR="$ENG_DIR/subagent_logs"

mkdir -p "$LOGS_DIR"
TIMESTAMP=$(date +%s)
LOG_FILE="$LOGS_DIR/crack-${TIMESTAMP}.json"

echo "[crack-agent] Starting hashcat: type=$HASH_TYPE file=$HASH_FILE"

# Common hash types for reference:
# 1000 = NTLM
# 5600 = NTLMv2
# 13100 = Kerberoast (TGS-REP)
# 18200 = AS-REP roast
# 1800 = sha512crypt
# 500 = md5crypt
# 3200 = bcrypt

CRACKED_FILE=$(mktemp)

# Run hashcat (--force for VM environments without GPU)
hashcat -m "$HASH_TYPE" "$HASH_FILE" "$WORDLIST" \
    --force --quiet --potfile-disable \
    -o "$CRACKED_FILE" 2>/dev/null || true

# If hashcat failed, try john as fallback
if [ ! -s "$CRACKED_FILE" ]; then
    echo "[crack-agent] Hashcat produced no results, trying john..."
    john "$HASH_FILE" --wordlist="$WORDLIST" --format="$(
        case "$HASH_TYPE" in
            1000) echo "NT" ;;
            5600) echo "netntlmv2" ;;
            13100) echo "krb5tgs" ;;
            18200) echo "krb5asrep" ;;
            *) echo "" ;;
        esac
    )" 2>/dev/null || true
    john "$HASH_FILE" --show 2>/dev/null | grep ":" > "$CRACKED_FILE" || true
fi

# Parse results and write to world model
RESULTS=$(python3 -c "
import sys, json
sys.path.insert(0, '/home/kali/.claude/scripts')

cracked = []
try:
    with open('$CRACKED_FILE') as f:
        for line in f:
            line = line.strip()
            if ':' in line:
                parts = line.split(':')
                cracked.append({
                    'hash_or_user': parts[0],
                    'password': parts[-1] if len(parts) > 1 else '',
                })
except:
    pass

# Write to world model if available
try:
    from world_model import WorldModel
    wm = WorldModel('$WM_DB')
    for c in cracked:
        wm.add_cred(
            username=c.get('hash_or_user', ''),
            password=c.get('password', ''),
            source='crack-agent',
            verified=False,
        )
    wm.close()
except:
    pass

print(json.dumps({'cracked': len(cracked), 'results': cracked}))
" 2>/dev/null || echo '{"cracked": 0}')

printf '%s\n' "$RESULTS" > "$LOG_FILE"
rm -f "$CRACKED_FILE"

echo "[crack-agent] Complete. $RESULTS"
echo "$RESULTS"
