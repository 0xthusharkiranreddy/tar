#!/usr/bin/env bash
set -euo pipefail

# TAR Post-Action Hook (PostToolUse on Bash)
# Detects pentest tool commands, routes to appropriate parser,
# updates world_model. Runs Critic check on expected effects.

ROOT=/home/kali
CURRENT_REAL=$(readlink -f "$ROOT/current" 2>/dev/null || printf '%s' "$ROOT/current")
WM_DB="$CURRENT_REAL/world_model.db"
PARSERS_DIR="$ROOT/.claude/scripts/parsers"

# Only run if world_model exists
[ -f "$WM_DB" ] || exit 0

# Read hook input from stdin (JSON with tool_input and tool_response)
INPUT=$(cat)

# Extract the command that was run
COMMAND=$(echo "$INPUT" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    # Handle different possible input formats
    if isinstance(data, dict):
        ti = data.get('tool_input', data)
        if isinstance(ti, dict):
            print(ti.get('command', ''))
        elif isinstance(ti, str):
            print(ti)
    else:
        print('')
except:
    print('')
" 2>/dev/null || echo '')

[ -n "$COMMAND" ] || exit 0

# Detect tool and route to parser
PARSED=""

case "$COMMAND" in
    *nmap*-oX*)
        # Extract XML output file path
        XML_FILE=$(echo "$COMMAND" | grep -oP '(?<=-oX\s)\S+' || echo '')
        if [ -n "$XML_FILE" ] && [ -f "$XML_FILE" ]; then
            PARSED=$(python3 "$PARSERS_DIR/nmap_parser.py" "$XML_FILE" --db "$WM_DB" 2>&1 || echo '')
            [ -n "$PARSED" ] && printf '[TAR] Nmap parsed: %s\n' "$PARSED"
        fi
        ;;
    *smbclient*-L*)
        # smbclient share listing — extract host IP
        HOST=$(echo "$COMMAND" | grep -oP '//(\d+\.\d+\.\d+\.\d+)' | tr -d '/' || echo '')
        if [ -n "$HOST" ]; then
            TOOL_OUTPUT=$(echo "$INPUT" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('tool_response', data.get('response', '')))
except:
    print('')
" 2>/dev/null || echo '')
            if [ -n "$TOOL_OUTPUT" ]; then
                PARSED=$(echo "$TOOL_OUTPUT" | python3 "$PARSERS_DIR/smbclient_parser.py" - --tool smbclient --host "$HOST" --db "$WM_DB" 2>&1 || echo '')
                [ -n "$PARSED" ] && printf '[TAR] SMB parsed: %s\n' "$PARSED"
            fi
        fi
        ;;
    *netexec*smb*|*crackmapexec*smb*)
        TOOL_OUTPUT=$(echo "$INPUT" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('tool_response', data.get('response', '')))
except:
    print('')
" 2>/dev/null || echo '')
        if [ -n "$TOOL_OUTPUT" ]; then
            PARSED=$(echo "$TOOL_OUTPUT" | python3 "$PARSERS_DIR/crackmapexec_parser.py" - --db "$WM_DB" 2>&1 || echo '')
            [ -n "$PARSED" ] && printf '[TAR] CME parsed: %s\n' "$PARSED"
        fi
        ;;
    *enum4linux*)
        HOST=$(echo "$COMMAND" | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1 || echo '')
        if [ -n "$HOST" ]; then
            TOOL_OUTPUT=$(echo "$INPUT" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('tool_response', data.get('response', '')))
except:
    print('')
" 2>/dev/null || echo '')
            if [ -n "$TOOL_OUTPUT" ]; then
                PARSED=$(echo "$TOOL_OUTPUT" | python3 "$PARSERS_DIR/smbclient_parser.py" - --tool enum4linux --host "$HOST" --db "$WM_DB" 2>&1 || echo '')
                [ -n "$PARSED" ] && printf '[TAR] enum4linux parsed: %s\n' "$PARSED"
            fi
        fi
        ;;
    *feroxbuster*|*gobuster*|*ffuf*)
        # Web fuzzer output
        TOOL_OUTPUT=$(echo "$INPUT" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('tool_response', data.get('response', '')))
except:
    print('')
" 2>/dev/null || echo '')
        if [ -n "$TOOL_OUTPUT" ]; then
            PARSED=$(echo "$TOOL_OUTPUT" | python3 "$PARSERS_DIR/gobuster_parser.py" --db "$WM_DB" 2>&1 || echo '')
            [ -n "$PARSED" ] && printf '[TAR] Web fuzz parsed: %s\n' "$PARSED"
        fi
        ;;
    *GetUserSPNs*|*kerberoast*)
        TOOL_OUTPUT=$(echo "$INPUT" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('tool_response', data.get('response', '')))
except:
    print('')
" 2>/dev/null || echo '')
        if [ -n "$TOOL_OUTPUT" ]; then
            PARSED=$(echo "$TOOL_OUTPUT" | python3 "$PARSERS_DIR/impacket_parser.py" --tool kerberoast --db "$WM_DB" 2>&1 || echo '')
            [ -n "$PARSED" ] && printf '[TAR] Kerberoast parsed: %s\n' "$PARSED"
        fi
        ;;
    *GetNPUsers*|*asreproast*)
        TOOL_OUTPUT=$(echo "$INPUT" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('tool_response', data.get('response', '')))
except:
    print('')
" 2>/dev/null || echo '')
        if [ -n "$TOOL_OUTPUT" ]; then
            PARSED=$(echo "$TOOL_OUTPUT" | python3 "$PARSERS_DIR/impacket_parser.py" --tool asreproast --db "$WM_DB" 2>&1 || echo '')
            [ -n "$PARSED" ] && printf '[TAR] AS-REP parsed: %s\n' "$PARSED"
        fi
        ;;
    *secretsdump*)
        TOOL_OUTPUT=$(echo "$INPUT" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('tool_response', data.get('response', '')))
except:
    print('')
" 2>/dev/null || echo '')
        if [ -n "$TOOL_OUTPUT" ]; then
            PARSED=$(echo "$TOOL_OUTPUT" | python3 "$PARSERS_DIR/impacket_parser.py" --tool secretsdump --db "$WM_DB" 2>&1 || echo '')
            [ -n "$PARSED" ] && printf '[TAR] Secretsdump parsed: %s\n' "$PARSED"
        fi
        ;;
    *hashcat*|*john*)
        # Hash cracking output
        TOOL_OUTPUT=$(echo "$INPUT" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('tool_response', data.get('response', '')))
except:
    print('')
" 2>/dev/null || echo '')
        if [ -n "$TOOL_OUTPUT" ]; then
            PARSED=$(echo "$TOOL_OUTPUT" | python3 "$PARSERS_DIR/hashcat_parser.py" --db "$WM_DB" 2>&1 || echo '')
            [ -n "$PARSED" ] && printf '[TAR] Crack parsed: %s\n' "$PARSED"
        fi
        ;;
    *netexec*winrm*|*crackmapexec*winrm*|*netexec*ldap*|*crackmapexec*ldap*|*netexec*mssql*|*crackmapexec*mssql*)
        TOOL_OUTPUT=$(echo "$INPUT" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('tool_response', data.get('response', '')))
except:
    print('')
" 2>/dev/null || echo '')
        if [ -n "$TOOL_OUTPUT" ]; then
            PARSED=$(echo "$TOOL_OUTPUT" | python3 "$PARSERS_DIR/crackmapexec_parser.py" - --db "$WM_DB" 2>&1 || echo '')
            [ -n "$PARSED" ] && printf '[TAR] NXC parsed: %s\n' "$PARSED"
        fi
        ;;
    *curl*|*wget*|*sqlmap*|*nikto*|*whatweb*|*wpscan*|*droopescan*|*joomscan*)
        # Web tool output → web_response_parser + tech_detect_parser
        TOOL_OUTPUT=$(echo "$INPUT" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('tool_response', data.get('response', '')))
except:
    print('')
" 2>/dev/null || echo '')
        if [ -n "$TOOL_OUTPUT" ] && [ ${#TOOL_OUTPUT} -gt 10 ]; then
            PARSED=$(echo "$TOOL_OUTPUT" | python3 "$PARSERS_DIR/web_response_parser.py" --db "$WM_DB" 2>&1 || echo '')
            [ -n "$PARSED" ] && printf '[TAR] Web parsed: %s\n' "$PARSED"
            # Also run tech detection
            TECH=$(echo "$TOOL_OUTPUT" | python3 "$PARSERS_DIR/tech_detect_parser.py" --db "$WM_DB" --full-body 2>&1 || echo '')
            [ -n "$TECH" ] && printf '[TAR] Tech: %s\n' "$TECH"
        fi
        ;;
    *hydra*|*kerbrute*|*crackmapexec*|*netexec*|*evil-winrm*|*psexec*|*wmiexec*|*ssh*|*ftp*|*redis-cli*|*mysql*|*mssql*|*ldapsearch*|*rpcclient*|*dig*|*snmpwalk*)
        # Service tools → generic_parser
        TOOL_OUTPUT=$(echo "$INPUT" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('tool_response', data.get('response', '')))
except:
    print('')
" 2>/dev/null || echo '')
        if [ -n "$TOOL_OUTPUT" ] && [ ${#TOOL_OUTPUT} -gt 10 ]; then
            TOOL_NAME=$(echo "$COMMAND" | grep -oP '^\S+' | sed 's|.*/||' || echo 'unknown')
            PARSED=$(echo "$TOOL_OUTPUT" | python3 "$PARSERS_DIR/generic_parser.py" --db "$WM_DB" --tool "$TOOL_NAME" 2>&1 || echo '')
            [ -n "$PARSED" ] && printf '[TAR] Parsed: %s\n' "$PARSED"
        fi
        ;;
    *linpeas*|*winpeas*|*sudo*-l*|*find*-perm*|*getcap*|*whoami*|*id\ *|*cat\ /etc/passwd*|*type\ *|*net\ user*|*systeminfo*)
        # Privesc enum → generic_parser
        TOOL_OUTPUT=$(echo "$INPUT" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('tool_response', data.get('response', '')))
except:
    print('')
" 2>/dev/null || echo '')
        if [ -n "$TOOL_OUTPUT" ] && [ ${#TOOL_OUTPUT} -gt 10 ]; then
            PARSED=$(echo "$TOOL_OUTPUT" | python3 "$PARSERS_DIR/generic_parser.py" --db "$WM_DB" --tool privesc_enum 2>&1 || echo '')
            [ -n "$PARSED" ] && printf '[TAR] Privesc parsed: %s\n' "$PARSED"
        fi
        ;;
esac

# ── Predicate Ledger: record success/failure for cross-engagement learning ──
python3 -c "
import sys, re, json, hashlib
sys.path.insert(0, '/home/kali/.claude/scripts')

cmd = '''$COMMAND'''
tool_output = '''$(echo "$INPUT" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    r = data.get('tool_response', data.get('response', ''))
    print(str(r)[:500])
except:
    print('')
" 2>/dev/null || echo '')'''

try:
    from predicate_ledger import PredicateLedger
    from world_model import WorldModel

    # Detect action
    action = ''
    patterns = [
        (r'GetUserSPNs', 'kerberoast'), (r'GetNPUsers', 'asreproast'),
        (r'secretsdump', 'secretsdump'), (r'certipy', 'certipy'),
        (r'ntlmrelayx', 'ntlmrelayx'), (r'responder', 'responder'),
        (r'PetitPotam|DFSCoerce|coercer', 'coerce'),
        (r'evil-winrm', 'evil_winrm'), (r'psexec', 'psexec'),
    ]
    for pat, act in patterns:
        if re.search(pat, cmd, re.I):
            action = act
            break

    if not action:
        sys.exit(0)

    # Build fingerprint
    wm = WorldModel('$WM_DB')
    services = wm.conn.execute('SELECT port, product FROM services WHERE host_id=1 LIMIT 10').fetchall()
    host = wm.conn.execute('SELECT os FROM hosts LIMIT 1').fetchone()
    os_name = host[0] if host else ''
    eng = wm.conn.execute('SELECT name FROM engagement LIMIT 1').fetchone()
    eng_name = eng[0] if eng else ''
    wm.close()

    pl = PredicateLedger()
    fp = pl.compute_fingerprint(os_name=os_name, services=[(s[0], s[1]) for s in services])

    # Detect failure patterns
    failure_patterns = [
        r'ACCESS_DENIED|LOGON_FAILURE|error|failed|refused|No entries found|Exhausted',
        r'KRB_AP_ERR_SKEW|INSUFFICIENT_ACCESS|UNWILLING_TO_PERFORM',
    ]
    is_failure = any(re.search(p, tool_output, re.I) for p in failure_patterns)
    is_empty = len(tool_output.strip()) < 10

    if is_failure or is_empty:
        silence = tool_output[:100] if tool_output.strip() else 'empty_output'
        pl.record_failure(action, fp, silence, eng_name)
    else:
        pl.record_success(action, fp)

    pl.close()
except:
    pass
" 2>/dev/null || true

# ── Phase Advancement Check ──
NEW_PHASE=$(python3 -c "
import sys
sys.path.insert(0, '/home/kali/.claude/scripts')
from world_model import WorldModel
wm = WorldModel('$WM_DB')
new = wm.maybe_advance_phase()
wm.close()
if new:
    print(new)
" 2>/dev/null || echo '')

if [ -n "$NEW_PHASE" ]; then
    printf '[TAR PHASE] Advanced to: %s\n' "$NEW_PHASE"
    # Trigger phase-boundary compaction
    bash "$ROOT/.claude/hooks/phase-compact.sh" phase-boundary 2>/dev/null || true
fi

# ── Cost Router: track success/failure for auto-escalation ──
COST_RESULT=$(python3 -c "
import sys, re
sys.path.insert(0, '/home/kali/.claude/scripts')
from cost_router import record_critic_failure, record_success

# Quick check if the command output indicates failure
tool_out = '''$(echo "$INPUT" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    r = data.get('tool_response', data.get('response', ''))
    print(str(r)[:200])
except:
    print('')
" 2>/dev/null || echo '')'''

failure_pats = r'ACCESS_DENIED|LOGON_FAILURE|error|failed|refused|No entries|timeout|Connection reset'
if re.search(failure_pats, tool_out, re.I) or len(tool_out.strip()) < 5:
    result = record_critic_failure('$WM_DB')
    if 'ESCALATED' in result:
        print(result)
else:
    record_success('$WM_DB')
" 2>/dev/null || echo '')

if [ -n "$COST_RESULT" ]; then
    printf '[TAR COST] %s\n' "$COST_RESULT"
fi

# Silence Reading: check for known failure patterns
case "$COMMAND" in
    *ntlmrelayx*|*responder*|*coerce*|*petitpotam*|*printerbug*)
        TOOL_OUTPUT=$(echo "$INPUT" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('tool_response', data.get('response', '')))
except:
    print('')
" 2>/dev/null || echo '')
        if [ -z "$TOOL_OUTPUT" ] || [ ${#TOOL_OUTPUT} -lt 10 ]; then
            printf '[TAR SILENCE] Zero output from relay/coerce tool. Check: wrong coercion method, port conflict (ss -tlnp), or target not vulnerable.\n'
        elif echo "$TOOL_OUTPUT" | grep -qi "KRB_AP_ERR_SKEW"; then
            printf '[TAR SILENCE] Kerberos clock skew >5 min detected. Fix with: sudo ntpdate -s TARGET_IP\n'
        elif echo "$TOOL_OUTPUT" | grep -qi "Exploit Success" && ! echo "$TOOL_OUTPUT" | grep -qi "connection\|relay\|hash"; then
            printf '[TAR SILENCE] Coerce "Exploit Success" but no callback received. RPC delivered != port 445 callback. Check coercion method.\n'
        fi
        ;;
esac
