#!/usr/bin/env bash
set -euo pipefail

# TAR Pre-Action Hook (PreToolUse on Bash)
# Enforces retry-block policy and pre-attack platform check.

ROOT=/home/kali
CURRENT_REAL=$(readlink -f "$ROOT/current" 2>/dev/null || printf '%s' "$ROOT/current")
WM_DB="$CURRENT_REAL/world_model.db"

# Only run if world_model exists
[ -f "$WM_DB" ] || exit 0

# Read hook input from stdin
INPUT=$(cat)

COMMAND=$(echo "$INPUT" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    ti = data.get('tool_input', data)
    if isinstance(ti, dict):
        print(ti.get('command', ''))
    elif isinstance(ti, str):
        print(ti)
except:
    print('')
" 2>/dev/null || echo '')

[ -n "$COMMAND" ] || exit 0

# Retry-block check: detect if same command was already run and failed
BLOCKED=$(python3 -c "
import sys, hashlib, json
sys.path.insert(0, '$ROOT/.claude/scripts')
from world_model import WorldModel

cmd = '''$COMMAND'''
cmd_hash = hashlib.sha256(cmd.encode()).hexdigest()[:16]

wm = WorldModel('$WM_DB')
rows = wm.conn.execute(
    'SELECT action_name FROM failed_attempts WHERE params_hash=?',
    (cmd_hash,)
).fetchall()
wm.close()

if rows:
    print(f'BLOCKED: This exact command already failed as [{rows[0][\"action_name\"]}]. Diagnose the failure before retrying.')
" 2>/dev/null || echo '')

if [ -n "$BLOCKED" ]; then
    printf '[TAR RETRY-BLOCK] %s\n' "$BLOCKED"
fi

# Cross-engagement predicate ledger check
LEDGER_BLOCKED=$(python3 -c "
import sys
sys.path.insert(0, '$ROOT/.claude/scripts')
from predicate_ledger import PredicateLedger
from world_model import WorldModel

try:
    wm = WorldModel('$WM_DB')
    # Build target fingerprint from world_model
    services = wm.conn.execute('SELECT port, product FROM services WHERE host_id=1 LIMIT 10').fetchall()
    host = wm.conn.execute('SELECT os FROM hosts LIMIT 1').fetchone()
    os_name = host[0] if host else ''
    wm.close()

    pl = PredicateLedger()
    fp = pl.compute_fingerprint(os_name=os_name, services=[(s[0], s[1]) for s in services])

    # Detect action name from command
    cmd = '''$COMMAND'''
    action = ''
    import re
    patterns = [
        (r'nmap\s+-p-', 'nmap_full'), (r'nmap\s+.*-sCV', 'nmap_scripts'),
        (r'GetUserSPNs', 'kerberoast'), (r'GetNPUsers', 'asreproast'),
        (r'secretsdump', 'secretsdump'), (r'certipy', 'certipy'),
        (r'ntlmrelayx', 'ntlmrelayx'), (r'responder', 'responder'),
        (r'PetitPotam|DFSCoerce|coercer', 'coerce'),
    ]
    for pat, act in patterns:
        if re.search(pat, cmd, re.I):
            action = act
            break

    if action and fp != 'unknown':
        blocked = pl.get_amended_preconditions(action, fp)
        for b in blocked:
            print(b)
    pl.close()
except:
    pass
" 2>/dev/null || echo '')

if [ -n "$LEDGER_BLOCKED" ]; then
    printf '[TAR LEDGER] %s\n' "$LEDGER_BLOCKED"
fi

# ── Technique prerequisite check via TechniqueAdvisor ──
PREREQ_WARN=$(python3 -c "
import sys, re
sys.path.insert(0, '$ROOT/.claude/scripts')

cmd = '''$COMMAND'''

# Detect action from command
action = ''
patterns = [
    (r'GetUserSPNs', 'kerberoast'), (r'GetNPUsers', 'asreproast'),
    (r'secretsdump', 'secretsdump'), (r'certipy\s+find', 'certipy'),
    (r'certipy\s+req', 'certipy'), (r'psexec', 'psexec'),
    (r'wmiexec', 'wmiexec'), (r'evil-winrm', 'evil_winrm'),
    (r'ntlmrelayx', 'ntlmrelayx'), (r'responder', 'responder'),
    (r'PetitPotam', 'petitpotam'), (r'bloodhound', 'bloodhound'),
    (r'rbcd|resource.based', 'rbcd'), (r'dcsync|DCSync', 'dcsync'),
    (r'hydra', 'hydra'), (r'sqlmap', 'sqlmap'),
]
for pat, act in patterns:
    if re.search(pat, cmd, re.I):
        action = act
        break

if action:
    try:
        from technique_advisor import get_advisor
        from world_model import WorldModel

        advisor = get_advisor()
        prereqs = advisor.get_prerequisites(action)

        if prereqs:
            wm = WorldModel('$WM_DB')
            services = wm.get_services()
            predicates = wm.get_state_predicates()
            creds = wm.get_creds()
            wm.close()

            ports = set(s['port'] for s in services)
            state = {
                'ports': ports,
                'predicates': predicates,
                'has_cred': bool(creds),
                'has_admin_cred': any(c.get('is_admin') for c in creds),
                'has_domain_cred': any(c.get('domain') for c in creds),
            }

            all_met, unmet = advisor.check_prerequisites_against_state(action, state)
            if unmet:
                for u in unmet[:3]:
                    print(f'PREREQ: {u}')
    except Exception:
        pass
" 2>/dev/null || echo '')

if [ -n "$PREREQ_WARN" ]; then
    printf '[TAR TECHNIQUE CHECK]\n%s\n' "$PREREQ_WARN"
fi

# Pre-attack platform check on first pentest tool invocation
case "$COMMAND" in
    *nmap*|*netexec*|*crackmapexec*|*smbclient*|*impacket*|*evil-winrm*|*rpcclient*|*ldapsearch*|*bloodhound*|*certipy*|*responder*|*ntlmrelayx*)
        TARGET_IP=$(echo "$COMMAND" | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1 || echo '')
        if [ -n "$TARGET_IP" ]; then
            # Only run platform check once per session (use a flag file)
            CHECK_FLAG="$CURRENT_REAL/.tar_platform_checked"
            if [ ! -f "$CHECK_FLAG" ]; then
                ISSUES=""
                # VPN routing
                if ! ip route get "$TARGET_IP" 2>/dev/null | grep -q "tun\|tap"; then
                    ISSUES="${ISSUES}[!] No VPN route to $TARGET_IP (no tun/tap device)\n"
                fi
                # Port conflicts
                CONFLICTS=$(ss -tlnp 2>/dev/null | grep -E ":445\b|:80\b|:389\b" | head -3 || true)
                if [ -n "$CONFLICTS" ]; then
                    ISSUES="${ISSUES}[!] Port conflicts detected:\n${CONFLICTS}\n"
                fi
                # Process conflicts
                PROCS=$(ps aux 2>/dev/null | grep -E "responder|ntlmrelayx" | grep -v grep || true)
                if [ -n "$PROCS" ]; then
                    ISSUES="${ISSUES}[!] Existing relay/responder processes:\n${PROCS}\n"
                fi

                if [ -n "$ISSUES" ]; then
                    printf '[TAR PLATFORM CHECK]\n%b' "$ISSUES"
                fi
                touch "$CHECK_FLAG"
            fi
        fi
        ;;
esac
