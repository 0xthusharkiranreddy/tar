#!/usr/bin/env bash
set -euo pipefail

# TAR Planner Context Hook (UserPromptSubmit)
# Injects ranked actions + filled commands + state summary into each prompt.
# Must complete in <2s for responsive UX.

ROOT=/home/kali
CURRENT_REAL=$(readlink -f "$ROOT/current" 2>/dev/null || printf '%s' "$ROOT/current")
WM_DB="$CURRENT_REAL/world_model.db"
SCRIPTS_DIR="$ROOT/.claude/scripts"

# Only run if world_model exists (active TAR engagement)
[ -f "$WM_DB" ] || exit 0

# Detect last action from session state (if available)
LAST_ACTION=""
STATE_FILE="$CURRENT_REAL/notes/session_state.md"
if [ -f "$STATE_FILE" ]; then
    LAST_ACTION=$(grep -oP '(?<=Last Action: )\S+' "$STATE_FILE" 2>/dev/null | tail -1 || echo '')
fi

# Get ranked actions + filled commands in a single Python call
CONTEXT=$(python3 -c "
import sys, json
sys.path.insert(0, '$SCRIPTS_DIR')

from action_ranker import rank_actions, get_current_phase
from param_filler import fill_multiple, get_fill_context
from world_model import WorldModel

db = '$WM_DB'
last = '$LAST_ACTION' or None

# Phase + state summary
wm = WorldModel(db)
summary = wm.get_state_summary()
phase = wm.current_phase()
failed_list = summary.get('failed_actions', [])
wm.close()

# Rank top 10 actions
ranked = rank_actions(db, last_action=last, top_n=10)
action_names = [a['name'] for a in ranked]

# Fill parameters for all ranked actions
filled = fill_multiple(db, action_names)

# Build compact state block
state_lines = []
state_lines.append(f'Phase: {phase}')
if summary.get('services'):
    ports = [f\"{s['port']}/{s.get('product','?')[:15]}\" for s in summary['services'][:12]]
    state_lines.append(f\"Services: {', '.join(ports)}\")
if summary.get('creds'):
    creds = [f\"{c['user']}@{c.get('domain','?')}({'pw' if c.get('has_password') else 'hash'})\" for c in summary['creds'][:5]]
    state_lines.append(f\"Creds: {', '.join(creds)}\")
if summary.get('critical_findings'):
    for f in summary['critical_findings'][:3]:
        state_lines.append(f\"Finding [{f['category']}]: {f['desc'][:60]}\")
if failed_list:
    state_lines.append(f\"Failed: {', '.join(failed_list[:8])}\")

print('## TAR World State')
for l in state_lines:
    print(l)

# Failure reasoning block — only when there are recent failures
if failed_list:
    wm2 = WorldModel(db)
    recent_failures = wm2.get_failed_attempts()
    wm2.close()

    print()
    print('## Failure Analysis')
    seen = set()
    for f in recent_failures[-5:]:  # Last 5 failures
        aname = f['action_name']
        if aname in seen:
            continue
        seen.add(aname)
        silence = f.get('silence_pattern') or f.get('error_output') or 'no output'
        silence = silence[:80]
        print(f'- **{aname}** failed: {silence}')

    # Provide reasoning guidance
    print()
    print('**Before next action**: State what the failure teaches you about the target.')
    print('Do NOT retry a failed action with the same parameters.')
    print('Ask: what would produce exactly this silence/error? Then choose an action that tests a different hypothesis.')

# Build ranked action table
print()
print(f'## Top Actions (phase={phase}, last={last or \"none\"})')
print()
for i, (r, f) in enumerate(zip(ranked, filled), 1):
    ready = 'READY' if f.get('ready') else f\"NEED:{','.join(f.get('unfilled',[]))}\"
    score = r['score']
    name = r['name']
    cat = r['category']
    desc = r['description'][:55]

    print(f'{i:>2}. [{ready}] **{name}** ({cat}, score={score:.0f})')
    print(f'    {desc}')
    if f.get('ready'):
        cmd = f['command'][:120]
        print(f'    \`{cmd}\`')
    mech = r.get('mechanism','')[:100]
    if mech:
        print(f'    Mechanism: {mech}')
    print()
" 2>/dev/null || echo '## TAR: planner-context error')

printf '%s\n' "$CONTEXT"
