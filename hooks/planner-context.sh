#!/usr/bin/env bash
set -euo pipefail

# TAR Planner Context Hook v2 (UserPromptSubmit)
# Injects: world state + ranked actions + HackTricks technique context + failure guidance
# Must complete in <3s for responsive UX (knowledge index cached at ~0.4s).

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

# Get ranked actions + filled commands + knowledge context in a single Python call
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
services = summary.get('services', [])
wm.close()

# Rank top 10 actions
ranked = rank_actions(db, last_action=last, top_n=10)
action_names = [a['name'] for a in ranked]

# Fill parameters for all ranked actions
filled = fill_multiple(db, action_names)

# ── Load knowledge index + technique advisor (cached, ~0.4s) ──
try:
    from knowledge_index import get_index
    from technique_advisor import get_advisor
    ki = get_index()
    advisor = get_advisor()
    has_knowledge = True
except Exception:
    has_knowledge = False

# ── Build compact state block ──
state_lines = []
state_lines.append(f'Phase: {phase}')
if services:
    ports = [f\"{s['port']}/{s.get('product','?')[:15]}\" for s in services[:12]]
    state_lines.append(f\"Services: {', '.join(ports)}\")

    # Version-specific vuln check (if knowledge available)
    if has_knowledge:
        for s in services[:6]:
            product = s.get('product', '')
            version = s.get('version', '')
            if product and version:
                vulns = ki.get_version_vulns(product, version)
                if vulns:
                    for v in vulns[:1]:
                        state_lines.append(f\"[!] {product} {version}: see {v['heading'][:60]}\")

if summary.get('creds'):
    creds = [f\"{c['user']}@{c.get('domain','?')}({'pw' if c.get('has_password') else 'hash'})\" for c in summary['creds'][:5]]
    state_lines.append(f\"Creds: {', '.join(creds)}\")
if summary.get('critical_findings'):
    for f in summary['critical_findings'][:3]:
        state_lines.append(f\"Finding [{f['category']}]: {f['desc'][:60]}\")
if failed_list:
    state_lines.append(f\"Failed: {', '.join(failed_list[:8])}\")

# ── Stuck detection + lockout guard warnings ──
try:
    from world_model import WorldModel as _WM3
    _wm3 = _WM3(db)
    stuck_findings = _wm3.get_findings(category='stuck_detection')
    _wm3.close()
    for sf in stuck_findings[-1:]:
        state_lines.append(f\"[STUCK] {sf['description'][:100]}\")
except Exception:
    pass

print('## TAR World State')
for l in state_lines:
    print(l)

# ── Failure Analysis with HackTricks guidance ──
if failed_list:
    wm2 = WorldModel(db)
    recent_failures = wm2.get_failed_attempts()
    wm2.close()

    print()
    print('## Failure Analysis')
    seen = set()
    for f in recent_failures[-5:]:
        aname = f['action_name']
        if aname in seen:
            continue
        seen.add(aname)
        silence = f.get('silence_pattern') or f.get('error_output') or 'no output'
        silence_short = silence[:80]
        print(f'- **{aname}** failed: {silence_short}')

        # Inject HackTricks failure guidance
        if has_knowledge:
            try:
                interp = advisor.get_failure_interpretation(aname, silence)
                if interp and not interp.startswith('No specific'):
                    # Trim to 2 lines max
                    interp_lines = interp.split(chr(10))[:2]
                    for il in interp_lines:
                        il = il.strip()
                        if il:
                            print(f'  → {il[:120]}')
            except Exception:
                pass

    print()
    print('**Before next action**: State what the failure teaches you about the target.')
    print('Do NOT retry with same parameters. Choose an action that tests a DIFFERENT hypothesis.')

    # When stuck (>=2 failures), suggest alternatives from HackTricks/PAT
    if has_knowledge and len(set(f['action_name'] for f in recent_failures[-4:])) >= 2:
        try:
            svc_tuples = [(s['port'], s.get('product', '')) for s in services[:5]]
            last_failed = recent_failures[-1]['action_name']
            alts = ki.get_alternatives(last_failed, services=svc_tuples)
            if alts:
                print()
                print('## Alternative Approaches (from HackTricks/PAT)')
                for a in alts[:3]:
                    print(f'- **{a[\"heading\"][:50]}** [{a[\"source\"]}]: {a[\"text\"][:100]}...')
        except Exception:
            pass

# ── Engagement Profile ──
try:
    import os as _os, sys as _sys
    _sys.path.insert(0, '$SCRIPTS_DIR')
    from engagement_profile import EngagementProfile
    ep = EngagementProfile(engagement_dir=_os.path.dirname(db))
    print()
    print('## Engagement Profile')
    print(ep.summary())
    if not ep.allow_destructive:
        print('[!] Destructive actions BLOCKED — set allow_destructive: true in engagement_profile.yml to enable them')
except Exception:
    pass

# ── Visual Perception (auto-capture web targets not yet screenshotted) ──
# Guard: only import perception_engine (which loads playwright) if web services exist
_web_svc_ports = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000}
_web_services = [s for s in services if s.get('port') in _web_svc_ports]
if _web_services:
    try:
        import os as _os2, re as _re2, pathlib as _pathlib
        from perception_engine import perceive_web_target
        screenshots_dir = _pathlib.Path(_os2.path.dirname(db)) / 'screenshots'
        already_shot = set(f.stem for f in screenshots_dir.iterdir()) if screenshots_dir.exists() else set()
        from world_model import WorldModel as _WM2
        _wm2 = _WM2(db)
        _hosts = _wm2.get_hosts()
        _wm2.close()
        if _hosts:
            ip = _hosts[0].get('ip', '')
            for svc in _web_services[:2]:
                port = svc.get('port', 80)
                scheme = 'https' if port in (443, 8443) else 'http'
                url = f'{scheme}://{ip}:{port}/'
                safe_key = _re2.sub(r'[^\w]', '_', url)[:60]
                print()
                if safe_key in already_shot:
                    print(f'## Visual Perception — {url}')
                    print(f'Screenshot on file → \`{screenshots_dir}/{safe_key}.png\` (use Read tool to view image)')
                else:
                    block = perceive_web_target(url, db, screenshots_dir)
                    print(block)
    except Exception:
        pass

# ── Ranked Action Table with Technique Context ──
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

    # Inject mechanism from HackTricks (for top-3 only, to save tokens)
    if has_knowledge and i <= 3:
        try:
            brief = advisor.get_mechanism_brief(name)
            if brief:
                # Cap at 150 chars
                brief = brief[:150]
                if len(brief) == 150:
                    brief = brief[:brief.rfind(' ')] + '...'
                print(f'    Mechanism: {brief}')
        except Exception:
            mech = r.get('mechanism','')[:100]
            if mech:
                print(f'    Mechanism: {mech}')
    else:
        mech = r.get('mechanism','')[:100]
        if mech:
            print(f'    Mechanism: {mech}')
    print()

# ── Attack chain planner: suggest multi-step path to phase goal ──
try:
    from attack_chain_planner import load_actions as _load_actions, plan_chain, extract_state_predicates
    phase_to_goal = {
        'recon': 'initial_foothold',
        'foothold': 'credential_access',
        'user': 'root_access',
        'privesc': 'root_access',
        'root': 'domain_admin',
        'cloud': 'cloud_data_exfil',
    }
    goal = phase_to_goal.get(phase, 'root_access')
    state = extract_state_predicates(db)
    chain_actions = _load_actions()
    chain = plan_chain(goal, state, chain_actions, max_depth=4)
    if chain:
        print(f'## Suggested Chain → {goal} ({len(chain)} steps)')
        for i, a in enumerate(chain, 1):
            effects = ', '.join(sorted(a['_effects']))[:60]
            print(f'  {i}. [{a.get(\"category\",\"?\")}] **{a[\"name\"]}** → {effects}')
        print()
    elif chain == []:
        print(f'## Chain Planner: {goal} already satisfied')
        print()
except Exception:
    pass
" 2>/dev/null || echo '## TAR: planner-context error')

printf '%s\n' "$CONTEXT"
