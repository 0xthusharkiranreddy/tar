#!/usr/bin/env python3
"""
action_ranker.py — v2.1: Knowledge-driven action ranking for TAR.

Scoring signals (v2.1):
  1. Phase relevance      (25 pts) — Phase-appropriate action selection
  2. Knowledge match      (30 pts) — HackTricks/PAT prerequisite + product-version matching
  3. Service specificity  (20 pts) — How many service-specific preconditions match
  4. Information gain     (15 pts) — Enumeration before exploitation preference
  5. Transition hint      (10 pts) — Walkthrough P(next|last) as tiebreaker only
  6. Profile modifier     (variable, can be negative) — Engagement profile noise/destructive penalty
  7. Redundancy penalty   (-15 pts) — Down-rank repeated tool-class actions in same phase

Usage:
    python3 action_ranker.py <world_model.db> [--last-action ACTION] [--top N]
"""

import json
import math
import sqlite3
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Optional

import yaml

ACTIONS_DIR = Path("/home/kali/knowledge/actions")
WALKTHROUGHS_DIR = Path("/home/kali/knowledge/walkthroughs")
SCRIPTS_DIR = Path("/home/kali/.claude/scripts")
LEDGER_DB = Path("/home/kali/knowledge/predicate_ledger.db")

# Tool-class groupings for redundancy down-rank (gap 7: web enum loop)
TOOL_CLASS = {
    "gobuster": "web_content_enum",
    "ffuf": "web_content_enum",
    "feroxbuster": "web_content_enum",
    "dirb": "web_content_enum",
    "wfuzz": "web_content_enum",
    "nikto": "web_vuln_scan",
    "whatweb": "web_tech_detect",
    "nmap_full": "port_scan",
    "nmap_targeted": "port_scan",
    "nmap_scripts": "port_scan",
    "nmap_udp": "port_scan",
    "kerbrute_spray": "credential_spray",
    "hydra": "credential_spray",
    "crackmapexec_spray": "credential_spray",
    "kerberoast": "kerberos_attack",
    "asreproast": "kerberos_attack",
    "blind_kerberoast": "kerberos_attack",
    "targeted_kerberoast": "kerberos_attack",
    "timeroast": "kerberos_attack",
    "responder": "poisoning",
    "mitm6": "poisoning",
    "ntlm_theft_file_drop": "poisoning",
    "enum4linux_ng": "smb_enum",
    "smb_null_session": "smb_enum",
    "smb_share_enum": "smb_enum",
    "smb_user_enum": "smb_enum",
    "rid_brute": "smb_enum",
    "ldap_anon": "ldap_enum",
    "ldapsearch": "ldap_enum",
    "ldapdomaindump": "ldap_enum",
    "ldap_enum": "ldap_enum",
    "bloodhound": "bloodhound_enum",
    "bloodhound_analysis": "bloodhound_enum",
    "lsass_procdump": "lsass_dump",
    "lsass_comsvcs": "lsass_dump",
    "secretsdump": "cred_dump",
    "sam_offline_dump": "cred_dump",
    "mscache2_dump": "cred_dump",
}

# Transition model cache (built once, reused)
_transition_cache = None
_phase_freq_cache = None

# Knowledge layer cache (lazy-loaded)
_knowledge_index = None
_technique_advisor = None


def _get_knowledge():
    """Lazy-load knowledge index and technique advisor."""
    global _knowledge_index, _technique_advisor
    if _knowledge_index is None:
        try:
            from knowledge_index import get_index
            from technique_advisor import get_advisor
            _knowledge_index = get_index()
            _technique_advisor = get_advisor()
        except Exception:
            pass
    return _knowledge_index, _technique_advisor


def _build_walkthrough_model():
    """Build transition and phase-frequency models from walkthrough corpus."""
    global _transition_cache, _phase_freq_cache

    if _transition_cache is not None:
        return

    transitions = defaultdict(Counter)  # "phase:prev_action" → Counter(next_action)
    phase_freq = defaultdict(Counter)    # phase → Counter(action)
    phase_totals = Counter()             # phase → total known-action steps

    for box_dir in WALKTHROUGHS_DIR.iterdir():
        steps_file = box_dir / "steps.json"
        if not steps_file.exists():
            continue
        try:
            data = json.loads(steps_file.read_text())
            steps = data.get("steps", []) if isinstance(data, dict) else data
        except (json.JSONDecodeError, OSError):
            continue

        prev_action = None
        prev_phase = None
        for s in steps:
            action = s.get("action", "unknown")
            phase = s.get("phase", "unknown")
            if action == "unknown":
                prev_action = None
                continue
            phase_freq[phase][action] += 1
            phase_totals[phase] += 1
            if prev_action:
                key = f"{prev_phase}:{prev_action}"
                transitions[key][action] += 1
            prev_action = action
            prev_phase = phase

    # Normalize phase frequencies to probabilities
    phase_prob = {}
    for phase, counts in phase_freq.items():
        total = phase_totals[phase]
        phase_prob[phase] = {action: count / total for action, count in counts.items()}

    # Normalize transitions to probabilities
    trans_prob = {}
    for key, counts in transitions.items():
        total = sum(counts.values())
        trans_prob[key] = {action: count / total for action, count in counts.items()}

    _transition_cache = trans_prob
    _phase_freq_cache = phase_prob


_actions_cache = None
_actions_cache_mtime = 0


def load_all_actions() -> list[dict]:
    """Load all action YAML definitions. Cached across calls within the process."""
    global _actions_cache, _actions_cache_mtime

    # Check mtime of actions dir — cheap invalidation
    try:
        mtime = max(
            (f.stat().st_mtime for f in ACTIONS_DIR.rglob("*.yml")),
            default=0,
        )
    except Exception:
        mtime = 0

    if _actions_cache is not None and mtime == _actions_cache_mtime:
        return _actions_cache

    actions = []
    for yml_file in sorted(ACTIONS_DIR.rglob("*.yml")):
        try:
            with open(yml_file) as f:
                action = yaml.safe_load(f)
            if action and "name" in action:
                action["_path"] = str(yml_file)
                actions.append(action)
        except Exception:
            continue

    _actions_cache = actions
    _actions_cache_mtime = mtime
    return actions


def get_predicates_from_db(db_path: str) -> set[str]:
    """Get current state predicates from world_model."""
    sys.path.insert(0, str(SCRIPTS_DIR))
    from world_model import WorldModel
    wm = WorldModel(db_path)
    predicates = wm.get_state_predicates()
    wm.close()
    return predicates


def get_failed_actions(db_path: str) -> set[str]:
    """Get actions that have already failed in this engagement."""
    sys.path.insert(0, str(SCRIPTS_DIR))
    from world_model import WorldModel
    wm = WorldModel(db_path)
    failed = wm.get_failed_attempts()
    wm.close()
    return {f["action_name"] for f in failed}


def get_current_phase(db_path: str) -> str:
    sys.path.insert(0, str(SCRIPTS_DIR))
    from world_model import WorldModel
    wm = WorldModel(db_path)
    phase = wm.current_phase()
    wm.close()
    return phase


def check_preconditions(action: dict, predicates: set[str]) -> bool:
    """Check if all preconditions of an action are met."""
    for pre in action.get("preconditions", []):
        pre = pre.strip()
        if "==" in pre:
            if pre not in predicates:
                return False
        else:
            if not any(pre in p for p in predicates):
                return False
    return True


def count_specific_preconditions(action: dict) -> int:
    """Count service-specific preconditions (more specific = higher rank)."""
    count = 0
    for pre in action.get("preconditions", []):
        pre = pre.strip()
        if pre.startswith("service.port=="):
            count += 2  # Port-specific is very informative
        elif pre.startswith("service.product=="):
            count += 3  # Product-specific is even more informative
        elif pre.startswith("os=="):
            count += 1
        elif pre == "domain_joined":
            count += 1
    return count


# Action categories by information gain tendency
ENUM_ACTIONS = {
    "nmap_full", "nmap_scripts", "nmap_targeted", "nmap_udp",
    "feroxbuster", "gobuster", "ffuf", "wfuzz", "nikto", "whatweb",
    "enum4linux_ng", "smb_share_enum", "smb_null_session", "smb_guest_access",
    "smbclient_list_shares", "rid_brute", "rpcclient", "smb_user_enum",
    "crackmapexec_spray", "winrm_check", "rdp_check", "dns_enum",
    "ldap_anon", "ldapsearch", "ldap_enum", "rpc_enum",
    "bloodhound", "kerberos_enum", "kerbrute_userenum",
    "linpeas", "winpeas", "sudo_check", "suid_check", "capabilities_check",
    "cron_check", "writable_files", "kernel_check",
    "curl_request", "subdomain_enum", "api_enum", "git_dump",
    "web_agent", "fuzz_agent",
}

EXPLOIT_ACTIONS = {
    "psexec", "wmiexec", "evil_winrm", "ssh", "netcat", "metasploit",
    "sqli_union", "sqli_error", "sqlmap", "command_injection", "lfi", "rfi",
    "ssti", "deserialization", "file_upload", "xxe", "ssrf",
    "kerberoast", "asreproast", "secretsdump", "dcsync",
    "certipy", "golden_ticket", "silver_ticket",
    "godpotato", "printspoofer", "potato_attack",
    "hydra", "hashcat", "john",
}

# Phase ordering for info-gain calculation
PHASE_ORDER = {"recon": 0, "foothold": 1, "user": 2, "privesc": 3, "root": 4}


def score_action(
    action: dict,
    phase: str,
    predicates: set[str],
    last_action: Optional[str],
    failed_actions: set[str],
    ledger_blocked: set[str],
    services_info: Optional[list] = None,
    profile=None,
    recent_same_class: Optional[set] = None,
) -> float:
    """
    Score an action (v2.1: knowledge-driven + profile-aware). Higher = more relevant.

    Returns -1.0 for actions that should be excluded.

    Scoring signals:
      1. Phase relevance      (0-25 pts) — Phase-appropriate via walkthrough + category
      2. Knowledge match      (0-30 pts) — HackTricks prerequisite depth + product-version
      3. Service specificity  (0-20 pts) — Precondition coverage
      4. Information gain     (0-15 pts) — Enum before exploit
      5. Transition hint      (0-10 pts) — Walkthrough P(next|last) as tiebreaker
      6. Profile modifier     (variable) — Engagement noise/destructive penalty
      7. Redundancy penalty   (-15 pts)  — Down-rank repeated tool-class in same phase
    """
    name = action["name"]

    # Hard exclusions
    if name in failed_actions:
        return -1.0
    if name in ledger_blocked:
        return -0.5

    # Precondition check (YAML preconditions)
    if not check_preconditions(action, predicates):
        return -1.0

    _build_walkthrough_model()
    ki, advisor = _get_knowledge()
    score = 0.0

    # ── 1. Phase relevance (0-25 points) ──
    # Combines walkthrough frequency + category bonus
    phase_probs = _phase_freq_cache.get(phase, {})
    phase_prob = phase_probs.get(name, 0.0)
    if phase_prob > 0:
        score += 15.0 * (1.0 + math.log10(phase_prob * 100 + 1)) / 3.0
    # Small bonus for actions in adjacent phases
    phase_idx = PHASE_ORDER.get(phase, 0)
    for adj_phase, adj_idx in PHASE_ORDER.items():
        if abs(adj_idx - phase_idx) == 1:
            adj_prob = _phase_freq_cache.get(adj_phase, {}).get(name, 0.0)
            if adj_prob > 0:
                score += 2.0

    # Category relevance within phase (0-10 points, part of phase relevance)
    category = action.get("category", "")
    phase_category_bonus = {
        "recon": {"recon": 10, "smb": 5, "web": 3, "services": 3},
        "foothold": {"web": 10, "services": 8, "smb": 7, "ad": 5, "creds": 5, "shell": 8},
        "user": {"ad": 8, "creds": 8, "shell": 7, "web": 5, "smb": 5, "services": 5},
        "privesc": {"privesc": 10, "ad": 8, "creds": 6, "shell": 5},
        "root": {"privesc": 10, "ad": 10, "creds": 5, "shell": 5},
    }
    cat_bonuses = phase_category_bonus.get(phase, {})
    score += cat_bonuses.get(category, 0)

    # ── 2. Knowledge match (0-30 points) ──
    if ki is not None and advisor is not None:
        knowledge_pts = 0.0

        # 2a. Product-version matching (0-15 points)
        # Only for exploit-type actions — enum actions don't benefit from vuln matching
        if services_info and name in EXPLOIT_ACTIONS:
            for svc in services_info[:6]:
                port = svc.get('port', 0)
                product = svc.get('product', '')
                version = svc.get('version', '')
                action_preconds = action.get("preconditions", [])
                port_match = any(f"service.port=={port}" in p for p in action_preconds)
                if port_match and product and version:
                    vulns = ki.get_version_vulns(product, version)
                    if vulns:
                        knowledge_pts += 15.0
                        break
                elif port_match and product:
                    knowledge_pts += 5.0
                    break

        # 2b. HackTricks technique depth (0-10 points)
        # Actions with dedicated HackTricks pages get a bonus
        try:
            ctx = ki.get_technique_context(name, max_chars=100)
            if ctx:
                knowledge_pts += 5.0
                # Extra bonus if context is from a dedicated page (not a passing mention)
                if len(ctx) > 80:
                    knowledge_pts += 5.0
        except Exception:
            pass

        # 2c. Prerequisite confidence (0-5 points)
        # Actions with curated prerequisites in technique_advisor get a bonus
        # (we've validated they're well-understood techniques)
        from technique_advisor import PREREQUISITES
        if name in PREREQUISITES:
            knowledge_pts += 5.0

        score += min(knowledge_pts, 30.0)
    else:
        # Fallback: give a small bonus to actions with mechanism descriptions
        if action.get("mechanism"):
            score += 5.0

    # ── 3. Service specificity (0-20 points) ──
    specificity = count_specific_preconditions(action)
    score += min(specificity * 5.0, 20.0)

    # ── 4. Information gain preference (0-15 points) ──
    phase_idx = PHASE_ORDER.get(phase, 0)
    if name in ENUM_ACTIONS:
        score += max(15.0 - phase_idx * 3.0, 3.0)
    elif name in EXPLOIT_ACTIONS:
        score += min(phase_idx * 3.0, 12.0)

    # ── 5. Transition hint (0-10 points) — demoted from v1's 25 ──
    if last_action:
        key = f"{phase}:{last_action}"
        trans_probs = _transition_cache.get(key, {})
        trans_prob = trans_probs.get(name, 0.0)
        if trans_prob > 0:
            trans_score = 10.0 * min(trans_prob * 3.0, 1.0)
            if name == last_action:
                trans_score *= 0.4
            score += trans_score
        for p in PHASE_ORDER:
            alt_key = f"{p}:{last_action}"
            alt_prob = _transition_cache.get(alt_key, {}).get(name, 0.0)
            if alt_prob > 0.1:
                score += 3.0
                break

    # ── 6. Engagement profile modifier (variable) ──
    # Applies noise penalty and destructive-action blocking from engagement_profile.yml
    if profile is not None:
        modifier = profile.action_score_modifier(name)
        if modifier <= -100:
            return -1.0  # hard block (destructive in non-destructive profile)
        score += modifier

    # ── 7. Redundancy penalty (-15 pts) ──
    # Down-rank if the same tool class was run recently (prevents web-enum loops)
    if recent_same_class and TOOL_CLASS.get(name):
        my_class = TOOL_CLASS[name]
        if my_class in recent_same_class:
            score -= 15.0

    return round(score, 2)


def get_ledger_blocked(db_path: str) -> set[str]:
    """Get actions blocked by cross-engagement predicate ledger."""
    if not LEDGER_DB.exists():
        return set()
    try:
        sys.path.insert(0, str(SCRIPTS_DIR))
        from world_model import WorldModel
        from predicate_ledger import PredicateLedger

        wm = WorldModel(db_path)
        services = wm.conn.execute(
            "SELECT port, product FROM services WHERE host_id=1 LIMIT 10"
        ).fetchall()
        host = wm.conn.execute("SELECT os FROM hosts LIMIT 1").fetchone()
        os_name = host[0] if host else ""
        wm.close()

        pl = PredicateLedger()
        fp = pl.compute_fingerprint(
            os_name=os_name,
            services=[(s[0], s[1]) for s in services]
        )
        blocked = set()
        if fp != "unknown":
            # Check each action
            conn = sqlite3.connect(str(LEDGER_DB))
            rows = conn.execute(
                "SELECT DISTINCT action FROM failure_predicates WHERE fingerprint=? AND count >= 3",
                (fp,)
            ).fetchall()
            conn.close()
            blocked = {r[0] for r in rows}
        pl.close()
        return blocked
    except Exception:
        return set()


def rank_actions(
    db_path: str,
    last_action: Optional[str] = None,
    top_n: int = 15,
) -> list[dict]:
    """
    Main entry: rank all applicable actions for current world state.

    Returns list of {name, category, description, mechanism, score, command_template}
    sorted by score descending.
    """
    predicates = get_predicates_from_db(db_path)
    phase = get_current_phase(db_path)
    failed = get_failed_actions(db_path)
    ledger_blocked = get_ledger_blocked(db_path)
    all_actions = load_all_actions()

    # Get service info for knowledge-driven scoring
    services_info = None
    try:
        sys.path.insert(0, str(SCRIPTS_DIR))
        from world_model import WorldModel
        wm = WorldModel(db_path)
        services_info = wm.get_services()
        wm.close()
    except Exception:
        pass

    # Load engagement profile for signal 6
    profile = None
    try:
        import os
        sys.path.insert(0, str(SCRIPTS_DIR))
        from engagement_profile import EngagementProfile
        engagement_dir = os.path.dirname(db_path)
        profile = EngagementProfile(engagement_dir=engagement_dir)
    except Exception:
        pass

    # Build recent_same_class for signal 7 (redundancy down-rank)
    # Look at the last 6 completed actions in WM failed+succeeded list
    recent_same_class: set[str] = set()
    try:
        from world_model import WorldModel
        wm2 = WorldModel(db_path)
        # Use failed actions + last_action as proxy for recently-run tool classes
        recent_actions = list(failed)
        if last_action:
            recent_actions.append(last_action)
        # Also pull from attack_paths (completed action sequence)
        rows = wm2.conn.execute(
            "SELECT action FROM attack_paths ORDER BY id DESC LIMIT 8"
        ).fetchall()
        recent_actions += [r[0] for r in rows if r[0]]
        wm2.close()
        for act_name in recent_actions:
            tc = TOOL_CLASS.get(act_name)
            if tc:
                recent_same_class.add(tc)
    except Exception:
        pass

    scored = []
    for action in all_actions:
        s = score_action(
            action, phase, predicates, last_action, failed, ledger_blocked,
            services_info=services_info,
            profile=profile,
            recent_same_class=recent_same_class,
        )
        if s < 0:
            continue
        scored.append({
            "name": action["name"],
            "category": action.get("category", ""),
            "description": action.get("description", ""),
            "mechanism": action.get("mechanism", ""),
            "command_template": action.get("command_template", ""),
            "preconditions": action.get("preconditions", []),
            "score": s,
        })

    scored.sort(key=lambda x: -x["score"])
    return scored[:top_n]


def main():
    import argparse
    parser = argparse.ArgumentParser(description="TAR Action Ranker")
    parser.add_argument("db_path", help="Path to world_model.db")
    parser.add_argument("--last-action", help="Previous action name for transition scoring")
    parser.add_argument("--top", type=int, default=15, help="Number of actions to return")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    ranked = rank_actions(args.db_path, last_action=args.last_action, top_n=args.top)

    if args.json:
        print(json.dumps(ranked, indent=2))
    else:
        phase = get_current_phase(args.db_path)
        print(f"Phase: {phase} | Last action: {args.last_action or 'none'}")
        print(f"{'Rank':>4} {'Score':>6} {'Action':<30} {'Category':<12} Description")
        print("-" * 100)
        for i, a in enumerate(ranked, 1):
            print(f"{i:>4} {a['score']:>6.1f} {a['name']:<30} {a['category']:<12} {a['description'][:50]}")


if __name__ == "__main__":
    main()
