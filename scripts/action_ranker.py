#!/usr/bin/env python3
"""
action_ranker.py — Ranks applicable TAR actions by contextual relevance.

Scoring signals:
  1. Phase relevance   — How often this action appears in current phase (walkthrough-learned)
  2. Service specificity — How many service-specific preconditions are satisfied
  3. Transition score  — P(this_action | last_action, phase) from walkthrough data
  4. Information gain   — Enumeration before exploitation preference
  5. Failure penalty    — Already-failed actions get suppressed

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

# Transition model cache (built once, reused)
_transition_cache = None
_phase_freq_cache = None


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


def load_all_actions() -> list[dict]:
    """Load all action YAML definitions."""
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
) -> float:
    """
    Score an action. Higher = more relevant.

    Returns -1.0 for actions that should be excluded.
    """
    name = action["name"]

    # Hard exclusions
    if name in failed_actions:
        return -1.0
    if name in ledger_blocked:
        return -0.5  # Soft penalty, not hard block

    # Precondition check
    if not check_preconditions(action, predicates):
        return -1.0

    _build_walkthrough_model()
    score = 0.0

    # 1. Phase relevance (0-30 points)
    phase_probs = _phase_freq_cache.get(phase, {})
    phase_prob = phase_probs.get(name, 0.0)
    # Log-scale to avoid domination by curl_request
    if phase_prob > 0:
        score += 30.0 * (1.0 + math.log10(phase_prob * 100 + 1)) / 3.0
    # Small bonus for actions in adjacent phases
    phase_idx = PHASE_ORDER.get(phase, 0)
    for adj_phase, adj_idx in PHASE_ORDER.items():
        if abs(adj_idx - phase_idx) == 1:
            adj_prob = _phase_freq_cache.get(adj_phase, {}).get(name, 0.0)
            if adj_prob > 0:
                score += 3.0

    # 2. Service specificity (0-20 points)
    specificity = count_specific_preconditions(action)
    score += min(specificity * 5.0, 20.0)

    # 3. Transition score (0-25 points)
    if last_action:
        key = f"{phase}:{last_action}"
        trans_probs = _transition_cache.get(key, {})
        trans_prob = trans_probs.get(name, 0.0)
        if trans_prob > 0:
            trans_score = 25.0 * min(trans_prob * 3.0, 1.0)
            # Penalize self-transitions (same action again) — diversity matters
            if name == last_action:
                trans_score *= 0.4
            score += trans_score
        # Also check cross-phase transitions
        for p in PHASE_ORDER:
            alt_key = f"{p}:{last_action}"
            alt_prob = _transition_cache.get(alt_key, {}).get(name, 0.0)
            if alt_prob > 0.1:
                score += 5.0
                break

    # 4. Information gain preference (0-15 points)
    phase_idx = PHASE_ORDER.get(phase, 0)
    if name in ENUM_ACTIONS:
        # Enum actions get bonus in early phases, less in late phases
        score += max(15.0 - phase_idx * 3.0, 3.0)
    elif name in EXPLOIT_ACTIONS:
        # Exploit actions get bonus in later phases
        score += min(phase_idx * 3.0, 12.0)

    # 5. Category relevance (0-10 points)
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

    scored = []
    for action in all_actions:
        s = score_action(action, phase, predicates, last_action, failed, ledger_blocked)
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
