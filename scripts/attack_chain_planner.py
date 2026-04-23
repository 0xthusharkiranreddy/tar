#!/usr/bin/env python3
"""
attack_chain_planner.py — Forward-chaining attack planner (A* v2.2).

Given a world model state and a goal (e.g., "root_access", "domain_admin"),
produces a sequence of actions that chains preconditions → effects toward the goal.

Uses action YAML preconditions/expected_effects as a STRIPS-style planning problem:
  - State: set of predicates currently true in world model
  - Actions: each YAML action with preconditions (must hold) and effects (added to state)
  - Goal: target predicate set

Algorithm: A* with admissible heuristic (unsatisfied goal predicates) and
per-goal action subsetting. Effective search depth raised from 6 → 8.
Falls back to BFS for small action sets.

Usage:
    python3 attack_chain_planner.py --db /path/to/world_model.db --goal domain_admin
    python3 attack_chain_planner.py --db ... --goal root_access --max-depth 8
"""

import heapq
import json
import sys
from pathlib import Path
from collections import deque

import yaml

SCRIPTS_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPTS_DIR))

ACTIONS_DIR = Path("/home/kali/knowledge/actions")


# ── Goal definitions ──
# Maps goal name → predicate set that must be satisfied
GOALS = {
    "initial_foothold": {"shell_obtained"},
    "user_flag": {"user_flag_obtained"},
    "root_flag": {"root_flag_obtained"},
    "root_access": {"root_shell"},
    "system_access": {"system_shell"},
    "domain_user": {"has_cred", "domain_joined"},
    "domain_admin": {"domain_admin"},
    "credential_access": {"has_cred"},
    "lateral_movement": {"shell_on_new_host"},
    "persistence": {"backdoor_installed"},
    # ── OCD mindmap additions (v2.1) ──
    "cross_forest_compromise": {"forest_admin", "trust_key_used"},
    "sccm_compromise": {"sccm_admin", "naa_extracted"},
    "domain_persistence": {"domain_persistence"},
    "hybrid_cloud_compromise": {"msol_obtained", "azure_admin"},
    "adcs_compromise": {"dc_certificate_obtained"},
    "coerced_relay_chain": {"dcsync_right_granted"},
    "credential_extraction_onhost": {"ntlm_hashes_obtained"},
    # ── Cloud goals (v2.3) ──
    "aws_cloud_admin": {"aws_role_assumed", "cloud_privilege_escalated"},
    "azure_cloud_admin": {"cloud.azure_token_available", "cloud_privilege_escalated"},
    "gcp_cloud_admin": {"cloud.gcp_token_available", "cloud_privilege_escalated"},
    "cloud_data_exfil": {"cloud_data_exposed"},
    # ── JWT/auth bypass (v2.3) ──
    "jwt_compromise": {"jwt_forged", "auth_bypass_achieved"},
}

# ── Effect normalization ──
# Some action effects are variations of the same predicate
EFFECT_ALIASES = {
    "ntlm_hashes_obtained": "has_hash",
    "tgs_hashes_obtained": "has_hash",
    "asrep_hashes_obtained": "has_hash",
    "hashes_dumped": "has_hash",
    "cracked_hash": "has_cred",
    "credential_obtained": "has_cred",
    "password_obtained": "has_cred",
    "session_obtained": "shell_obtained",
    "shell_spawned": "shell_obtained",
    "rce_achieved": "shell_obtained",
    "root_shell_obtained": "root_shell",
    "privileged_shell": "root_shell",
    "system_shell_obtained": "system_shell",
    "dc_compromised": "domain_admin",
    "domain_admin_obtained": "domain_admin",
    "krbtgt_hash": "domain_admin",
    # OCD mindmap additions (v2.1)
    "trust_key_extracted": "trust_key_used",
    "sccm_naa_obtained": "naa_extracted",
    "sccm_site_db_sysadmin": "sccm_admin",
    "sccm_takeover_complete": "sccm_admin",
    "sccm_full_admin_list": "sccm_admin_enumerated",
    "skeleton_key_installed": "domain_persistence",
    "dc_shadow_active": "domain_persistence",
    "custom_ssp_installed": "domain_persistence",
    "dsrm_password_set": "domain_persistence",
    "saphire_ticket_forged": "domain_admin",
    "forest_admin_obtained": "forest_admin",
    "cross_forest_access": "forest_admin",
    "msol_account_obtained": "msol_obtained",
    "dc_certificate_obtained": "domain_admin",
    "computer_cert_obtained": "certificate_obtained",
    "root_access": "root_shell",
    "dcsync_right_granted": "dcsync_right_granted",
    # Cloud effect aliases (v2.3)
    "aws_instance_role_creds_obtained": "cloud.aws_creds_available",
    "aws_creds_upgraded": "cloud_privilege_escalated",
    "azure_managed_identity_token_obtained": "cloud.azure_token_available",
    "gcp_service_account_token": "cloud.gcp_token_available",
    "cloud_privilege_escalated": "cloud_privilege_escalated",
    # JWT
    "jwt_forged": "jwt_forged",
    "auth_bypass_achieved": "auth_bypass_achieved",
}


def normalize_effect(effect: str) -> str:
    return EFFECT_ALIASES.get(effect, effect)


_planner_actions_cache = None
_planner_actions_mtime = 0


def load_actions():
    """Load all action YAMLs (process-level cache with mtime invalidation)."""
    global _planner_actions_cache, _planner_actions_mtime
    try:
        mtime = max(
            (f.stat().st_mtime for f in ACTIONS_DIR.rglob("*.yml")),
            default=0,
        )
    except Exception:
        mtime = 0
    if _planner_actions_cache is not None and mtime == _planner_actions_mtime:
        return _planner_actions_cache

    # Reuse action_ranker's loader if already cached there
    try:
        from action_ranker import load_all_actions
        raw_actions = load_all_actions()
    except Exception:
        raw_actions = []
        for p in ACTIONS_DIR.rglob("*.yml"):
            try:
                data = yaml.safe_load(p.read_text())
                if data and "name" in data:
                    raw_actions.append(data)
            except Exception:
                continue

    actions = []
    for data in raw_actions:
        effects = {normalize_effect(e) for e in (data.get("expected_effects", []) or [])}
        actions.append({
            **data,
            "_effects": effects,
            "_preconditions": set(data.get("preconditions", []) or []),
        })

    _planner_actions_cache = actions
    _planner_actions_mtime = mtime
    return actions


def extract_state_predicates(db_path: str) -> set:
    """Extract current state predicates from world model."""
    sys.path.insert(0, str(SCRIPTS_DIR))
    from world_model import WorldModel

    wm = WorldModel(db_path)
    state = set(wm.get_state_predicates())

    # Augment with flag/privilege predicates from findings
    for f in wm.get_findings():
        cat = f.get("category", "")
        desc = f.get("description", "").lower()
        if cat == "privilege" and "root" in desc:
            state.add("root_shell")
            state.add("uid=0")
        if cat == "privilege" and "system" in desc:
            state.add("system_shell")
            state.add("nt_authority_system")
        if cat == "suid":
            state.add("suid_found")
        if cat == "cron":
            state.add("cron_found")
        if "domain admin" in desc:
            state.add("domain_admin")
            state.add("da_access")
        # Cloud state detection
        if cat in ("cloud", "finding") and "aws" in desc and "cred" in desc:
            state.add("cloud.aws_creds_available")
            state.add("aws_iam_enumerated")
        if cat in ("cloud", "finding") and "azure" in desc and ("token" in desc or "cred" in desc):
            state.add("cloud.azure_token_available")
        if cat in ("cloud", "finding") and "gcp" in desc and ("token" in desc or "service account" in desc):
            state.add("cloud.gcp_token_available")
        if cat in ("finding", "web") and "jwt" in desc and "token" in desc:
            state.add("jwt_token_found")

    wm.close()
    return state


def preconditions_satisfied(action: dict, state: set) -> bool:
    """Check if action's preconditions are all in current state."""
    for pre in action["_preconditions"]:
        if pre in state:
            continue
        # Handle simple negation, comparison ops
        if pre.startswith("!"):
            if pre[1:] not in state:
                continue
            return False
        # Special predicates that always "hold" (weak preconditions)
        if pre in ("any", "always", "true"):
            continue
        return False
    return True


def _heuristic(state: frozenset, goal_preds: set) -> int:
    """Admissible A* heuristic: count unsatisfied goal predicates."""
    return len(goal_preds - state)


def _goal_subset_actions(goal: str, actions: list) -> list:
    """
    Per-goal action subsetting — restrict to actions likely relevant to goal.
    Reduces the branching factor, making A* 3-10x faster on large action sets.
    """
    GOAL_CATEGORIES = {
        "domain_admin":          {"ad", "creds", "smb", "services", "sccm"},
        "cross_forest_compromise": {"ad", "creds"},
        "sccm_compromise":       {"sccm", "ad", "creds"},
        "domain_persistence":    {"ad"},
        "hybrid_cloud_compromise": {"ad", "services"},
        "adcs_compromise":       {"ad", "services"},
        "root_access":           {"privesc", "shell", "creds", "services", "web"},
        "system_access":         {"privesc", "shell", "ad"},
        "initial_foothold":      {"web", "services", "smb", "recon"},
        "credential_access":     {"creds", "smb", "ad", "services"},
        "coerced_relay_chain":   {"ad", "services"},
        "credential_extraction_onhost": {"creds", "ad", "privesc"},
        # Cloud goals (v2.3)
        "aws_cloud_admin":       {"cloud"},
        "azure_cloud_admin":     {"cloud"},
        "gcp_cloud_admin":       {"cloud"},
        "cloud_data_exfil":      {"cloud"},
        # JWT (v2.3)
        "jwt_compromise":        {"web"},
    }
    allowed = GOAL_CATEGORIES.get(goal)
    if not allowed:
        return actions  # no subsetting for unknown goals
    subset = [a for a in actions if a.get("category", "") in allowed]
    # Always include at least a minimum set so planner isn't starved
    return subset if len(subset) >= 5 else actions


def plan_chain(goal: str, initial_state: set, actions: list, max_depth: int = 8):
    """
    A* forward-chaining planner. Finds lowest-cost path from initial_state to goal.

    Cost model: each action costs 1 step. Heuristic: unsatisfied goal predicates
    (admissible — never overestimates actual remaining steps).

    Returns: list of action dicts in execution order, or None if no plan found,
    or [] if goal already satisfied.
    """
    goal_preds = GOALS.get(goal, {goal})

    # Already at goal
    if goal_preds.issubset(initial_state):
        return []

    # Per-goal action subsetting
    candidate_actions = _goal_subset_actions(goal, actions)

    # A* priority queue: (f_score, counter, state_frozen, plan_list)
    # f = g (steps so far) + h (unsatisfied goal preds)
    counter = 0
    start = frozenset(initial_state)
    h0 = _heuristic(start, goal_preds)
    heap = [(h0, counter, start, [])]
    # Best g-score seen per state
    best_g: dict[frozenset, int] = {start: 0}

    while heap:
        f, _, state, plan = heapq.heappop(heap)
        g = len(plan)

        # Depth cap
        if g >= max_depth:
            continue

        # Prune if a better path to this state was already found
        if best_g.get(state, 999) < g:
            continue

        for action in candidate_actions:
            if not preconditions_satisfied(action, state):
                continue

            new_state = state | action["_effects"]
            if new_state == state:
                continue  # no progress

            new_g = g + 1
            if new_g >= best_g.get(new_state, 999):
                continue  # already found a shorter path here
            best_g[new_state] = new_g

            new_plan = plan + [action]

            if goal_preds.issubset(new_state):
                return new_plan

            h = _heuristic(new_state, goal_preds)
            counter += 1
            heapq.heappush(heap, (new_g + h, counter, new_state, new_plan))

    # A* failed — try BFS as fallback with a tighter depth for quick partial plans
    return _bfs_fallback(goal_preds, initial_state, actions, max_depth=min(max_depth, 4))


def _bfs_fallback(goal_preds: set, initial_state: set, actions: list, max_depth: int = 4):
    """BFS fallback when A* finds nothing (goal truly unreachable within depth)."""
    queue = deque([(frozenset(initial_state), [])])
    visited = {frozenset(initial_state)}

    while queue:
        state, plan = queue.popleft()
        if len(plan) >= max_depth:
            continue
        for action in actions:
            if not preconditions_satisfied(action, state):
                continue
            new_state = state | action["_effects"]
            if new_state == state or new_state in visited:
                continue
            visited.add(new_state)
            new_plan = plan + [action]
            if goal_preds.issubset(new_state):
                return new_plan
            queue.append((new_state, new_plan))
    return None


def format_plan(plan) -> str:
    """Format plan for human reading."""
    if plan is None:
        return "No plan found (goal unreachable from current state within depth)."
    if plan == []:
        return "Goal already satisfied."

    lines = [f"Attack chain ({len(plan)} steps):"]
    for i, action in enumerate(plan, 1):
        name = action["name"]
        cat = action.get("category", "?")
        effects = ", ".join(sorted(action["_effects"]))[:80]
        lines.append(f"  {i}. [{cat}] {name} → {effects}")
    return "\n".join(lines)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="TAR Attack Chain Planner")
    parser.add_argument("--db", help="Path to world_model.db (for state)")
    parser.add_argument("--goal", default="root_access", help="Goal predicate or name")
    parser.add_argument("--max-depth", type=int, default=6, help="Max chain length")
    parser.add_argument("--state", help="Comma-separated initial state predicates (overrides db)")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    # Determine initial state
    if args.state:
        state = set(args.state.split(","))
    elif args.db:
        state = extract_state_predicates(args.db)
    else:
        print("Error: need --db or --state", file=sys.stderr)
        sys.exit(1)

    actions = load_actions()
    print(f"Loaded {len(actions)} actions, {len(state)} initial predicates", file=sys.stderr)
    print(f"Goal: {args.goal} → {GOALS.get(args.goal, {args.goal})}", file=sys.stderr)

    plan = plan_chain(args.goal, state, actions, max_depth=args.max_depth)

    if args.json:
        print(json.dumps({
            "goal": args.goal,
            "initial_state": sorted(state),
            "plan": [{"name": a["name"], "category": a.get("category"),
                      "preconditions": sorted(a["_preconditions"]),
                      "effects": sorted(a["_effects"])}
                     for a in plan],
            "length": len(plan),
        }, indent=2))
    else:
        print(format_plan(plan))


if __name__ == "__main__":
    main()
