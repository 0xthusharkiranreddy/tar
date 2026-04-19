#!/usr/bin/env python3
"""
replay_harness.py — Validate TAR action library against walkthrough corpus.

For each step in a walkthrough's steps.json:
1. Simulate the world_model state accumulated up to that step
2. Compute applicable actions (preconditions satisfied)
3. Check if the walkthrough's chosen action appears in applicable set
4. Score: top-1 match, top-3 match, preconditions-satisfied %

Usage:
    python3 replay_harness.py --all
    python3 replay_harness.py --filter smb-path
    python3 replay_harness.py --box eighteen
    python3 replay_harness.py --difficulty easy
"""

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

WALKTHROUGHS_DIR = Path("/home/kali/knowledge/walkthroughs")
ACTIONS_DIR = Path("/home/kali/knowledge/actions")

# Our known actions loaded from YAML
ACTIONS = {}


def load_actions():
    """Load all action YAML files."""
    global ACTIONS
    for yml_file in sorted(ACTIONS_DIR.rglob("*.yml")):
        try:
            with open(yml_file) as f:
                action = yaml.safe_load(f)
            if action and "name" in action:
                ACTIONS[action["name"]] = action
        except Exception:
            continue


def simulate_state_at_step(steps: list[dict], step_idx: int) -> dict:
    """
    Build a simulated world-model state from walkthrough steps up to step_idx.
    This is a heuristic reconstruction — not as precise as real nmap output,
    but good enough to test precondition matching.
    """
    state = {
        "services": set(),     # (port, product)
        "predicates": set(),
        "has_cred": False,
        "has_password": False,
        "has_hash": False,
        "has_users": False,
        "has_shares": False,
        "has_target": True,
        "domain_joined": False,
        "os": None,
        "phase": "recon",
    }

    # Also look at the CURRENT step's command to infer what services it targets
    # (the walkthrough author knows which ports are open even if we haven't simulated nmap output)
    steps_to_scan = list(range(step_idx))
    if step_idx < len(steps):
        steps_to_scan.append(step_idx)

    for i in steps_to_scan:
        step = steps[i]
        cmd = step.get("command", "")
        action = step.get("action", "")
        phase = step.get("phase", "")

        if phase in ("foothold", "user", "privesc", "root"):
            state["phase"] = phase

        # Infer services from nmap output lines (port/proto open service)
        for port_match in re.finditer(r"\b(\d+)/(tcp|udp)\s+open\s+(\S+)", cmd):
            port = int(port_match.group(1))
            product = port_match.group(3)
            state["services"].add((port, product))

        # Infer services from explicit -p port lists in nmap commands
        p_match = re.search(r"-p\s+([\d,]+)", cmd)
        if p_match and ("nmap" in cmd.lower()):
            for port_str in p_match.group(1).split(","):
                try:
                    port = int(port_str.strip())
                    state["services"].add((port, "unknown"))
                except ValueError:
                    pass

        # Infer services from commands targeting specific ports
        if re.search(r":445\b|smb|smbclient|netexec\s+smb|crackmapexec\s+smb", cmd, re.I):
            state["services"].add((445, "microsoft-ds"))
        if re.search(r":88\b|kerberos|kerbrute|GetUserSPNs|GetNPUsers", cmd, re.I):
            state["services"].add((88, "kerberos"))
        if re.search(r":5985\b|winrm|evil-winrm", cmd, re.I):
            state["services"].add((5985, "winrm"))
        if re.search(r":22\b|ssh\s+", cmd, re.I):
            state["services"].add((22, "ssh"))
        if re.search(r":80\b|:443\b|http|curl|gobuster|feroxbuster|ffuf|nikto", cmd, re.I):
            state["services"].add((80, "http"))
        if re.search(r":1433\b|mssql|mssqlclient", cmd, re.I):
            state["services"].add((1433, "mssql"))
        if re.search(r":389\b|ldap", cmd, re.I):
            state["services"].add((389, "ldap"))
        if re.search(r":3306\b|mysql", cmd, re.I):
            state["services"].add((3306, "mysql"))

        # Infer creds from commands that use -u/-p or user:pass patterns
        if re.search(r"-[up]\s+\S+.*-[up]\s+\S+|:\S+@\S+", cmd):
            state["has_cred"] = True
            state["has_password"] = True

        # Infer from action types
        if action in ("crackmapexec_spray", "winrm_check", "evil_winrm", "psexec",
                       "wmiexec", "mssqlclient", "ssh", "ldap_enum"):
            if re.search(r"-[up]\s|password|pass", cmd, re.I):
                state["has_cred"] = True
                state["has_password"] = True

        if action == "hashcat" or action == "john":
            state["has_hash"] = True

        if action in ("smb_user_enum", "rid_brute", "kerbrute_userenum",
                       "impacket_getusers", "enum4linux_ng", "bloodhound"):
            state["has_users"] = True

        if action in ("smb_share_enum", "smbclient_list_shares", "smbclient_connect"):
            state["has_shares"] = True

        if re.search(r"domain|\.htb|\.local", cmd, re.I):
            state["domain_joined"] = True

        # OS detection
        if re.search(r"windows|winrm|mssql|iis|powershell", cmd, re.I):
            state["os"] = "windows"
        elif re.search(r"linux|ssh.*22|apache|nginx", cmd, re.I):
            state["os"] = "linux"

    # Build predicate set
    preds = set()
    preds.add("has_target")
    preds.add(f"phase={state['phase']}")

    for port, product in state["services"]:
        preds.add(f"service.port=={port}")
        preds.add(f"service.product=={product}")
        preds.add("service.state==open")
        preds.add(f"service.protocol==tcp")

    if state["has_cred"]:
        preds.add("has_cred")
    if state["has_password"]:
        preds.add("has_password")
    if state["has_hash"]:
        preds.add("has_hash")
    if state["has_users"]:
        preds.add("has_users")
    if state["has_shares"]:
        preds.add("has_shares")
    if state["domain_joined"]:
        preds.add("domain_joined")
    if state["os"]:
        preds.add(f"os=={state['os']}")

    state["predicates"] = preds
    return state


def check_preconditions(action_def: dict, predicates: set) -> bool:
    """Check if an action's preconditions are satisfied by the current predicates."""
    for pre in action_def.get("preconditions", []):
        pre = pre.strip()
        if "==" in pre:
            if pre not in predicates:
                return False
        else:
            # Keyword match: check if any predicate contains this keyword
            if not any(pre in p for p in predicates):
                return False
    return True


def get_applicable_actions(predicates: set) -> list[str]:
    """Return list of action names whose preconditions are satisfied."""
    applicable = []
    for name, action_def in ACTIONS.items():
        if check_preconditions(action_def, predicates):
            applicable.append(name)
    return applicable


def replay_walkthrough(steps_json_path: str) -> dict:
    """Replay a single walkthrough and compute match scores."""
    data = json.loads(Path(steps_json_path).read_text())
    steps = data.get("steps", [])

    results = {
        "box": data.get("box_name", "unknown"),
        "os": data.get("os", "unknown"),
        "total_steps": len(steps),
        "known_action_steps": 0,
        "top1_matches": 0,
        "topN_matches": 0,
        "applicable_matches": 0,
        "not_in_library": 0,
        "precondition_failures": [],
    }

    for i, step in enumerate(steps):
        action = step.get("action", "unknown")

        # Skip unknown actions — they're not in our library
        if action == "unknown" or action not in ACTIONS:
            results["not_in_library"] += 1
            continue

        results["known_action_steps"] += 1

        # Simulate state at this step
        state = simulate_state_at_step(steps, i)
        applicable = get_applicable_actions(state["predicates"])

        if action in applicable:
            results["applicable_matches"] += 1
            # Top-1: is it the first applicable action? (by YAML sort order for now)
            if applicable and applicable[0] == action:
                results["top1_matches"] += 1
            # Top-N (top-3)
            if action in applicable[:3]:
                results["topN_matches"] += 1
        else:
            results["precondition_failures"].append({
                "step": i,
                "action": action,
                "command": step.get("command", "")[:80],
                "predicates": sorted(state["predicates"]),
                "applicable": applicable,
            })

    return results


def run_replay(args):
    load_actions()
    print(f"[*] Loaded {len(ACTIONS)} actions from {ACTIONS_DIR}")

    # Collect walkthrough paths
    walkthrough_paths = []
    manifest_path = WALKTHROUGHS_DIR / "manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {"boxes": {}}

    for box_dir in sorted(WALKTHROUGHS_DIR.iterdir()):
        if not box_dir.is_dir():
            continue
        steps_path = box_dir / "steps.json"
        if not steps_path.exists():
            continue

        box_name = box_dir.name

        # Apply filters
        if args.box and box_name != args.box:
            continue

        if args.filter == "smb-path":
            data = json.loads(steps_path.read_text())
            smb_actions = {"smbclient_list_shares", "smb_null_session", "smb_guest_access",
                          "crackmapexec_spray", "enum4linux_ng", "smb_share_enum",
                          "smb_user_enum", "rid_brute", "psexec", "wmiexec", "evil_winrm"}
            actions_used = set(s.get("action") for s in data.get("steps", []))
            if not actions_used & smb_actions:
                continue

        if args.difficulty:
            box_info = manifest.get("boxes", {}).get(box_name, {})
            if box_info.get("difficulty", "unknown") != args.difficulty:
                continue

        walkthrough_paths.append(steps_path)

    if not walkthrough_paths:
        print("[!] No walkthroughs matched filters.")
        return 1

    print(f"[*] Replaying {len(walkthrough_paths)} walkthroughs...\n")

    # Aggregate results
    agg = {
        "total_boxes": len(walkthrough_paths),
        "total_known_steps": 0,
        "total_applicable": 0,
        "total_top1": 0,
        "total_topN": 0,
        "total_not_in_library": 0,
        "per_box": [],
    }

    for steps_path in walkthrough_paths:
        result = replay_walkthrough(str(steps_path))
        agg["per_box"].append(result)
        agg["total_known_steps"] += result["known_action_steps"]
        agg["total_applicable"] += result["applicable_matches"]
        agg["total_top1"] += result["top1_matches"]
        agg["total_topN"] += result["topN_matches"]
        agg["total_not_in_library"] += result["not_in_library"]

        known = result["known_action_steps"]
        if known > 0:
            app_pct = result["applicable_matches"] / known * 100
            t1_pct = result["top1_matches"] / known * 100
            print(f"  {result['box']:25s} known={known:3d}  applicable={app_pct:5.1f}%  top1={t1_pct:5.1f}%  failures={len(result['precondition_failures'])}")

    # Summary
    total = agg["total_known_steps"]
    if total > 0:
        app_rate = agg["total_applicable"] / total * 100
        top1_rate = agg["total_top1"] / total * 100
        topN_rate = agg["total_topN"] / total * 100
    else:
        app_rate = top1_rate = topN_rate = 0

    print(f"\n{'='*60}")
    print(f"REPLAY SUMMARY")
    print(f"{'='*60}")
    print(f"Boxes tested:        {agg['total_boxes']}")
    print(f"Known action steps:  {total}")
    print(f"Not in library:      {agg['total_not_in_library']}")
    print(f"")
    print(f"Applicable rate:     {app_rate:.1f}% ({agg['total_applicable']}/{total})")
    print(f"Top-1 match rate:    {top1_rate:.1f}% ({agg['total_top1']}/{total})")
    print(f"Top-3 match rate:    {topN_rate:.1f}% ({agg['total_topN']}/{total})")

    # Show most common precondition failures
    all_failures = []
    for r in agg["per_box"]:
        all_failures.extend(r.get("precondition_failures", []))

    if all_failures:
        print(f"\nPrecondition failures ({len(all_failures)} total):")
        failure_actions = {}
        for f in all_failures:
            a = f["action"]
            failure_actions[a] = failure_actions.get(a, 0) + 1
        for action, count in sorted(failure_actions.items(), key=lambda x: -x[1])[:10]:
            print(f"  {action:30s} {count:4d} failures")
            # Show one example
            example = next(f for f in all_failures if f["action"] == action)
            print(f"    Example cmd: {example['command']}")
            print(f"    Applicable at that point: {example['applicable']}")

    # Metric output for gate checks
    if args.metric == "top1":
        print(f"\n>>> GATE METRIC (top1): {top1_rate:.1f}%")
        return 0 if top1_rate >= (args.threshold or 0) else 1
    elif args.metric == "applicable":
        print(f"\n>>> GATE METRIC (applicable): {app_rate:.1f}%")
        return 0 if app_rate >= (args.threshold or 0) else 1

    return 0


def main():
    parser = argparse.ArgumentParser(description="TAR Replay Harness")
    parser.add_argument("--box", help="Test single box")
    parser.add_argument("--filter", choices=["smb-path", "all"], default="all")
    parser.add_argument("--difficulty", choices=["easy", "medium", "hard", "insane"])
    parser.add_argument("--metric", choices=["top1", "applicable", "topN"], default="applicable")
    parser.add_argument("--threshold", type=float, help="Gate threshold percentage")
    args = parser.parse_args()

    return run_replay(args)


if __name__ == "__main__":
    sys.exit(main())
