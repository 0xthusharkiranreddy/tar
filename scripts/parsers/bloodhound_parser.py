#!/usr/bin/env python3
"""
bloodhound_parser.py — Parse BloodHound JSON collection data into structured records.

Usage:
    python3 bloodhound_parser.py --dir /path/to/bloodhound_data/ [--db world_model.db]
"""

import json
import sys
from pathlib import Path


def parse_bloodhound_users(data: dict) -> list[dict]:
    """Extract users from BloodHound users JSON."""
    results = []
    for user in data.get("data", []):
        props = user.get("Properties", {})
        results.append({
            "type": "ad_user",
            "username": props.get("name", ""),
            "enabled": props.get("enabled", True),
            "admincount": props.get("admincount", False),
            "hasspn": props.get("hasspn", False),
            "dontreqpreauth": props.get("dontreqpreauth", False),
            "pwdneverexpires": props.get("pwdneverexpires", False),
            "lastlogon": props.get("lastlogon", ""),
        })
    return results


def parse_bloodhound_computers(data: dict) -> list[dict]:
    """Extract computers from BloodHound computers JSON."""
    results = []
    for comp in data.get("data", []):
        props = comp.get("Properties", {})
        results.append({
            "type": "computer",
            "name": props.get("name", ""),
            "os": props.get("operatingsystem", ""),
            "enabled": props.get("enabled", True),
            "unconstraineddelegation": props.get("unconstraineddelegation", False),
        })
    return results


def parse_bloodhound_groups(data: dict) -> list[dict]:
    """Extract group memberships."""
    results = []
    for group in data.get("data", []):
        props = group.get("Properties", {})
        members = [m.get("MemberId", "") for m in group.get("Members", [])]
        results.append({
            "type": "group",
            "name": props.get("name", ""),
            "members": members,
            "admincount": props.get("admincount", False),
        })
    return results


def parse_bloodhound_directory(dir_path: str) -> dict:
    """Parse all BloodHound JSON files in a directory."""
    results = {"users": [], "computers": [], "groups": [], "edges": []}
    bh_dir = Path(dir_path)

    for json_file in bh_dir.glob("*.json"):
        try:
            data = json.loads(json_file.read_text())
            meta = data.get("meta", {})
            data_type = meta.get("type", "").lower()

            if data_type == "users" or "users" in json_file.name.lower():
                results["users"] = parse_bloodhound_users(data)
            elif data_type == "computers" or "computers" in json_file.name.lower():
                results["computers"] = parse_bloodhound_computers(data)
            elif data_type == "groups" or "groups" in json_file.name.lower():
                results["groups"] = parse_bloodhound_groups(data)
        except (json.JSONDecodeError, Exception):
            continue

    return results


def write_to_world_model(results: dict, db_path: str):
    """Write BloodHound data to world_model."""
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from world_model import WorldModel

    wm = WorldModel(db_path)

    for user in results.get("users", []):
        wm.add_user(
            username=user.get("username", ""),
            source="bloodhound",
        )
        if user.get("hasspn"):
            wm.add_finding(
                category="kerberoastable",
                severity="high",
                description=f"Kerberoastable user: {user['username']}",
            )
        if user.get("dontreqpreauth"):
            wm.add_finding(
                category="asreproastable",
                severity="high",
                description=f"AS-REP roastable user: {user['username']}",
            )

    for comp in results.get("computers", []):
        if comp.get("unconstraineddelegation"):
            wm.add_finding(
                category="delegation",
                severity="critical",
                description=f"Unconstrained delegation: {comp['name']}",
            )

    wm.close()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Parse BloodHound JSON data")
    parser.add_argument("--dir", required=True, help="Directory with BloodHound JSON files")
    parser.add_argument("--db", help="World model DB path")
    args = parser.parse_args()

    results = parse_bloodhound_directory(args.dir)

    if args.db:
        write_to_world_model(results, args.db)

    summary = {
        "users": len(results["users"]),
        "computers": len(results["computers"]),
        "groups": len(results["groups"]),
        "kerberoastable": sum(1 for u in results["users"] if u.get("hasspn")),
        "asreproastable": sum(1 for u in results["users"] if u.get("dontreqpreauth")),
        "unconstrained_delegation": sum(1 for c in results["computers"] if c.get("unconstraineddelegation")),
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
