#!/usr/bin/env python3
"""
smbclient_parser.py — Parse smbclient/smbmap/enum4linux output into typed records.

Handles:
- smbclient -L //host (share listing)
- smbmap -H host (share access mapping)
- enum4linux-ng output (users, shares, domain info)
"""

import json
import re
import sys
from pathlib import Path


def parse_smbclient_list(text: str, host_ip: str = None) -> dict:
    """Parse smbclient -L output."""
    shares = []
    domain = None

    for line in text.split("\n"):
        # Share listing: Sharename Type Comment
        share_match = re.match(r"\s+(\S+)\s+(Disk|IPC|Printer)\s*(.*)", line)
        if share_match:
            name = share_match.group(1)
            share_type = share_match.group(2)
            comment = share_match.group(3).strip()
            shares.append({
                "name": name,
                "type": share_type,
                "comment": comment,
                "access_level": None,
            })

        # Domain/workgroup line
        domain_match = re.match(r"\s+Domain=\[([^\]]+)\]", line)
        if domain_match:
            domain = domain_match.group(1)

    return {"host_ip": host_ip, "shares": shares, "domain": domain}


def parse_smbmap(text: str, host_ip: str = None) -> dict:
    """Parse smbmap -H output."""
    shares = []

    for line in text.split("\n"):
        # smbmap output: SHARENAME  READ, WRITE  or NO ACCESS
        share_match = re.match(
            r"\s+(\S+)\s+(READ ONLY|READ, WRITE|NO ACCESS|WRITE ONLY)\s*(.*)", line
        )
        if share_match:
            name = share_match.group(1)
            access = share_match.group(2).strip()
            access_map = {
                "READ ONLY": "read",
                "READ, WRITE": "write",
                "WRITE ONLY": "write",
                "NO ACCESS": "none",
            }
            shares.append({
                "name": name,
                "access_level": access_map.get(access, access.lower()),
            })

    return {"host_ip": host_ip, "shares": shares}


def parse_enum4linux(text: str, host_ip: str = None) -> dict:
    """Parse enum4linux-ng output for users, shares, domain info."""
    result = {
        "host_ip": host_ip,
        "shares": [],
        "users": [],
        "domain": None,
        "os": None,
        "domain_sid": None,
    }

    section = None
    for line in text.split("\n"):
        # Section headers
        if "Share Enumeration" in line or "shares:" in line.lower():
            section = "shares"
        elif "User Enumeration" in line or "users:" in line.lower():
            section = "users"
        elif "Domain Information" in line:
            section = "domain"

        # Domain name
        domain_match = re.search(r"Domain Name:\s+(\S+)", line)
        if domain_match:
            result["domain"] = domain_match.group(1)

        # Domain SID
        sid_match = re.search(r"Domain SID:\s+(S-\d+-\d+-\d+-[\d-]+)", line)
        if sid_match:
            result["domain_sid"] = sid_match.group(1)

        # OS info
        os_match = re.search(r"OS:\s+(.+?)(?:\s*$|\s+OS build)", line)
        if os_match:
            result["os"] = os_match.group(1).strip()

        # Users from RID cycling or user enum
        user_match = re.search(r"(\S+\\)?(\S+)\s+\(RID:\s*(\d+)\)", line)
        if user_match:
            domain_prefix = user_match.group(1)
            username = user_match.group(2)
            rid = int(user_match.group(3))
            if rid >= 1000 or username.lower() in ("administrator", "guest"):
                result["users"].append({
                    "username": username,
                    "rid": rid,
                    "domain": domain_prefix.rstrip("\\") if domain_prefix else result.get("domain"),
                })

        # Shares
        if section == "shares":
            share_match = re.match(r"\s+(\S+)\s+(Disk|IPC|Printer)", line)
            if share_match:
                result["shares"].append({
                    "name": share_match.group(1),
                    "type": share_match.group(2),
                    "access_level": None,
                })

    return result


def write_to_world_model(parsed: dict, db_path: str):
    """Write parsed SMB results into world_model DB."""
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from world_model import WorldModel

    wm = WorldModel(db_path)
    host_ip = parsed.get("host_ip")

    if host_ip:
        host = wm.get_host_by_ip(host_ip)
        if not host:
            host_id = wm.add_host(host_ip, os=parsed.get("os"), domain=parsed.get("domain"))
        else:
            host_id = host["id"]
            if parsed.get("domain"):
                wm.conn.execute("UPDATE hosts SET domain=? WHERE id=?", (parsed["domain"], host_id))
                wm.conn.commit()
            if parsed.get("os"):
                wm.conn.execute("UPDATE hosts SET os=? WHERE id=?", (parsed["os"], host_id))
                wm.conn.commit()

        for share in parsed.get("shares", []):
            wm.add_share(host_id, share["name"], access_level=share.get("access_level"))

    for user in parsed.get("users", []):
        wm.add_user(
            username=user["username"],
            domain=user.get("domain"),
            rid=user.get("rid"),
        )

    wm.close()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Parse SMB tool output for TAR world_model")
    parser.add_argument("input", help="Output file or - for stdin")
    parser.add_argument("--tool", choices=["smbclient", "smbmap", "enum4linux"], required=True)
    parser.add_argument("--host", help="Target host IP")
    parser.add_argument("--db", help="World model DB path")
    args = parser.parse_args()

    if args.input == "-":
        text = sys.stdin.read()
    else:
        text = Path(args.input).read_text()

    if args.tool == "smbclient":
        parsed = parse_smbclient_list(text, host_ip=args.host)
    elif args.tool == "smbmap":
        parsed = parse_smbmap(text, host_ip=args.host)
    elif args.tool == "enum4linux":
        parsed = parse_enum4linux(text, host_ip=args.host)

    if args.db:
        write_to_world_model(parsed, args.db)
        print(json.dumps({"shares": len(parsed.get("shares", [])), "users": len(parsed.get("users", [])), "written_to": args.db}))
    else:
        print(json.dumps(parsed, indent=2))


if __name__ == "__main__":
    main()
