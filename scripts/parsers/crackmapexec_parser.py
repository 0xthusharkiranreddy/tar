#!/usr/bin/env python3
"""
crackmapexec_parser.py — Parse CrackMapExec/NetExec output into typed records.

Handles:
- netexec smb host (SMB enumeration)
- netexec smb host -u user -p pass --shares (authenticated share enum)
- netexec smb host -u user -p pass --users (user enumeration)
- netexec smb host -u users.txt -p pass (password spraying)
- netexec smb host --rid-brute (RID cycling)
"""

import json
import re
import sys
from pathlib import Path


def parse_crackmapexec(text: str) -> dict:
    """Parse CrackMapExec/NetExec output into structured data."""
    result = {
        "hosts": [],
        "creds": [],
        "shares": [],
        "users": [],
    }

    seen_hosts = set()

    for line in text.split("\n"):
        line = line.strip()
        if not line:
            continue

        # Strip ANSI color codes
        line = re.sub(r"\x1b\[[0-9;]*m", "", line)

        # Host info line: SMB 10.10.10.1 445 DC01 [*] Windows Server 2019 Build 17763 x64
        host_match = re.match(
            r"(?:SMB|LDAP|MSSQL|WINRM|SSH)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\S+)\s+\[\*\]\s+(.*)",
            line,
        )
        if host_match:
            ip = host_match.group(1)
            port = int(host_match.group(2))
            hostname = host_match.group(3)
            info = host_match.group(4)

            if ip not in seen_hosts:
                seen_hosts.add(ip)
                os_info = None
                domain = None

                if "Windows" in info:
                    os_info = "windows"
                elif "Linux" in info or "Ubuntu" in info:
                    os_info = "linux"

                domain_match = re.search(r"domain:(\S+)", info)
                if domain_match:
                    domain = domain_match.group(1)

                result["hosts"].append({
                    "ip": ip,
                    "hostname": hostname,
                    "os": os_info,
                    "domain": domain,
                    "banner": info.strip(),
                })
            continue

        # Successful auth: [+] domain\user:password
        cred_match = re.match(
            r".*\[\+\]\s+(?:(\S+?)\\)?(\S+?):(\S+?)(?:\s+.*)?$", line
        )
        if cred_match and "[+]" in line:
            domain = cred_match.group(1)
            username = cred_match.group(2)
            password = cred_match.group(3)

            is_admin = "(Pwn3d!)" in line
            result["creds"].append({
                "domain": domain,
                "username": username,
                "password": password,
                "is_admin": is_admin,
                "source": "crackmapexec_spray",
            })
            continue

        # Share enumeration: SHARENAME READ,WRITE
        share_match = re.match(
            r".*(?:SMB|LDAP)\s+\S+\s+\d+\s+\S+\s+(\S+)\s+(READ|WRITE|READ,WRITE|NO ACCESS)\s*(.*)",
            line,
        )
        if share_match:
            name = share_match.group(1)
            access_raw = share_match.group(2)
            access_map = {
                "READ": "read",
                "WRITE": "write",
                "READ,WRITE": "write",
                "NO ACCESS": "none",
            }
            result["shares"].append({
                "name": name,
                "access_level": access_map.get(access_raw, "none"),
            })
            continue

        # RID brute / user enum: 500: DOMAIN\Administrator (SidTypeUser)
        rid_match = re.search(
            r"(\d+):\s+(?:(\S+?)\\)?(\S+)\s+\(SidType(User|Group)\)", line
        )
        if rid_match:
            rid = int(rid_match.group(1))
            domain = rid_match.group(2)
            name = rid_match.group(3)
            sid_type = rid_match.group(4)
            if sid_type == "User":
                result["users"].append({
                    "username": name,
                    "domain": domain,
                    "rid": rid,
                })
            continue

        # User enum from --users: domain\user
        user_match = re.match(
            r".*(?:SMB|LDAP)\s+\S+\s+\d+\s+\S+\s+(?:(\S+?)\\)?(\S+)\s+", line
        )
        if user_match and "badpwdcount" in line.lower():
            domain = user_match.group(1)
            username = user_match.group(2)
            result["users"].append({
                "username": username,
                "domain": domain,
            })

    return result


def write_to_world_model(parsed: dict, db_path: str):
    """Write parsed CME results into world_model DB."""
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from world_model import WorldModel

    wm = WorldModel(db_path)

    for host in parsed.get("hosts", []):
        host_id = wm.add_host(
            ip=host["ip"],
            hostname=host.get("hostname"),
            os=host.get("os"),
            domain=host.get("domain"),
        )
        for share in parsed.get("shares", []):
            wm.add_share(host_id, share["name"], access_level=share.get("access_level"))

    for cred in parsed.get("creds", []):
        wm.add_cred(
            username=cred["username"],
            password=cred.get("password"),
            domain=cred.get("domain"),
            source=cred.get("source", "crackmapexec"),
            verified=True,
        )
        if cred.get("is_admin"):
            wm.add_user(
                username=cred["username"],
                domain=cred.get("domain"),
                is_admin=True,
            )

    for user in parsed.get("users", []):
        wm.add_user(
            username=user["username"],
            domain=user.get("domain"),
            rid=user.get("rid"),
        )

    wm.close()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Parse CrackMapExec/NetExec output for TAR")
    parser.add_argument("input", help="Output file or - for stdin")
    parser.add_argument("--db", help="World model DB path")
    args = parser.parse_args()

    if args.input == "-":
        text = sys.stdin.read()
    else:
        text = Path(args.input).read_text()

    parsed = parse_crackmapexec(text)

    if args.db:
        write_to_world_model(parsed, args.db)
        print(json.dumps({
            "hosts": len(parsed["hosts"]),
            "creds": len(parsed["creds"]),
            "shares": len(parsed["shares"]),
            "users": len(parsed["users"]),
            "written_to": args.db,
        }))
    else:
        print(json.dumps(parsed, indent=2))


if __name__ == "__main__":
    main()
