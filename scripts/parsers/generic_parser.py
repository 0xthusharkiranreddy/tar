#!/usr/bin/env python3
"""
generic_parser.py — Catch-all parser for tools without dedicated parsers.

Extracts from any command output:
  - Credentials (username:password, hashes, tokens)
  - IP addresses and hostnames
  - File paths (interesting system files)
  - Service banners
  - Privilege indicators (root, SYSTEM, admin)
  - Flag patterns (HTB format)

Usage:
    echo "$OUTPUT" | python3 generic_parser.py --db /path/to/world_model.db --tool toolname
"""

import json
import re
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).parent.parent


def parse_generic(text: str, tool_name: str = "") -> dict:
    """Parse unstructured command output into structured data.

    Returns {findings, creds, hosts, paths, flags}
    """
    result = {
        "findings": [],
        "creds": [],
        "hosts": [],
        "paths": [],
        "flags": [],
    }

    # ── Credential patterns ──

    # user:password in various formats
    # /etc/passwd style
    for m in re.finditer(r'^(\w[\w.-]*):([^:]+):\d+:\d+:', text, re.M):
        user, field = m.group(1), m.group(2)
        if field not in ('x', '*', '!', '!!'):
            result["creds"].append({"username": user, "hash": field, "hash_type": "unix", "source": tool_name or "passwd"})
        else:
            result["creds"].append({"username": user, "source": "user_enum"})

    # /etc/shadow style
    for m in re.finditer(r'^(\w[\w.-]*):\$(\d+)\$([^:]+):', text, re.M):
        result["creds"].append({
            "username": m.group(1),
            "hash": f"${m.group(2)}${m.group(3)}",
            "hash_type": {"1": "md5crypt", "5": "sha256crypt", "6": "sha512crypt", "2a": "bcrypt", "2b": "bcrypt"}.get(m.group(2), "unix"),
            "source": "shadow",
        })

    # NTLM hashes (SAM/secretsdump format)
    for m in re.finditer(r'^(\S+?):\d+:([a-f0-9]{32}):([a-f0-9]{32}):::', text, re.M):
        result["creds"].append({
            "username": m.group(1),
            "hash": f"{m.group(2)}:{m.group(3)}",
            "hash_type": "ntlm",
            "source": tool_name or "sam_dump",
        })

    # NetNTLMv2 hashes
    for m in re.finditer(r'^(\S+?)::(\S+?):[a-f0-9]+:[a-f0-9]+:[a-f0-9]+', text, re.M):
        result["creds"].append({
            "username": m.group(1),
            "hash": m.group(0),
            "hash_type": "netntlmv2",
            "source": tool_name or "capture",
        })

    # Kerberos TGS hashes (kerberoast output)
    for m in re.finditer(r'\$krb5tgs\$\d+\$\*?([^*$]+)\$', text):
        result["creds"].append({
            "username": m.group(1),
            "hash": text[m.start():m.start()+min(200, len(text)-m.start())],
            "hash_type": "krb5tgs",
            "source": "kerberoast",
        })

    # AS-REP hashes
    for m in re.finditer(r'\$krb5asrep\$\d+\$([^@$]+)[@$]', text):
        result["creds"].append({
            "username": m.group(1),
            "hash": text[m.start():m.start()+min(200, len(text)-m.start())],
            "hash_type": "krb5asrep",
            "source": "asreproast",
        })

    # Generic user:pass patterns (careful with false positives)
    for m in re.finditer(r'(?:credentials?|login|cred|password found|valid)\s*[:\-]\s*(\w+)\s*[:/]\s*(\S+)', text, re.I):
        user, passwd = m.group(1), m.group(2)
        if len(passwd) > 2 and passwd not in ('null', 'none', 'N/A'):
            result["creds"].append({"username": user, "password": passwd, "source": tool_name or "generic"})

    # Cracked password output (hashcat/john style)
    for m in re.finditer(r'^([^:\s]+):(\S+)\s*$', text, re.M):
        # Heuristic: if first field looks like a hash and second is readable
        if len(m.group(1)) >= 16 and m.group(2).isprintable() and len(m.group(2)) < 50:
            result["creds"].append({"password": m.group(2), "hash": m.group(1)[:32], "source": "cracked"})

    # ── Privilege indicators ──
    priv_patterns = [
        (r'uid=0\(root\)', "root shell obtained", "critical"),
        (r'nt authority\\system', "SYSTEM shell obtained", "critical"),
        (r'nt authority\\network service', "Network Service shell", "high"),
        (r'(BUILTIN\\Administrators|admin.*:.*True)', "Admin access confirmed", "high"),
        (r'SeImpersonatePrivilege', "SeImpersonate available — potato attack viable", "high"),
        (r'SeAssignPrimaryTokenPrivilege', "SeAssignPrimaryToken — potato attack viable", "high"),
        (r'SeBackupPrivilege', "SeBackup — can read any file", "high"),
        (r'SeRestorePrivilege', "SeRestore — can write any file", "high"),
        (r'SeDebugPrivilege', "SeDebug — can dump LSASS", "high"),
        (r'SeTakeOwnershipPrivilege', "SeTakeOwnership — can take ownership of any object", "high"),
        (r'(NOPASSWD|ALL.*ALL)', "sudo NOPASSWD found", "high"),
        (r'Pwn3d!|STATUS_ADMIN', "Admin access via CrackMapExec", "critical"),
    ]
    for pat, desc, severity in priv_patterns:
        if re.search(pat, text, re.I):
            result["findings"].append({
                "category": "privilege",
                "severity": severity,
                "description": desc,
                "evidence": re.search(pat, text, re.I).group(0)[:100],
            })

    # ── SUID/capabilities ──
    for m in re.finditer(r'-[rwx-]*s[rwx-]*\s+\d+\s+\S+\s+\S+\s+\d+\s+\S+\s+\d+\s+[\d:]+\s+(/\S+)', text):
        result["findings"].append({
            "category": "suid",
            "severity": "high",
            "description": f"SUID binary: {m.group(1)}",
            "evidence": m.group(0)[:150],
        })

    for m in re.finditer(r'(/\S+)\s*=\s*(cap_\w+)', text, re.I):
        result["findings"].append({
            "category": "capability",
            "severity": "high",
            "description": f"Capability {m.group(2)} on {m.group(1)}",
            "evidence": m.group(0)[:150],
        })

    # ── Interesting file paths ──
    interesting_paths = [
        r'/home/\w+/\.ssh/id_rsa',
        r'/root/\.ssh/id_rsa',
        r'/etc/shadow',
        r'/var/www/\S+/\.env',
        r'/var/www/\S+/config\.\S+',
        r'/var/www/\S+/wp-config\.php',
        r'/opt/\S+/\.env',
        r'C:\\Users\\\w+\\Desktop\\(?:user|root)\.txt',
        r'/home/\w+/(?:user|root)\.txt',
        r'/root/root\.txt',
    ]
    for pat in interesting_paths:
        for m in re.finditer(pat, text, re.I):
            path = m.group(0)
            if path not in result["paths"]:
                result["paths"].append(path)

    # ── IP addresses and hostnames ──
    for m in re.finditer(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text):
        ip = m.group(1)
        # Skip common non-target IPs
        if ip.startswith(('127.', '0.', '255.', '224.')) or ip in ('0.0.0.0',):
            continue
        if ip not in result["hosts"]:
            result["hosts"].append(ip)

    # ── Flag patterns (HTB) ──
    for m in re.finditer(r'\b([a-f0-9]{32})\b', text):
        # Context check: near "flag", "root.txt", "user.txt", etc.
        context = text[max(0, m.start()-50):min(len(text), m.end()+50)]
        if re.search(r'flag|root\.txt|user\.txt|proof|congratulations', context, re.I):
            result["flags"].append(m.group(1))

    # ── Cron jobs ──
    for m in re.finditer(r'^[\d*,/\s]+\s+(?:root|www-data|\w+)\s+(/\S+)', text, re.M):
        result["findings"].append({
            "category": "cron",
            "severity": "medium",
            "description": f"Cron job: {m.group(1)}",
            "evidence": m.group(0).strip()[:150],
        })

    # ── Writable directories/files ──
    for m in re.finditer(r'(?:World-writable|writable by (?:group|other)|drwxrwxrwx)\s*(?:\S+\s+){6,8}(/\S+)', text, re.I):
        result["findings"].append({
            "category": "writable",
            "severity": "medium",
            "description": f"Writable: {m.group(1)}",
            "evidence": m.group(0)[:100],
        })

    return result


def update_world_model(db_path: str, parsed: dict, tool_name: str = ""):
    """Write parsed results into world_model."""
    sys.path.insert(0, str(SCRIPTS_DIR))
    from world_model import WorldModel

    wm = WorldModel(db_path)

    for f in parsed["findings"]:
        wm.add_finding(
            category=f["category"],
            severity=f["severity"],
            description=f["description"],
            evidence_path=f.get("evidence", "")[:500],
        )

    # Deduplicate creds before adding
    seen_creds = set()
    for c in parsed["creds"]:
        key = (c.get("username", ""), c.get("password", ""), c.get("hash", "")[:32])
        if key in seen_creds:
            continue
        seen_creds.add(key)
        if c.get("username") or c.get("password") or c.get("hash"):
            wm.add_cred(
                username=c.get("username", ""),
                password=c.get("password", ""),
                hash_value=c.get("hash", ""),
                hash_type=c.get("hash_type", ""),
                source=c.get("source", tool_name or "generic"),
            )

    wm.close()

    parts = []
    if parsed["findings"]: parts.append(f"{len(parsed['findings'])} findings")
    if parsed["creds"]: parts.append(f"{len(seen_creds)} creds")
    if parsed["hosts"]: parts.append(f"{len(parsed['hosts'])} hosts")
    if parsed["flags"]: parts.append(f"FLAG: {parsed['flags'][0]}")

    return ", ".join(parts) if parts else "no findings"


def main():
    import argparse
    parser = argparse.ArgumentParser(description="TAR Generic Output Parser")
    parser.add_argument("input", nargs="?", default="-", help="Input file (- for stdin)")
    parser.add_argument("--db", help="Path to world_model.db")
    parser.add_argument("--tool", default="", help="Tool name for attribution")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    if args.input == "-":
        text = sys.stdin.read()
    else:
        text = Path(args.input).read_text()

    parsed = parse_generic(text, tool_name=args.tool)

    if args.db:
        summary = update_world_model(args.db, parsed, tool_name=args.tool)
        print(summary)
    elif args.json:
        print(json.dumps(parsed, indent=2))
    else:
        for cat in ("findings", "creds", "hosts", "paths", "flags"):
            items = parsed[cat]
            if items:
                print(f"\n{cat.upper()}:")
                for item in items[:20]:
                    print(f"  {item}")


if __name__ == "__main__":
    main()
