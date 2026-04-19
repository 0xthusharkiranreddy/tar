#!/usr/bin/env python3
"""
impacket_parser.py — Parse impacket tool output into structured records.

Handles: GetUserSPNs (Kerberoast), GetNPUsers (AS-REP), secretsdump,
         GetADUsers, findDelegation.

Usage:
    python3 impacket_parser.py --tool kerberoast [--db world_model.db] < output.txt
"""

import json
import re
import sys
from pathlib import Path


def parse_kerberoast(text: str) -> list[dict]:
    """Parse GetUserSPNs output — TGS hashes."""
    results = []
    current_hash = []
    in_hash = False

    for line in text.split("\n"):
        if line.startswith("$krb5tgs$"):
            in_hash = True
            current_hash = [line.strip()]
        elif in_hash and line.strip() and not line.startswith("[-]"):
            current_hash.append(line.strip())
        elif in_hash:
            hash_str = "".join(current_hash)
            # Extract username from hash: $krb5tgs$23$*user$realm$spn*$...
            user_match = re.search(r"\$krb5tgs\$\d+\$\*?([^$*]+)", hash_str)
            results.append({
                "type": "kerberoast",
                "hash": hash_str,
                "username": user_match.group(1) if user_match else "unknown",
                "hash_type": "13100",
            })
            in_hash = False
            current_hash = []

    # Also parse table output: ServicePrincipalName  Name  MemberOf  PasswordLastSet
    for line in text.split("\n"):
        if re.match(r"\S+/\S+\s+\S+\s+", line) and "ServicePrincipalName" not in line and "---" not in line:
            parts = line.split()
            if len(parts) >= 2:
                spn = parts[0]
                username = parts[1]
                # Only add if not already captured via hash
                if not any(r["username"] == username for r in results):
                    results.append({
                        "type": "kerberoast_spn",
                        "spn": spn,
                        "username": username,
                    })

    return results


def parse_asreproast(text: str) -> list[dict]:
    """Parse GetNPUsers output — AS-REP hashes."""
    results = []
    current_hash = []
    in_hash = False

    for line in text.split("\n"):
        if line.startswith("$krb5asrep$"):
            in_hash = True
            current_hash = [line.strip()]
        elif in_hash and line.strip() and not line.startswith("[-]"):
            current_hash.append(line.strip())
        elif in_hash:
            hash_str = "".join(current_hash)
            user_match = re.search(r"\$krb5asrep\$\d+\$([^@:]+)", hash_str)
            results.append({
                "type": "asreproast",
                "hash": hash_str,
                "username": user_match.group(1) if user_match else "unknown",
                "hash_type": "18200",
            })
            in_hash = False
            current_hash = []

    return results


def parse_secretsdump(text: str) -> list[dict]:
    """Parse secretsdump output — SAM/NTDS hashes."""
    results = []
    for line in text.split("\n"):
        line = line.strip()
        # SAM/NTDS format: user:rid:lmhash:nthash:::
        match = re.match(r"^([^:]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::", line)
        if match:
            results.append({
                "type": "ntlm_hash",
                "username": match.group(1),
                "rid": int(match.group(2)),
                "lm_hash": match.group(3),
                "nt_hash": match.group(4),
                "hash_type": "1000",
            })
        # Kerberos keys: user:aes256-cts-hmac-sha1-96:hexkey
        aes_match = re.match(r"^([^:]+):(aes\d+-[^:]+):([a-fA-F0-9]+)$", line)
        if aes_match:
            results.append({
                "type": "kerberos_key",
                "username": aes_match.group(1),
                "key_type": aes_match.group(2),
                "key": aes_match.group(3),
            })
        # Cleartext passwords from LSA secrets
        if "DPAPI_SYSTEM" not in line and "$MACHINE.ACC" not in line:
            cleartext_match = re.match(r"^([^:]+):\$DCC2\$\d+#([^#]+)#([a-fA-F0-9]+)$", line)
            if cleartext_match:
                results.append({
                    "type": "dcc2_hash",
                    "username": cleartext_match.group(2),
                    "hash": line,
                    "hash_type": "2100",
                })

    return results


def parse_getadusers(text: str) -> list[dict]:
    """Parse GetADUsers output."""
    results = []
    for line in text.split("\n"):
        if re.match(r"\S+\s+\d{4}-\d{2}-\d{2}", line):
            parts = line.split()
            if parts:
                results.append({
                    "type": "ad_user",
                    "username": parts[0],
                })
    return results


def parse_find_delegation(text: str) -> list[dict]:
    """Parse findDelegation output."""
    results = []
    for line in text.split("\n"):
        if any(d in line for d in ["Unconstrained", "Constrained", "Resource"]) and "---" not in line and "AccountName" not in line:
            parts = line.split()
            if len(parts) >= 3:
                results.append({
                    "type": "delegation",
                    "account": parts[0],
                    "delegation_type": parts[-1] if parts[-1] in ("Unconstrained", "Constrained", "Resource-Based") else "unknown",
                })
    return results


TOOL_PARSERS = {
    "kerberoast": parse_kerberoast,
    "asreproast": parse_asreproast,
    "secretsdump": parse_secretsdump,
    "getadusers": parse_getadusers,
    "find_delegation": parse_find_delegation,
}


def write_to_world_model(results: list[dict], db_path: str):
    """Write parsed results to world_model."""
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from world_model import WorldModel

    wm = WorldModel(db_path)
    for r in results:
        rtype = r.get("type", "")
        if rtype in ("kerberoast", "asreproast"):
            wm.add_cred(
                username=r.get("username", ""),
                hash_value=r.get("hash", ""),
                hash_type=r.get("hash_type", ""),
                source=rtype,
            )
        elif rtype == "ntlm_hash":
            wm.add_cred(
                username=r.get("username", ""),
                hash_value=r.get("nt_hash", ""),
                hash_type="1000",
                source="secretsdump",
            )
        elif rtype == "ad_user":
            wm.add_user(username=r.get("username", ""), source="getadusers")
        elif rtype == "delegation":
            wm.add_finding(
                category="delegation",
                severity="high",
                description=f"{r['delegation_type']} delegation: {r['account']}",
            )
    wm.close()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Parse impacket tool output")
    parser.add_argument("--tool", required=True, choices=list(TOOL_PARSERS.keys()))
    parser.add_argument("--db", help="World model DB path")
    parser.add_argument("input_file", nargs="?")
    args = parser.parse_args()

    if args.input_file:
        text = Path(args.input_file).read_text()
    else:
        text = sys.stdin.read()

    parse_fn = TOOL_PARSERS[args.tool]
    results = parse_fn(text)

    if args.db:
        write_to_world_model(results, args.db)

    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
