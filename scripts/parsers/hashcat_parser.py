#!/usr/bin/env python3
"""
hashcat_parser.py — Parse hashcat/john cracked output into credential records.

Usage:
    python3 hashcat_parser.py [--db world_model.db] < cracked.txt
    python3 hashcat_parser.py --potfile ~/.hashcat/hashcat.potfile [--db world_model.db]
"""

import json
import re
import sys
from pathlib import Path


def parse_cracked(text: str) -> list[dict]:
    """Parse hashcat -o output or john --show output (hash:password format)."""
    results = []
    for line in text.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Kerberoast: $krb5tgs$23$*user$realm$spn*$...:password
        krb_match = re.match(r"\$krb5tgs\$\d+\$\*?([^$*]+).*:(.+)$", line)
        if krb_match:
            results.append({
                "username": krb_match.group(1),
                "password": krb_match.group(2),
                "source": "kerberoast_crack",
                "hash_type": "13100",
            })
            continue

        # AS-REP: $krb5asrep$23$user@domain:...:password
        asrep_match = re.match(r"\$krb5asrep\$\d+\$([^@:]+).*:(.+)$", line)
        if asrep_match:
            results.append({
                "username": asrep_match.group(1),
                "password": asrep_match.group(2),
                "source": "asreproast_crack",
                "hash_type": "18200",
            })
            continue

        # NTLM: hash:password  or  user:rid:lmhash:nthash:password
        ntlm_match = re.match(r"([a-fA-F0-9]{32}):(.+)$", line)
        if ntlm_match:
            results.append({
                "hash": ntlm_match.group(1),
                "password": ntlm_match.group(2),
                "source": "ntlm_crack",
                "hash_type": "1000",
            })
            continue

        # NTLMv2: user::domain:challenge:hash:password
        ntlmv2_match = re.match(r"([^:]+)::[^:]*:[^:]+:[^:]+:(.+)$", line)
        if ntlmv2_match:
            results.append({
                "username": ntlmv2_match.group(1),
                "password": ntlmv2_match.group(2),
                "source": "ntlmv2_crack",
                "hash_type": "5600",
            })
            continue

        # Generic hash:password (sha512crypt, md5crypt, bcrypt, etc.)
        if ":" in line:
            parts = line.rsplit(":", 1)
            if len(parts) == 2 and parts[1]:
                results.append({
                    "hash_or_user": parts[0],
                    "password": parts[1],
                    "source": "hash_crack",
                })

    return results


def write_to_world_model(results: list[dict], db_path: str):
    """Write cracked credentials to world_model."""
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from world_model import WorldModel

    wm = WorldModel(db_path)
    for r in results:
        wm.add_cred(
            username=r.get("username", r.get("hash_or_user", "")),
            password=r.get("password", ""),
            source=r.get("source", "crack"),
            verified=False,
        )
    wm.close()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Parse hashcat/john cracked output")
    parser.add_argument("--db", help="World model DB path")
    parser.add_argument("--potfile", help="Hashcat potfile path")
    parser.add_argument("input_file", nargs="?")
    args = parser.parse_args()

    if args.potfile:
        text = Path(args.potfile).read_text()
    elif args.input_file:
        text = Path(args.input_file).read_text()
    else:
        text = sys.stdin.read()

    results = parse_cracked(text)

    if args.db:
        write_to_world_model(results, args.db)

    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
