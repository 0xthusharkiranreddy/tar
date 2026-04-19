#!/usr/bin/env python3
"""
responder_parser.py — Parse Responder log files for captured hashes.

Usage:
    python3 responder_parser.py --log-dir /usr/share/responder/logs/ [--db world_model.db]
    cat responder_output.txt | python3 responder_parser.py [--db world_model.db]
"""

import json
import re
import sys
from pathlib import Path


def parse_responder_logs(log_dir: str) -> list[dict]:
    """Parse Responder log directory for captured hashes."""
    results = []
    log_path = Path(log_dir)

    for log_file in log_path.glob("*.txt"):
        for line in log_file.read_text(errors="replace").split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # NTLMv2 hash format: user::domain:challenge:hash:hash
            if "::" in line and line.count(":") >= 5:
                parts = line.split(":")
                if len(parts) >= 6:
                    results.append({
                        "type": "ntlmv2",
                        "username": parts[0],
                        "domain": parts[2] if len(parts) > 2 else "",
                        "hash": line,
                        "hash_type": "5600",
                        "source": f"responder:{log_file.name}",
                    })

    return results


def parse_responder_stdout(text: str) -> list[dict]:
    """Parse Responder console output for captured hashes."""
    results = []
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)

    for line in text.split("\n"):
        # [+] NTLMv2 Hash: user::domain:...
        hash_match = re.search(r"NTLMv[12]\s+(?:Hash|Client)\s*:\s*(.+)", line)
        if hash_match:
            hash_line = hash_match.group(1).strip()
            parts = hash_line.split(":")
            results.append({
                "type": "ntlmv2" if "v2" in line else "ntlmv1",
                "username": parts[0] if parts else "unknown",
                "hash": hash_line,
                "hash_type": "5600" if "v2" in line else "5500",
                "source": "responder",
            })

        # [+] Cleartext password: ...
        clear_match = re.search(r"Cleartext\s+(?:password|Password)\s*:\s*(.+)", line)
        if clear_match:
            results.append({
                "type": "cleartext",
                "password": clear_match.group(1).strip(),
                "source": "responder",
            })

    return results


def write_to_world_model(results: list[dict], db_path: str):
    """Write captured hashes to world_model."""
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from world_model import WorldModel

    wm = WorldModel(db_path)
    for r in results:
        if r["type"] == "cleartext":
            wm.add_cred(password=r["password"], source="responder")
        else:
            wm.add_cred(
                username=r.get("username", ""),
                hash_value=r.get("hash", ""),
                hash_type=r.get("hash_type", ""),
                source="responder",
            )
    wm.close()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Parse Responder output/logs")
    parser.add_argument("--db", help="World model DB path")
    parser.add_argument("--log-dir", help="Responder logs directory")
    parser.add_argument("input_file", nargs="?")
    args = parser.parse_args()

    if args.log_dir:
        results = parse_responder_logs(args.log_dir)
    elif args.input_file:
        text = Path(args.input_file).read_text(errors="replace")
        results = parse_responder_stdout(text)
    else:
        text = sys.stdin.read()
        results = parse_responder_stdout(text)

    if args.db:
        write_to_world_model(results, args.db)

    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
