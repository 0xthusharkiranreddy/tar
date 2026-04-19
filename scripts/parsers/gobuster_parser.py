#!/usr/bin/env python3
"""
gobuster_parser.py — Parse gobuster/feroxbuster/ffuf output into structured findings.

Usage:
    python3 gobuster_parser.py [--db /path/to/world_model.db] < output.txt
    cat output.txt | python3 gobuster_parser.py --db /path/to/world_model.db

Handles output from gobuster dir, feroxbuster, and ffuf.
"""

import json
import re
import sys
from pathlib import Path


def parse_gobuster(text: str) -> list[dict]:
    """Parse gobuster dir output."""
    results = []
    for line in text.strip().split("\n"):
        # gobuster: /path (Status: 200) [Size: 1234]
        match = re.match(r"(/\S*)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]", line.strip())
        if match:
            results.append({
                "path": match.group(1),
                "status": int(match.group(2)),
                "size": int(match.group(3)),
                "source": "gobuster",
            })
    return results


def parse_feroxbuster(text: str) -> list[dict]:
    """Parse feroxbuster output."""
    results = []
    for line in text.strip().split("\n"):
        # feroxbuster: 200  GET  1234l  5678w  91011c  http://target/path
        match = re.match(r"\s*(\d+)\s+\w+\s+(\d+)l\s+(\d+)w\s+(\d+)c\s+(https?://\S+)", line.strip())
        if match:
            url = match.group(5)
            path = re.sub(r"https?://[^/]+", "", url)
            results.append({
                "path": path or "/",
                "status": int(match.group(1)),
                "size": int(match.group(4)),
                "url": url,
                "source": "feroxbuster",
            })
    return results


def parse_ffuf(text: str) -> list[dict]:
    """Parse ffuf output (text or JSON)."""
    results = []

    # Try JSON first
    try:
        data = json.loads(text)
        for r in data.get("results", []):
            results.append({
                "path": r.get("input", {}).get("FUZZ", ""),
                "status": r.get("status", 0),
                "size": r.get("length", 0),
                "words": r.get("words", 0),
                "url": r.get("url", ""),
                "source": "ffuf",
            })
        return results
    except (json.JSONDecodeError, TypeError):
        pass

    # Text output: [Status: 200, Size: 1234, Words: 56, Lines: 78, Duration: 12ms]
    for line in text.strip().split("\n"):
        match = re.match(
            r"(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)",
            line.strip()
        )
        if match:
            results.append({
                "path": match.group(1),
                "status": int(match.group(2)),
                "size": int(match.group(3)),
                "source": "ffuf",
            })
    return results


def parse_web_fuzz(text: str) -> list[dict]:
    """Auto-detect and parse gobuster/feroxbuster/ffuf output."""
    if "feroxbuster" in text[:500].lower() or re.search(r"\d+\s+\w+\s+\d+l\s+\d+w", text[:500]):
        return parse_feroxbuster(text)
    elif '"results"' in text[:200]:
        return parse_ffuf(text)
    elif "Status:" in text[:500] and "[Size:" in text[:500]:
        return parse_gobuster(text)
    elif "[Status:" in text[:500]:
        return parse_ffuf(text)
    else:
        # Try all parsers
        results = parse_gobuster(text)
        if not results:
            results = parse_feroxbuster(text)
        if not results:
            results = parse_ffuf(text)
        return results


def write_to_world_model(results: list[dict], db_path: str, host_ip: str = None):
    """Write findings to world_model."""
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from world_model import WorldModel

    wm = WorldModel(db_path)
    for r in results:
        wm.add_finding(
            category="web_directory",
            severity="info",
            description=f"{r['source']}: {r['path']} (status={r['status']}, size={r['size']})",
            evidence_path=r.get("url", r["path"]),
        )
    wm.close()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Parse web fuzzer output")
    parser.add_argument("--db", help="World model DB path")
    parser.add_argument("--host", help="Target host IP")
    parser.add_argument("input_file", nargs="?", help="Input file (default: stdin)")
    args = parser.parse_args()

    if args.input_file:
        text = Path(args.input_file).read_text()
    else:
        text = sys.stdin.read()

    results = parse_web_fuzz(text)

    if args.db:
        write_to_world_model(results, args.db, args.host)

    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
