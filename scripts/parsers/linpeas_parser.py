#!/usr/bin/env python3
"""
linpeas_parser.py — Parse LinPEAS/WinPEAS output into structured findings.

Usage:
    python3 linpeas_parser.py [--db world_model.db] < linpeas_output.txt
"""

import json
import re
import sys
from pathlib import Path


# Section headers in LinPEAS output
LINPEAS_SECTIONS = {
    "SUID": "suid",
    "Capabilities": "capabilities",
    "Cron jobs": "cron",
    "writable": "writable",
    "sudo": "sudo",
    "passwd": "passwords",
    "SSH": "ssh",
    "Docker": "docker",
    "Interesting Files": "files",
}


def parse_linpeas(text: str) -> list[dict]:
    """Parse LinPEAS output into categorized findings."""
    findings = []
    current_section = "general"

    # Color codes cleanup
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)

    for line in text.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue

        # Detect section headers
        for keyword, section in LINPEAS_SECTIONS.items():
            if keyword.lower() in stripped.lower() and ("═" in stripped or "╔" in stripped or "──" in stripped):
                current_section = section
                break

        # SUID binaries
        if current_section == "suid" and stripped.startswith("/"):
            findings.append({
                "category": "suid",
                "severity": "medium",
                "path": stripped.split()[0] if stripped.split() else stripped,
                "description": f"SUID binary: {stripped.split()[0] if stripped.split() else stripped}",
            })

        # Capabilities
        if current_section == "capabilities" and "cap_" in stripped.lower():
            findings.append({
                "category": "capability",
                "severity": "high" if "cap_setuid" in stripped.lower() else "medium",
                "description": stripped,
            })

        # Cron jobs
        if current_section == "cron" and ("*" in stripped or "cron" in stripped.lower()):
            if not stripped.startswith("#"):
                findings.append({
                    "category": "cron",
                    "severity": "medium",
                    "description": stripped,
                })

        # Sudo permissions
        if "NOPASSWD" in stripped or "(ALL)" in stripped:
            findings.append({
                "category": "sudo",
                "severity": "high",
                "description": stripped,
            })

        # Interesting files with passwords/keys
        if re.search(r"password|passwd|id_rsa|\.pem|\.key|credential|secret", stripped, re.I):
            if re.search(r"[=:].*\S", stripped) and "Binary file" not in stripped:
                findings.append({
                    "category": "credential_file",
                    "severity": "high",
                    "description": stripped[:200],
                })

        # Docker group membership
        if "docker" in stripped.lower() and "group" in stripped.lower():
            findings.append({
                "category": "docker",
                "severity": "critical",
                "description": "User is in docker group — root equivalent",
            })

    return findings


def parse_winpeas(text: str) -> list[dict]:
    """Parse WinPEAS output into categorized findings."""
    findings = []
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)

    for line in text.split("\n"):
        stripped = line.strip()

        # SeImpersonatePrivilege
        if "SeImpersonatePrivilege" in stripped or "SeAssignPrimaryTokenPrivilege" in stripped:
            findings.append({
                "category": "token_privesc",
                "severity": "critical",
                "description": f"Dangerous privilege: {stripped}",
            })

        # AlwaysInstallElevated
        if "AlwaysInstallElevated" in stripped:
            findings.append({
                "category": "msi_privesc",
                "severity": "critical",
                "description": "AlwaysInstallElevated enabled — install MSI as SYSTEM",
            })

        # Unquoted service paths
        if re.search(r"unquoted.*path|service.*path.*space", stripped, re.I):
            findings.append({
                "category": "unquoted_path",
                "severity": "high",
                "description": stripped[:200],
            })

        # Stored credentials
        if "cmdkey" in stripped.lower() and "target" in stripped.lower():
            findings.append({
                "category": "stored_cred",
                "severity": "high",
                "description": stripped[:200],
            })

        # AutoLogon
        if re.search(r"DefaultPassword|AutoLogon", stripped, re.I):
            findings.append({
                "category": "autologon",
                "severity": "high",
                "description": stripped[:200],
            })

    return findings


def write_to_world_model(findings: list[dict], db_path: str):
    """Write findings to world_model."""
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from world_model import WorldModel

    wm = WorldModel(db_path)
    for f in findings:
        wm.add_finding(
            category=f["category"],
            severity=f.get("severity", "info"),
            description=f["description"],
        )
    wm.close()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Parse LinPEAS/WinPEAS output")
    parser.add_argument("--db", help="World model DB path")
    parser.add_argument("--type", choices=["linux", "windows"], default="linux")
    parser.add_argument("input_file", nargs="?")
    args = parser.parse_args()

    if args.input_file:
        text = Path(args.input_file).read_text(errors="replace")
    else:
        text = sys.stdin.read()

    if args.type == "windows":
        findings = parse_winpeas(text)
    else:
        findings = parse_linpeas(text)

    if args.db:
        write_to_world_model(findings, args.db)

    print(json.dumps(findings, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
