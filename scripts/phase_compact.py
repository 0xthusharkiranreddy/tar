#!/usr/bin/env python3
"""
phase_compact.py — Generate compaction state from world_model.

Modes:
    phase-boundary: Detailed delta for mid-session phase transitions
    session-end:    Full state dump for next session boot

Usage:
    python3 phase_compact.py <world_model.db> [phase-boundary|session-end]
"""

import json
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from world_model import WorldModel


def phase_boundary(db_path: str) -> str:
    wm = WorldModel(db_path)
    summary = wm.get_state_summary()
    phase = summary.get("phase", "unknown")
    predicates = sorted(wm.get_state_predicates())
    services = wm.get_services()
    creds = wm.get_creds()
    users = wm.get_users()
    shares = wm.get_shares()
    findings = wm.get_findings()
    failed = wm.get_failed_attempts()
    wm.close()

    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [f"# Phase Boundary Delta — entered {phase} at {ts}", ""]

    lines.append("## Services")
    for s in services:
        product = s.get("product") or "?"
        version = s.get("version") or ""
        line = f"- {s['host_ip']}:{s['port']}/{s.get('protocol','tcp')} {product} {version}".strip()
        if s.get("scripts") and isinstance(s["scripts"], dict):
            scripts_str = ", ".join(list(s["scripts"].keys())[:5])
            line += f" | scripts: {scripts_str}"
        lines.append(line)

    if creds:
        lines.append("")
        lines.append("## Credentials")
        for c in creds:
            dom = f"{c['domain']}\\" if c.get("domain") else ""
            user = c.get("username") or "?"
            if c.get("password"):
                secret = f"pw:{c['password'][:3]}***"
            elif c.get("hash"):
                secret = f"hash:{c.get('hash_type') or '?'}"
            else:
                secret = "no_secret"
            verified = " [verified]" if c.get("verified") else ""
            source = f" (from: {c.get('source', '?')})" if c.get("source") else ""
            lines.append(f"- {dom}{user} ({secret}){verified}{source}")

    if users:
        lines.append("")
        lines.append(f"## Users ({len(users)} enumerated)")
        admins = [u for u in users if u.get("is_admin")]
        spn_users = [u for u in users if u.get("spn")]
        if admins:
            lines.append(f"- Admins: {', '.join(u['username'] for u in admins[:10])}")
        if spn_users:
            lines.append(f"- SPN (Kerberoastable): {', '.join(u['username'] for u in spn_users[:10])}")

    if shares:
        lines.append("")
        lines.append("## Shares")
        for s in shares:
            lines.append(f"- //{s['host_ip']}/{s['name']} [{s.get('access_level', '?')}]")

    if findings:
        lines.append("")
        lines.append("## Key Findings")
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for f in sorted(findings, key=lambda x: severity_order.get(x.get("severity", "info"), 5)):
            sev = f.get("severity", "info")
            if sev in ("critical", "high", "medium"):
                lines.append(f"- [{sev.upper()}] {f['description'][:100]}")

    if failed:
        lines.append("")
        lines.append("## Failed Actions (do NOT retry)")
        seen = set()
        for f in failed:
            aname = f["action_name"]
            if aname not in seen:
                seen.add(aname)
                silence = f.get("silence_pattern") or f.get("error_output") or "?"
                lines.append(f"- {aname}: {silence[:60]}")

    lines.append("")
    lines.append("## Active Predicates")
    lines.append(", ".join(predicates))
    lines.append("")
    lines.append("---")
    lines.append("This delta replaces raw scan output. Read world_model.db for full details.")

    return "\n".join(lines)


def session_end(db_path: str) -> str:
    wm = WorldModel(db_path)
    summary = wm.get_state_summary()
    predicates = sorted(wm.get_state_predicates())

    eng = wm.conn.execute(
        "SELECT * FROM engagement ORDER BY id DESC LIMIT 1"
    ).fetchone()
    eng_name = eng["name"] if eng else "unknown"
    eng_ip = eng["target_ip"] if eng else "?"
    tier = eng["tier"] if eng else "balanced"

    services = wm.get_services()
    creds = wm.get_creds()
    users = wm.get_users()
    shares = wm.get_shares()
    findings = wm.get_findings()
    failed = wm.get_failed_attempts()
    wm.close()

    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [
        f"# TAR Session State — {eng_name} ({eng_ip})",
        f"Saved: {ts} | Phase: {summary['phase']} | Tier: {tier}",
        "",
    ]

    lines.append("## Services")
    for s in services:
        p = s.get("product") or "?"
        v = s.get("version") or ""
        lines.append(f"- {s['host_ip']}:{s['port']} {p} {v}".strip())

    if creds:
        lines.append("")
        lines.append("## Credentials")
        for c in creds:
            dom = f"{c['domain']}\\" if c.get("domain") else ""
            user = c.get("username") or "?"
            secret = "pw" if c.get("password") else "hash" if c.get("hash") else "none"
            verified = " [v]" if c.get("verified") else ""
            lines.append(f"- {dom}{user} ({secret}){verified}")

    if users:
        lines.append("")
        lines.append(f"## Users: {len(users)} enumerated")

    if shares:
        lines.append("")
        lines.append("## Shares")
        for s in shares:
            lines.append(f"- //{s['host_ip']}/{s['name']} [{s.get('access_level', '?')}]")

    if findings:
        lines.append("")
        lines.append("## Findings")
        for f in findings:
            sev = f.get("severity", "info")
            lines.append(f"- [{sev}] {f['description'][:80]}")

    if failed:
        lines.append("")
        lines.append("## Failed")
        seen = set()
        for f in failed:
            if f["action_name"] not in seen:
                seen.add(f["action_name"])
                lines.append(f"- {f['action_name']}")

    lines.append("")
    lines.append("## Predicates")
    lines.append(", ".join(predicates))
    lines.append("")
    lines.append("## Next Action")
    lines.append("## Falsifier")

    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <world_model.db> [phase-boundary|session-end]")
        sys.exit(1)

    db_path = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else "session-end"

    if mode == "phase-boundary":
        print(phase_boundary(db_path))
    else:
        print(session_end(db_path))


if __name__ == "__main__":
    main()
