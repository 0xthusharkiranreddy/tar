#!/usr/bin/env python3
"""
playwright_parser.py — Parse perception_engine.py DOM analysis into WM findings.

Input: JSON output from perception_engine.py --json
Output: structured findings + predicates written to world_model.db
"""

import json
import re
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(SCRIPTS_DIR))


def parse_playwright(text: str) -> dict:
    result = {
        "findings": [],
        "creds": [],
        "tech_stack": [],
        "paths": [],
        "predicates": [],
    }

    # Accept either JSON from perception_engine or plain text perception block
    try:
        data = json.loads(text)
        dom = data.get("dom", {})
        timing = data.get("timing", {})
        screenshot = data.get("screenshot")
    except (json.JSONDecodeError, ValueError):
        dom = {}
        timing = {}
        screenshot = None
        # Fallback: parse plain-text block
        _parse_text_block(text, result)
        return result

    # Screenshot captured
    if screenshot:
        result["findings"].append({
            "category": "visual",
            "severity": "info",
            "description": "Web target screenshot captured",
            "evidence": screenshot,
        })
        result["predicates"].append("web_visual_captured")

    # Forms → attack surface
    for form in dom.get("forms", []):
        inputs = form.get("inputs", [])
        action = form.get("action", "")
        method = form.get("method", "GET")
        # Login form detection
        input_names = " ".join(inputs).lower()
        if any(kw in input_names for kw in ("password", "passwd", "pass")):
            result["findings"].append({
                "category": "web",
                "severity": "info",
                "description": f"Login form discovered: {method} {action}",
                "evidence": f"Inputs: {', '.join(inputs[:8])}",
            })
            result["predicates"].append("login_form_found")
        result["paths"].append(action)

    # DOM-XSS sinks
    for sink in dom.get("js_sinks", []):
        result["findings"].append({
            "category": "xss",
            "severity": "medium",
            "description": f"DOM-XSS sink detected: {sink[:80]}",
            "evidence": sink,
        })
    if dom.get("js_sinks"):
        result["predicates"].append("dom_xss_sink_present")

    # Hardcoded JS secrets
    for secret in dom.get("secrets", []):
        result["findings"].append({
            "category": "creds",
            "severity": "high",
            "description": "Hardcoded secret/API key in client-side JS",
            "evidence": secret[:100],
        })
    if dom.get("secrets"):
        result["predicates"].append("js_secret_exposed")

    # SPA routes → path enumeration
    for route in dom.get("spa_routes", []):
        result["paths"].append(route)
    if dom.get("spa_routes"):
        result["predicates"].append("spa_routes_discovered")

    # Auth endpoints intercepted
    for hint in dom.get("auth_hints", []):
        result["findings"].append({
            "category": "web",
            "severity": "info",
            "description": f"Auth endpoint intercepted: {hint[:100]}",
            "evidence": hint,
        })
    if dom.get("auth_hints"):
        result["predicates"].append("auth_endpoint_known")

    # Honeypot
    for flag in dom.get("honeypot_flags", []):
        result["findings"].append({
            "category": "opsec",
            "severity": "high",
            "description": f"Honeypot indicator: {flag}",
            "evidence": flag,
        })
    if dom.get("honeypot_flags"):
        result["predicates"].append("honeypot_detected")

    # Timing
    verdict = timing.get("verdict", "")
    if "INJECTION LIKELY" in verdict:
        result["findings"].append({
            "category": "sqli",
            "severity": "critical",
            "description": f"Time-based injection confirmed: {verdict}",
            "evidence": json.dumps(timing.get("timing_differential", {})),
        })
        result["predicates"].append("timebased_injection_confirmed")
    elif "Marginal" in verdict:
        result["findings"].append({
            "category": "sqli",
            "severity": "medium",
            "description": f"Marginal timing differential: {verdict}",
            "evidence": json.dumps(timing.get("baseline_times", [])),
        })
        result["predicates"].append("timing_differential_marginal")

    return result


def _parse_text_block(text: str, result: dict):
    """Parse plain-text perception_engine output block."""
    if "DOM-XSS sinks" in text:
        result["predicates"].append("dom_xss_sink_present")
        result["findings"].append({
            "category": "xss",
            "severity": "medium",
            "description": "DOM-XSS sinks detected (from visual perception block)",
            "evidence": text[text.find("DOM-XSS sinks"):text.find("DOM-XSS sinks")+200],
        })
    if "Login form" in text or "password[password]" in text.lower():
        result["predicates"].append("login_form_found")
    if "HONEYPOT" in text.upper():
        result["predicates"].append("honeypot_detected")
    if "TIME-BASED INJECTION" in text:
        result["predicates"].append("timebased_injection_confirmed")
    if "JS secrets" in text:
        result["predicates"].append("js_secret_exposed")
    if "SPA routes" in text:
        result["predicates"].append("spa_routes_discovered")
    if "Screenshot saved" in text:
        result["predicates"].append("web_visual_captured")


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("input", nargs="?", default="-")
    parser.add_argument("--db", default="")
    args = parser.parse_args()

    if args.input == "-":
        text = sys.stdin.read()
    else:
        text = Path(args.input).read_text()

    result = parse_playwright(text)

    if args.db:
        from world_model import WorldModel
        wm = WorldModel(args.db)
        for f in result["findings"]:
            wm.add_finding(
                category=f["category"],
                description=f["description"],
                severity=f.get("severity", "info"),
                evidence=f.get("evidence", ""),
            )
        for path in result["paths"]:
            if path and len(path) > 1:
                wm.add_finding(
                    category="path",
                    description=f"SPA/form path: {path}",
                    severity="info",
                )
        wm.close()

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
