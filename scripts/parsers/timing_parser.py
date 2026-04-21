#!/usr/bin/env python3
"""
timing_parser.py — Parse curl/timing probe output for response-time differentials.

Handles:
  - curl -w "%{time_*}" output
  - Manual timing probe JSON from perception_engine.timing_probe()
  - httpx / ffuf timing fields
  - Response-size differentials (authenticated vs not)
"""

import json
import re
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(SCRIPTS_DIR))


# Time thresholds in seconds
BLIND_SQLI_THRESHOLD = 4.0   # payload response ≥ baseline + this → likely time-based injection
INTERESTING_DIFF = 1.5       # worth flagging, further investigation


def parse_timing(text: str) -> dict:
    result = {
        "findings": [],
        "predicates": [],
        "timing_data": {},
    }

    # JSON output from perception_engine.timing_probe()
    try:
        data = json.loads(text)
        if "baseline_avg" in data:
            _parse_timing_probe_json(data, result)
            return result
    except (json.JSONDecodeError, ValueError):
        pass

    # curl -w output: time_total, time_connect, time_starttransfer
    curl_times = {}
    for m in re.finditer(r"(time_\w+):\s*([\d.]+)", text, re.I):
        curl_times[m.group(1)] = float(m.group(2))

    if curl_times:
        result["timing_data"] = curl_times
        total = curl_times.get("time_total", 0)
        ttfb = curl_times.get("time_starttransfer", 0)

        if total >= BLIND_SQLI_THRESHOLD:
            result["findings"].append({
                "category": "sqli",
                "severity": "high",
                "description": f"Suspiciously high response time: {total:.2f}s — possible time-based injection",
                "evidence": str(curl_times),
            })
            result["predicates"].append("timing_anomaly_detected")

        if ttfb > 0 and total > 0:
            result["timing_data"]["ttfb_ratio"] = round(ttfb / total, 2)

    # httpx / ffuf format: [200] [1234] [1.234s]
    for m in re.finditer(r"\[(\d{3})\]\s+\[(\d+)\]\s+\[([\d.]+)s\]", text):
        status, size, elapsed = m.groups()
        result["timing_data"].setdefault("responses", []).append({
            "status": int(status),
            "size": int(size),
            "elapsed": float(elapsed),
        })

    # Response-size differential: same endpoint, different size = conditional response
    responses = result["timing_data"].get("responses", [])
    if len(responses) >= 2:
        sizes = [r["size"] for r in responses]
        if max(sizes) - min(sizes) > 200:
            result["findings"].append({
                "category": "web",
                "severity": "medium",
                "description": "Response size differential detected — possible conditional execution (auth bypass / injection)",
                "evidence": f"Sizes: {sizes}",
            })
            result["predicates"].append("response_size_differential")

    return result


def _parse_timing_probe_json(data: dict, result: dict):
    verdict = data.get("verdict", "")
    result["timing_data"] = {
        "baseline_avg": data.get("baseline_avg"),
        "baseline_stddev": data.get("baseline_stddev"),
        "payload_times": data.get("payload_times", {}),
        "timing_differential": data.get("timing_differential", {}),
    }

    if "INJECTION LIKELY" in verdict:
        result["findings"].append({
            "category": "sqli",
            "severity": "critical",
            "description": verdict,
            "evidence": json.dumps(data.get("timing_differential", {})),
        })
        result["predicates"].append("timebased_injection_confirmed")
    elif "Marginal" in verdict:
        result["findings"].append({
            "category": "sqli",
            "severity": "medium",
            "description": verdict,
            "evidence": json.dumps(data.get("baseline_times", [])),
        })
        result["predicates"].append("timing_differential_marginal")

    # Authenticated vs unauthenticated timing in differential
    diffs = data.get("timing_differential", {})
    max_diff = max(diffs.values()) if diffs else 0
    if max_diff >= INTERESTING_DIFF:
        result["predicates"].append("timing_anomaly_detected")


def main():
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("input", nargs="?", default="-")
    p.add_argument("--db", default="")
    args = p.parse_args()

    if args.input == "-":
        text = sys.stdin.read()
    else:
        text = Path(args.input).read_text()

    result = parse_timing(text)

    if args.db and result["findings"]:
        from world_model import WorldModel
        wm = WorldModel(args.db)
        for f in result["findings"]:
            wm.add_finding(
                category=f["category"],
                description=f["description"],
                severity=f.get("severity", "info"),
                evidence=f.get("evidence", ""),
            )
        wm.close()

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
