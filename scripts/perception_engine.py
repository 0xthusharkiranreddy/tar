#!/usr/bin/env python3
"""
perception_engine.py — Visual and timing perception for TAR.

Fills four human-operator perception gaps:
  1. Visual  — headless-browser screenshot + rendered DOM summary
  2. JS      — extracts forms, event-handlers, JS secrets, SPA routes, DOM-XSS sinks
  3. Timing  — baseline vs auth/payload response-time differential
  4. Canary  — honeypot fingerprint checks on rendered content

Called from the planner-context hook when web targets exist in WM.
Also callable standalone:
    python3 perception_engine.py --db /path/world_model.db --url https://target/
"""

import argparse
import base64
import json
import re
import subprocess
import sys
import time
from pathlib import Path

SCRIPTS_DIR = Path(__file__).parent


# ── Playwright availability ─────────────────────────────────────────────────

def _playwright_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
        return True
    except ImportError:
        return False


# ── Screenshot ──────────────────────────────────────────────────────────────

def capture_screenshot(url: str, out_path: Path, timeout_ms: int = 12000) -> bool:
    """Render URL headlessly, save PNG to out_path. Returns True on success."""
    if not _playwright_available():
        return False
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                executable_path="/usr/bin/chromium",
                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
            )
            ctx = browser.new_context(ignore_https_errors=True)
            page = ctx.new_page()
            page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
            page.wait_for_timeout(1500)  # let deferred JS settle
            page.screenshot(path=str(out_path), full_page=False)
            browser.close()
        return out_path.exists()
    except Exception:
        return False


# ── DOM analysis ─────────────────────────────────────────────────────────────

# DOM-XSS sink patterns — things that can execute injected JS in the rendered page
_DOM_XSS_SINKS = re.compile(
    r"(innerHTML\s*=|outerHTML\s*=|insertAdjacentHTML|document\.write\s*\(|"
    r"eval\s*\(|setTimeout\s*\(|setInterval\s*\(|location\.href\s*=|"
    r"window\.location\s*=|src\s*=.*[\"'].*\+|href\s*=.*[\"'].*\+)",
    re.I,
)

_SECRET_PATTERNS = re.compile(
    r"(?:api[_-]?key|secret|token|password|passwd|auth|bearer|private[_-]?key"
    r"|access[_-]?key|client[_-]?secret)\s*[=:]\s*[\"']([^\"']{8,})[\"']",
    re.I,
)

_SPA_ROUTE_PATTERNS = re.compile(
    r"(?:path|route|url)\s*:\s*[\"'](/[^\"']*)[\"']",
    re.I,
)


def analyze_dom(url: str, timeout_ms: int = 15000) -> dict:
    """
    Render URL and extract:
      - Page title, headings (h1-h3), meta description
      - All forms (action, method, input names/types)
      - JS event-handlers registered (click, submit, change)
      - DOM-XSS sink patterns found in inline JS
      - Hardcoded secrets / API keys in JS
      - SPA route definitions
      - Login/auth endpoint hints
      - Honeypot indicators (fake creds pages, canary tokens)

    Returns a structured dict.
    """
    result = {
        "title": "",
        "headings": [],
        "forms": [],
        "js_sinks": [],
        "secrets": [],
        "spa_routes": [],
        "auth_hints": [],
        "honeypot_flags": [],
        "rendered_text_excerpt": "",
        "error": None,
    }

    if not _playwright_available():
        result["error"] = "playwright not available"
        return result

    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                executable_path="/usr/bin/chromium",
                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
            )
            ctx = browser.new_context(ignore_https_errors=True)
            page = ctx.new_page()

            # Intercept requests for auth-endpoint detection
            auth_hints = []
            def on_request(req):
                url_lower = req.url.lower()
                if any(kw in url_lower for kw in ("login", "auth", "signin", "token", "oauth", "sso", "saml", "api/v")):
                    auth_hints.append(f"{req.method} {req.url[:120]}")

            page.on("request", on_request)

            page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
            page.wait_for_timeout(2000)

            # Title
            result["title"] = page.title()

            # Headings
            for tag in ("h1", "h2", "h3"):
                elements = page.query_selector_all(tag)
                for el in elements[:5]:
                    text = el.inner_text().strip()[:80]
                    if text:
                        result["headings"].append(f"<{tag}> {text}")

            # Forms
            forms = page.query_selector_all("form")
            for form in forms[:10]:
                action = form.get_attribute("action") or ""
                method = (form.get_attribute("method") or "GET").upper()
                inputs = []
                for inp in form.query_selector_all("input, textarea, select"):
                    inp_name = inp.get_attribute("name") or inp.get_attribute("id") or "?"
                    inp_type = inp.get_attribute("type") or "text"
                    inputs.append(f"{inp_name}[{inp_type}]")
                result["forms"].append({
                    "action": action[:100],
                    "method": method,
                    "inputs": inputs[:15],
                })

            # Inline JS analysis
            scripts = page.query_selector_all("script")
            all_js = ""
            for script in scripts[:20]:
                content = script.inner_html()
                all_js += content + "\n"

            # DOM-XSS sinks
            for m in _DOM_XSS_SINKS.finditer(all_js):
                result["js_sinks"].append(m.group(0)[:100])
            result["js_sinks"] = list(set(result["js_sinks"]))[:10]

            # Secrets
            for m in _SECRET_PATTERNS.finditer(all_js):
                result["secrets"].append(f"{m.group(0)[:60]}...")
            result["secrets"] = list(set(result["secrets"]))[:5]

            # SPA routes
            for m in _SPA_ROUTE_PATTERNS.finditer(all_js):
                result["spa_routes"].append(m.group(1))
            result["spa_routes"] = list(set(result["spa_routes"]))[:15]

            # Auth hints from intercepted requests
            result["auth_hints"] = list(set(auth_hints))[:10]

            # Honeypot indicators
            body_text = page.inner_text("body")[:3000]
            result["rendered_text_excerpt"] = body_text[:500]
            _check_honeypot_signals(result, page, body_text)

            browser.close()

    except Exception as e:
        result["error"] = str(e)[:200]

    return result


def _check_honeypot_signals(result: dict, page, body_text: str):
    """Populate result['honeypot_flags'] with detected honeypot indicators."""
    flags = []

    # Common honeypot tool signatures
    honeypot_signatures = [
        ("glastopf", "Glastopf web honeypot"),
        ("kippo", "Kippo SSH honeypot marker"),
        ("honeyd", "honeyd service emulator"),
        ("conpot", "ConPot ICS honeypot"),
        ("dionaea", "Dionaea malware honeypot"),
        ("HFish", "HFish honeypot platform"),
        ("opencanary", "OpenCanary honeypot"),
        ("canarytokens", "CanaryTokens canary file"),
        ("thinkst", "Thinkst canary detection"),
    ]
    body_lower = body_text.lower()
    for sig, desc in honeypot_signatures:
        if sig.lower() in body_lower:
            flags.append(f"Signature match: {desc}")

    # Too-perfect service enumeration (some honeypots serve static nmap-looking pages)
    if re.search(r"22/tcp.*open.*ssh.*OpenSSH.*80/tcp.*open.*http", body_text, re.I):
        flags.append("Body contains nmap-style service listing — possible honeypot lure")

    # Login page with suspiciously common default creds in source comments
    html = page.content()
    if re.search(r"<!--.*(?:admin.*admin|test.*test|root.*root).*-->", html, re.I):
        flags.append("HTML comment contains default-credential hint — possible credential canary")

    # Overly fast response combined with no real content
    if len(body_text.strip()) < 50:
        flags.append("Near-empty rendered body — service may be a minimal responder")

    result["honeypot_flags"] = flags


# ── Timing probe ─────────────────────────────────────────────────────────────

def timing_probe(url: str, n: int = 5, extra_headers: dict = None) -> dict:
    """
    Fire N requests to url, record time_total per request via curl -w.
    Also fires a payload request with a sleep-inducing parameter to
    detect time-based blind SQLi / SSTI / command injection.

    Returns {
        baseline_times: [float],
        baseline_avg: float,
        baseline_stddev: float,
        payload_times: {payload_name: float},
        timing_differential: {payload_name: float},  # seconds above baseline
        verdict: str,
    }
    """
    result = {
        "baseline_times": [],
        "baseline_avg": 0.0,
        "baseline_stddev": 0.0,
        "payload_times": {},
        "timing_differential": {},
        "verdict": "no timing signal",
    }

    header_args = []
    if extra_headers:
        for k, v in extra_headers.items():
            header_args += ["-H", f"{k}: {v}"]

    def _curl_time(target_url: str) -> float:
        try:
            out = subprocess.check_output(
                ["curl", "-sk", "-o", "/dev/null", "-w", "%{time_total}",
                 "--max-time", "15", "--connect-timeout", "5", target_url]
                + header_args,
                timeout=20,
            )
            return float(out.decode().strip())
        except Exception:
            return -1.0

    # Baseline
    times = [_curl_time(url) for _ in range(n)]
    times = [t for t in times if t >= 0]
    if not times:
        result["verdict"] = "curl baseline failed"
        return result

    avg = sum(times) / len(times)
    variance = sum((t - avg) ** 2 for t in times) / len(times)
    stddev = variance ** 0.5

    result["baseline_times"] = [round(t, 3) for t in times]
    result["baseline_avg"] = round(avg, 3)
    result["baseline_stddev"] = round(stddev, 3)

    # Time-based injection payloads (append to URL as query param)
    sep = "&" if "?" in url else "?"
    payloads = {
        "sqli_sleep_5":  f"{url}{sep}id=1'+AND+SLEEP(5)--+-",
        "sqli_pg_sleep":  f"{url}{sep}id=1';SELECT+pg_sleep(5)--",
        "cmd_sleep_5":   f"{url}{sep}id=1;sleep+5",
        "ssti_sleep":    f"{url}{sep}name=%7B%7B7*'7'%7D%7D",  # Jinja detect (no sleep, different length)
    }

    for name, purl in payloads.items():
        t = _curl_time(purl)
        if t >= 0:
            result["payload_times"][name] = round(t, 3)
            diff = round(t - avg, 3)
            result["timing_differential"][name] = diff

    # Verdict
    strong_signals = [
        name for name, diff in result["timing_differential"].items()
        if diff >= 4.0 and "sleep" in name
    ]
    if strong_signals:
        result["verdict"] = f"TIME-BASED INJECTION LIKELY: {', '.join(strong_signals)} (+{max(result['timing_differential'].values()):.1f}s above baseline)"
    elif any(d >= 2.0 for d in result["timing_differential"].values()):
        result["verdict"] = "Marginal timing differential — possible time-based injection, needs deeper probe"
    else:
        result["verdict"] = f"No timing signal (baseline {avg:.2f}s ±{stddev:.2f}s)"

    return result


# ── Hook-facing entry point ──────────────────────────────────────────────────

def perceive_web_target(url: str, db_path: str, out_dir: Path) -> str:
    """
    Run full perception pass on a web target.
    Returns a text block ready for injection into planner-context hook output.
    Saves screenshot to out_dir/<sanitised_url>.png if possible.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^\w]", "_", url)[:60]
    screenshot_path = out_dir / f"{safe}.png"

    lines = [f"## Visual Perception — {url}"]

    # Screenshot
    captured = capture_screenshot(url, screenshot_path)
    if captured:
        lines.append(f"Screenshot saved → `{screenshot_path}` (use Read tool to view)")
    else:
        lines.append("Screenshot: chromium headless unavailable — DOM analysis only")

    # DOM analysis
    dom = analyze_dom(url)
    if dom.get("error"):
        lines.append(f"DOM analysis error: {dom['error']}")
    else:
        if dom["title"]:
            lines.append(f"Title: {dom['title']}")
        if dom["headings"]:
            lines.append("Headings: " + " | ".join(dom["headings"][:4]))
        if dom["forms"]:
            for f in dom["forms"][:3]:
                inputs_str = ", ".join(f["inputs"][:8])
                lines.append(f"Form [{f['method']} {f['action'] or '/'}]: {inputs_str}")
        if dom["js_sinks"]:
            lines.append("DOM-XSS sinks: " + "; ".join(dom["js_sinks"][:4]))
        if dom["secrets"]:
            lines.append("JS secrets: " + "; ".join(dom["secrets"][:3]))
        if dom["spa_routes"]:
            lines.append("SPA routes: " + ", ".join(dom["spa_routes"][:8]))
        if dom["auth_hints"]:
            lines.append("Auth requests intercepted: " + "; ".join(dom["auth_hints"][:4]))
        if dom["honeypot_flags"]:
            lines.append("HONEYPOT INDICATORS: " + "; ".join(dom["honeypot_flags"]))

    lines.append("")
    return "\n".join(lines)


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--db", default="")
    parser.add_argument("--screenshot-dir", default="/tmp/tar_screenshots")
    parser.add_argument("--timing", action="store_true")
    parser.add_argument("--json", dest="as_json", action="store_true")
    args = parser.parse_args()

    out = {}

    if args.timing:
        out["timing"] = timing_probe(args.url)

    dom = analyze_dom(args.url)
    out["dom"] = dom

    screenshot_path = Path(args.screenshot_dir) / (re.sub(r"[^\w]", "_", args.url)[:60] + ".png")
    Path(args.screenshot_dir).mkdir(parents=True, exist_ok=True)
    out["screenshot"] = str(screenshot_path) if capture_screenshot(args.url, screenshot_path) else None

    if args.as_json:
        print(json.dumps(out, indent=2))
    else:
        print(perceive_web_target(args.url, args.db, Path(args.screenshot_dir)))


if __name__ == "__main__":
    main()
