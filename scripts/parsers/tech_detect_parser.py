#!/usr/bin/env python3
"""
tech_detect_parser.py — Detect web technology stack from HTTP responses.

Analyzes HTTP headers, response body, and error pages to identify:
  - Web server (Apache, Nginx, IIS, etc.)
  - Language/Runtime (PHP, Python, Java, .NET, Node.js, Ruby)
  - Framework (Flask, Django, Express, Laravel, Spring, ASP.NET MVC)
  - Template engine (Jinja2, Twig, Freemarker, ERB, Handlebars)
  - CMS (WordPress, Drupal, Joomla)
  - WAF (Cloudflare, ModSecurity, etc.)
  - Known vulnerable versions

Updates world_model with tech_stack findings and suggests relevant attacks.

Usage:
    curl -sI http://target | python3 tech_detect_parser.py --db /path/to/world_model.db
    curl -s http://target | python3 tech_detect_parser.py --db /path/to/world_model.db --full-body
"""

import json
import re
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).parent.parent

# ═══════════════════════════════════════════════════════════════
# Detection signatures
# ═══════════════════════════════════════════════════════════════

SERVER_SIGNATURES = {
    r'Apache/([\d.]+)': ("Apache", "server"),
    r'nginx/([\d.]+)': ("Nginx", "server"),
    r'Microsoft-IIS/([\d.]+)': ("IIS", "server"),
    r'openresty/([\d.]+)': ("OpenResty", "server"),
    r'LiteSpeed': ("LiteSpeed", "server"),
    r'Werkzeug/([\d.]+)': ("Werkzeug", "server"),
    r'gunicorn': ("Gunicorn", "server"),
    r'Kestrel': ("Kestrel/.NET", "server"),
    r'Jetty\(([\d.]+)\)': ("Jetty", "server"),
    r'Tomcat/([\d.]+)': ("Tomcat", "server"),
    r'WildFly/([\d.]+)': ("WildFly", "server"),
}

HEADER_SIGNATURES = {
    # X-Powered-By patterns
    r'PHP/([\d.]+)': ("PHP", "language"),
    r'ASP\.NET': ("ASP.NET", "language"),
    r'Express': ("Express.js", "framework"),
    r'Phusion Passenger': ("Ruby/Passenger", "runtime"),
    r'JSF': ("JavaServer Faces", "framework"),
    # Framework-specific headers
    r'X-Django': ("Django", "framework"),
    r'X-Drupal': ("Drupal", "cms"),
    r'X-Generator:\s*WordPress': ("WordPress", "cms"),
    r'X-Generator:\s*Joomla': ("Joomla", "cms"),
    r'X-Redirect-By:\s*WordPress': ("WordPress", "cms"),
    r'X-Craft-Solo': ("Craft CMS", "cms"),
    r'X-Shopify': ("Shopify", "cms"),
}

COOKIE_SIGNATURES = {
    "PHPSESSID": ("PHP", "language"),
    "JSESSIONID": ("Java", "language"),
    "ASP.NET_SessionId": ("ASP.NET", "language"),
    "connect.sid": ("Express.js/Node.js", "framework"),
    "csrftoken": ("Django (probable)", "framework"),
    "laravel_session": ("Laravel", "framework"),
    "rack.session": ("Ruby/Rack", "framework"),
    "ci_session": ("CodeIgniter", "framework"),
    "cakephp": ("CakePHP", "framework"),
    "_rails": ("Ruby on Rails", "framework"),
    "XSRF-TOKEN": ("Angular/Laravel", "framework"),
    "blazor": ("Blazor/.NET", "framework"),
}

BODY_SIGNATURES = {
    # CMS detection
    r'wp-content|wp-includes|wp-json': ("WordPress", "cms"),
    r'Drupal\.settings|sites/default/files': ("Drupal", "cms"),
    r'/media/jui/|com_content': ("Joomla", "cms"),
    r'content="WordPress': ("WordPress", "cms"),
    r'generator.*?Drupal': ("Drupal", "cms"),
    # Framework detection from HTML/JS
    r'__VIEWSTATE|__EVENTVALIDATION': ("ASP.NET WebForms", "framework"),
    r'ng-app=|ng-controller=|angular\.min\.js': ("Angular", "frontend"),
    r'react\.production\.min|reactDOM|__NEXT_DATA__': ("React/Next.js", "frontend"),
    r'vue\.min\.js|v-bind:|v-for=': ("Vue.js", "frontend"),
    r'data-turbo|turbolinks': ("Ruby on Rails/Turbo", "framework"),
    # Language detection from error pages
    r'Traceback \(most recent call last\)': ("Python", "language"),
    r'at [\w.]+\.java:\d+': ("Java", "language"),
    r'Fatal error.*?in /\S+\.php': ("PHP", "language"),
    r'SyntaxError|TypeError.*?at [\w./]+\.js': ("Node.js", "language"),
    r'ActionController::RoutingError|ActiveRecord': ("Ruby on Rails", "framework"),
    r'System\.Web\.HttpException|System\.NullReferenceException': ("ASP.NET", "framework"),
    r'org\.springframework': ("Spring", "framework"),
    r'Laravel|Illuminate\\': ("Laravel", "framework"),
    r'Django|ImproperlyConfigured': ("Django", "framework"),
    r'Werkzeug Debugger|WERKZEUG_DEBUG_PIN': ("Flask/Werkzeug (DEBUG)", "framework"),
    r'Bottle.*?Error|bottle\.py': ("Bottle (Python)", "framework"),
    r'Express.*?Error|Cannot (GET|POST)': ("Express.js", "framework"),
    # Template engine detection
    r'Jinja2|jinja2\.exceptions': ("Jinja2", "template_engine"),
    r'Twig_Error|twig\.': ("Twig", "template_engine"),
    r'freemarker\.template': ("Freemarker", "template_engine"),
    r'Thymeleaf|th:': ("Thymeleaf", "template_engine"),
    r'Mustache|Handlebars': ("Handlebars/Mustache", "template_engine"),
    r'Pebble|PebbleException': ("Pebble", "template_engine"),
    r'Smarty|{%\s*literal\s*%}': ("Smarty", "template_engine"),
    r'ERB|ActionView::Template::Error': ("ERB (Ruby)", "template_engine"),
    r'Mako|mako\.exceptions': ("Mako", "template_engine"),
    r'Velocity|VelocityException': ("Velocity", "template_engine"),
}

WAF_SIGNATURES = {
    r'cloudflare|cf-ray': ("Cloudflare", "waf"),
    r'mod_security|NOYB': ("ModSecurity", "waf"),
    r'X-Sucuri-ID': ("Sucuri", "waf"),
    r'akamai|X-Akamai': ("Akamai", "waf"),
    r'Incapsula|X-CDN: Imperva': ("Imperva", "waf"),
    r'X-Shield-Request-ID': ("Varnish/Shield", "waf"),
    r'AwsAlb': ("AWS ALB/WAF", "waf"),
}

# Known vulnerable versions
VULN_VERSIONS = {
    ("Apache", "2.4.49"): "CVE-2021-41773: Path traversal + RCE",
    ("Apache", "2.4.50"): "CVE-2021-42013: Path traversal bypass of 2.4.49 fix",
    ("IIS", "6.0"): "CVE-2017-7269: WebDAV buffer overflow RCE",
    ("Tomcat", "9.0.30"): "CVE-2020-1938: Ghostcat AJP file read",
    ("Tomcat", "8.5.19"): "CVE-2017-12617: JSP upload RCE via PUT",
    ("Werkzeug", "0."): "Werkzeug debugger PIN bypass possible",
    ("Werkzeug", "1."): "Werkzeug debugger PIN bypass possible",
    ("Drupal", "7."): "Drupalgeddon (CVE-2018-7600) if unpatched",
    ("Drupal", "8."): "Drupalgeddon2 (CVE-2018-7602) if unpatched",
    ("PHP", "8.1.0"): "CVE-2024-2961: iconv buffer overflow",
}


def detect_tech(text: str, headers_only: bool = False) -> dict:
    """Detect technology stack from HTTP response text.

    Args:
        text: Full HTTP response (headers + body) or headers only
        headers_only: If True, skip body analysis

    Returns {
        detections: [{component, version, type, confidence, source}],
        vulns: [{component, version, cve_desc}],
        suggested_attacks: [str],
    }
    """
    result = {
        "detections": [],
        "vulns": [],
        "suggested_attacks": [],
    }

    seen = set()  # Prevent duplicates

    # Split headers from body
    header_section = text
    body_section = ""
    if "\r\n\r\n" in text:
        header_section, body_section = text.split("\r\n\r\n", 1)
    elif "\n\n" in text:
        header_section, body_section = text.split("\n\n", 1)

    # ── Server header ──
    for pat, (name, dtype) in SERVER_SIGNATURES.items():
        m = re.search(pat, header_section, re.I)
        if m:
            version = m.group(1) if m.lastindex else ""
            key = (name, dtype)
            if key not in seen:
                seen.add(key)
                result["detections"].append({
                    "component": name, "version": version,
                    "type": dtype, "confidence": "high", "source": "server_header",
                })

    # ── Other headers ──
    for pat, (name, dtype) in HEADER_SIGNATURES.items():
        m = re.search(pat, header_section, re.I)
        if m:
            version = m.group(1) if m.lastindex else ""
            key = (name, dtype)
            if key not in seen:
                seen.add(key)
                result["detections"].append({
                    "component": name, "version": version,
                    "type": dtype, "confidence": "high", "source": "header",
                })

    # ── Cookie signatures ──
    for cookie_name, (name, dtype) in COOKIE_SIGNATURES.items():
        if cookie_name.lower() in header_section.lower():
            key = (name, dtype)
            if key not in seen:
                seen.add(key)
                result["detections"].append({
                    "component": name, "version": "",
                    "type": dtype, "confidence": "medium", "source": "cookie",
                })

    # ── WAF detection ──
    for pat, (name, dtype) in WAF_SIGNATURES.items():
        if re.search(pat, text, re.I):
            key = (name, dtype)
            if key not in seen:
                seen.add(key)
                result["detections"].append({
                    "component": name, "version": "",
                    "type": dtype, "confidence": "high", "source": "header/response",
                })

    # ── Body analysis ──
    if not headers_only and body_section:
        for pat, (name, dtype) in BODY_SIGNATURES.items():
            if re.search(pat, body_section, re.I):
                key = (name, dtype)
                if key not in seen:
                    seen.add(key)
                    result["detections"].append({
                        "component": name, "version": "",
                        "type": dtype, "confidence": "medium", "source": "body",
                    })

    # ── Version vulnerability matching ──
    for det in result["detections"]:
        comp = det["component"]
        ver = det["version"]
        if not ver:
            continue
        for (vuln_comp, vuln_ver), desc in VULN_VERSIONS.items():
            if comp == vuln_comp and ver.startswith(vuln_ver):
                result["vulns"].append({
                    "component": comp,
                    "version": ver,
                    "cve_desc": desc,
                })

    # ── Suggest attacks based on detections ──
    _suggest_attacks(result)

    return result


def _suggest_attacks(result: dict):
    """Generate attack suggestions based on detected tech."""
    components = {d["component"].lower() for d in result["detections"]}
    types = {d["type"] for d in result["detections"]}

    suggestions = []

    # CMS-specific attacks
    if "wordpress" in components:
        suggestions.extend(["wpscan --enumerate vp,vt,u", "wp-admin brute force", "xmlrpc pingback SSRF"])
    if "drupal" in components:
        suggestions.extend(["droopescan scan drupal", "drupalgeddon2 exploit check"])
    if "joomla" in components:
        suggestions.append("joomscan enumeration")

    # Framework-specific attacks
    if "flask/werkzeug (debug)" in components:
        suggestions.append("Werkzeug debugger PIN bypass (calculate PIN from /proc/self/...)")
    if "django" in components or "django (probable)" in components:
        suggestions.extend(["Django debug page info leak", "Django admin at /admin/"])
    if "laravel" in components:
        suggestions.extend(["Laravel .env file disclosure", "Laravel debug mode RCE (CVE-2021-3129)"])
    if "spring" in components:
        suggestions.extend(["Spring actuator endpoints (/actuator)", "Spring4Shell check"])
    if "express.js" in components or "express.js/node.js" in components:
        suggestions.append("Node.js prototype pollution / SSRF via internal services")
    if "tomcat" in components:
        suggestions.extend(["Tomcat manager brute force (/manager/html)", "Ghostcat AJP (port 8009)"])

    # Template engine → SSTI
    if "template_engine" in types:
        engines = [d["component"] for d in result["detections"] if d["type"] == "template_engine"]
        for eng in engines:
            suggestions.append(f"SSTI via {eng} — use engine-specific payloads")

    # Language-specific
    if "php" in components:
        suggestions.extend(["PHP type juggling", "PHP deserialization", "PHP filter chains for LFI"])
    if "java" in components:
        suggestions.extend(["Java deserialization (ysoserial)", "Log4Shell check", "JNDI injection"])
    if "asp.net" in components or "asp.net webforms" in components:
        suggestions.extend([".NET deserialization (ysoserial.net)", "ViewState deserialization"])

    # WAF detected — note bypass needed
    if "waf" in types:
        wafs = [d["component"] for d in result["detections"] if d["type"] == "waf"]
        suggestions.append(f"WAF detected ({', '.join(wafs)}) — encoding/bypass techniques needed")

    # Known vulns
    for v in result["vulns"]:
        suggestions.append(f"EXPLOIT: {v['cve_desc']}")

    result["suggested_attacks"] = suggestions


def update_world_model(db_path: str, detected: dict):
    """Write tech stack detections into world_model as findings."""
    sys.path.insert(0, str(SCRIPTS_DIR))
    from world_model import WorldModel

    wm = WorldModel(db_path)

    for d in detected["detections"]:
        wm.add_finding(
            category="tech_stack",
            severity="info",
            description=f"{d['type']}: {d['component']} {d['version']}".strip(),
            evidence_path=f"source: {d['source']}, confidence: {d['confidence']}",
        )

    for v in detected["vulns"]:
        wm.add_finding(
            category="vulnerability",
            severity="critical",
            description=f"{v['component']} {v['version']}: {v['cve_desc']}",
            evidence_path="version_match",
        )

    wm.close()

    parts = []
    if detected["detections"]:
        techs = [f"{d['component']}" for d in detected["detections"][:5]]
        parts.append(f"Tech: {', '.join(techs)}")
    if detected["vulns"]:
        parts.append(f"{len(detected['vulns'])} known vulns")
    if detected["suggested_attacks"]:
        parts.append(f"{len(detected['suggested_attacks'])} attack suggestions")

    return " | ".join(parts) if parts else "no detections"


def main():
    import argparse
    parser = argparse.ArgumentParser(description="TAR Web Tech Stack Detector")
    parser.add_argument("input", nargs="?", default="-", help="Input file (- for stdin)")
    parser.add_argument("--db", help="Path to world_model.db")
    parser.add_argument("--full-body", action="store_true", help="Analyze full response body")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    if args.input == "-":
        text = sys.stdin.read()
    else:
        text = Path(args.input).read_text()

    detected = detect_tech(text, headers_only=not args.full_body)

    if args.db:
        summary = update_world_model(args.db, detected)
        print(summary)
    elif args.json:
        print(json.dumps(detected, indent=2))
    else:
        if detected["detections"]:
            print("Technology Stack:")
            for d in detected["detections"]:
                ver = f" {d['version']}" if d['version'] else ""
                print(f"  [{d['confidence']}] {d['type']}: {d['component']}{ver} (via {d['source']})")
        if detected["vulns"]:
            print("\nKnown Vulnerabilities:")
            for v in detected["vulns"]:
                print(f"  [!] {v['component']} {v['version']}: {v['cve_desc']}")
        if detected["suggested_attacks"]:
            print("\nSuggested Attacks:")
            for s in detected["suggested_attacks"]:
                print(f"  → {s}")
        if not detected["detections"]:
            print("No technology detected.")


if __name__ == "__main__":
    main()
