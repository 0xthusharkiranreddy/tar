#!/usr/bin/env python3
"""
web_response_parser.py — Parse web exploit output into structured findings.

Handles output from: curl, sqlmap, SSTI probes, LFI, command injection,
file upload, XXE, SSRF, and other web attack tools.

Extracts:
  - HTTP status codes and redirect chains
  - Identified vulnerabilities (SQLi, SSTI, XSS, LFI, etc.)
  - Leaked credentials, paths, files
  - Technology stack fingerprints
  - Interesting headers and cookies

Usage:
    echo "$OUTPUT" | python3 web_response_parser.py --db /path/to/world_model.db
    python3 web_response_parser.py output.txt --db /path/to/world_model.db
"""

import json
import re
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).parent.parent


def parse_web_response(text: str) -> dict:
    """Parse web response/exploit output into structured data.

    Returns {
        findings: [{category, severity, description, evidence}],
        creds: [{username, password, source}],
        tech_stack: [{component, version, source}],
        paths: [str],
        headers: {name: value},
    }
    """
    result = {
        "findings": [],
        "creds": [],
        "tech_stack": [],
        "paths": [],
        "headers": {},
    }

    lines = text.split('\n')

    # ── Extract HTTP headers ──
    for line in lines:
        # Header format: "Header-Name: value" or "< Header-Name: value" (curl -v)
        m = re.match(r'(?:<\s*)?([A-Z][\w-]+):\s*(.+)', line.strip())
        if m:
            name, value = m.group(1), m.group(2).strip()
            result["headers"][name] = value

    # ── Technology fingerprinting from headers ──
    _detect_tech_from_headers(result)

    # ── SQLi detection ──
    sqli_patterns = [
        (r'(?:SQL syntax|mysql_fetch|pg_query|ORA-\d+|Microsoft OLE DB|ODBC SQL Server)', "error-based SQLi confirmed"),
        (r'sqlmap identified.*injection point', "sqlmap confirmed SQLi"),
        (r'Type:\s*(UNION|boolean-based|time-based|error-based|stacked)', "sqlmap identified injection type"),
        (r'available databases|current database|current user', "SQLi exploitation successful"),
        (r'(\d+)\s+entries?\s+dumped', "database entries dumped"),
        (r'web server operating system:\s*(.+)', "OS fingerprint via SQLi"),
        (r'back-end DBMS:\s*(.+)', "DBMS identified"),
    ]
    for pat, desc in sqli_patterns:
        m = re.search(pat, text, re.I)
        if m:
            evidence = m.group(0)[:200]
            result["findings"].append({
                "category": "sqli",
                "severity": "critical",
                "description": desc,
                "evidence": evidence,
            })

    # ── SSTI detection ──
    ssti_patterns = [
        (r'49(?![\d])', "SSTI probe {{7*7}} = 49 confirmed"),
        (r'7777777', "SSTI Jinja2 detected ({{7*'7'}} = 7777777)"),
        (r'uid=\d+\(\w+\)\s+gid=\d+', "RCE via SSTI confirmed"),
        (r'root:x:0:0', "SSTI/LFI reading /etc/passwd confirmed"),
    ]
    for pat, desc in ssti_patterns:
        if re.search(pat, text):
            result["findings"].append({
                "category": "ssti",
                "severity": "critical",
                "description": desc,
                "evidence": re.search(pat, text).group(0)[:200],
            })

    # ── LFI/Path Traversal detection ──
    lfi_patterns = [
        (r'root:x:0:0:root:/root:/bin/(?:bash|sh)', "LFI confirmed - /etc/passwd readable"),
        (r'\[boot loader\].*\[operating systems\]', "LFI confirmed - Windows boot.ini readable"),
        (r';\s*for\s+16-bit\s+app\s+support', "LFI confirmed - Windows win.ini readable"),
        (r'DocumentRoot\s+/\S+', "LFI reading Apache config"),
        (r'server\s*\{[^}]*listen\s+\d+', "LFI reading Nginx config"),
        (r'DB_PASSWORD|DB_USERNAME|SECRET_KEY|API_KEY', "LFI leaking environment/config secrets"),
    ]
    for pat, desc in lfi_patterns:
        if re.search(pat, text, re.I):
            result["findings"].append({
                "category": "lfi",
                "severity": "critical",
                "description": desc,
                "evidence": re.search(pat, text, re.I).group(0)[:200],
            })

    # ── Command injection detection ──
    cmd_patterns = [
        (r'uid=(\d+)\((\w+)\)\s+gid=(\d+)\((\w+)\)', "Command injection confirmed (id output)"),
        (r'(nt authority\\system|root)\s*$', "Command injection with elevated privileges"),
        (r'(www-data|apache|nginx|iis apppool)', "Command injection as web user"),
    ]
    for pat, desc in cmd_patterns:
        m = re.search(pat, text, re.I | re.M)
        if m:
            result["findings"].append({
                "category": "command_injection",
                "severity": "critical",
                "description": desc,
                "evidence": m.group(0)[:200],
            })

    # ── XSS detection ���─
    if re.search(r'<script>alert\(|onerror=|javascript:', text, re.I):
        result["findings"].append({
            "category": "xss",
            "severity": "high",
            "description": "Reflected XSS payload in response",
            "evidence": "Script/event handler found in response body",
        })

    # ── XXE detection ──
    if re.search(r'root:x:0:0|ENTITY|SYSTEM\s+"file://', text, re.I):
        result["findings"].append({
            "category": "xxe",
            "severity": "critical",
            "description": "XXE exploitation successful",
            "evidence": "File read or entity expansion detected",
        })

    # ── SSRF detection ──
    ssrf_patterns = [
        (r'169\.254\.169\.254|metadata.*compute', "SSRF to cloud metadata endpoint"),
        (r'localhost|127\.0\.0\.1|0\.0\.0\.0', "SSRF to internal service"),
    ]
    for pat, desc in ssrf_patterns:
        if re.search(pat, text, re.I):
            result["findings"].append({
                "category": "ssrf",
                "severity": "high",
                "description": desc,
                "evidence": re.search(pat, text, re.I).group(0)[:100],
            })

    # ── Credential extraction ──
    _extract_creds(text, result)

    # ── Interesting paths ──
    _extract_paths(text, result)

    # ─�� File upload detection ──
    upload_patterns = [
        (r'File uploaded successfully|upload.*success', "File upload successful"),
        (r'shell\.php|webshell|cmd\.php|c99|r57', "Webshell upload detected"),
    ]
    for pat, desc in upload_patterns:
        if re.search(pat, text, re.I):
            result["findings"].append({
                "category": "file_upload",
                "severity": "critical",
                "description": desc,
                "evidence": re.search(pat, text, re.I).group(0)[:100],
            })

    return result


def _detect_tech_from_headers(result: dict):
    """Detect technology stack from HTTP headers."""
    headers = result["headers"]

    # Server header
    server = headers.get("Server", "")
    if server:
        result["tech_stack"].append({"component": "server", "version": server, "source": "header"})

    # X-Powered-By
    powered = headers.get("X-Powered-By", "")
    if powered:
        result["tech_stack"].append({"component": "runtime", "version": powered, "source": "header"})

    # Framework detection from various headers
    for hdr, patterns in {
        "X-AspNet-Version": [("ASP.NET", r"([\d.]+)")],
        "X-AspNetMvc-Version": [("ASP.NET MVC", r"([\d.]+)")],
        "X-Django-Version": [("Django", r"([\d.]+)")],
        "X-Drupal-Cache": [("Drupal", None)],
        "X-Generator": [("CMS", r"(.+)")],
        "X-Redirect-By": [("WordPress", r"WordPress")],
    }.items():
        val = headers.get(hdr, "")
        if val:
            for name, pat in patterns:
                if pat:
                    m = re.search(pat, val)
                    ver = m.group(1) if m else val
                else:
                    ver = val
                result["tech_stack"].append({"component": name, "version": ver, "source": "header"})

    # Cookie-based detection
    cookies = headers.get("Set-Cookie", "")
    if "PHPSESSID" in cookies:
        result["tech_stack"].append({"component": "language", "version": "PHP", "source": "cookie"})
    if "JSESSIONID" in cookies:
        result["tech_stack"].append({"component": "language", "version": "Java", "source": "cookie"})
    if "ASP.NET_SessionId" in cookies:
        result["tech_stack"].append({"component": "language", "version": "ASP.NET", "source": "cookie"})
    if "connect.sid" in cookies:
        result["tech_stack"].append({"component": "framework", "version": "Express.js", "source": "cookie"})
    if "csrftoken" in cookies and "django" not in str(result["tech_stack"]).lower():
        result["tech_stack"].append({"component": "framework", "version": "Django (probable)", "source": "cookie"})


def _extract_creds(text: str, result: dict):
    """Extract credentials from output."""
    # user:password patterns
    for m in re.finditer(r'(?:password|passwd|pwd|credentials?)\s*[:=]\s*["\']?(\S+)["\']?', text, re.I):
        val = m.group(1).strip("\"'")
        if len(val) > 2 and len(val) < 100 and val not in ('null', 'none', 'false', 'true', '*'):
            result["creds"].append({"password": val, "source": "web_response"})

    for m in re.finditer(r'(?:username|user|login)\s*[:=]\s*["\']?(\S+)["\']?', text, re.I):
        val = m.group(1).strip("\"'")
        if len(val) > 1 and len(val) < 50 and val not in ('null', 'none', 'false', 'true'):
            result["creds"].append({"username": val, "source": "web_response"})

    # MySQL/MSSQL connection strings
    for m in re.finditer(r'(?:mysql|mssql|postgres|jdbc)://(\w+):([^@]+)@', text, re.I):
        result["creds"].append({
            "username": m.group(1),
            "password": m.group(2),
            "source": "connection_string",
        })

    # .env file patterns
    for m in re.finditer(r'(?:DB_PASSWORD|MYSQL_PASSWORD|SECRET_KEY|API_KEY|JWT_SECRET)\s*=\s*["\']?(\S+)["\']?', text, re.I):
        val = m.group(1).strip("\"'")
        if val and val not in ('changeme', 'password', 'secret'):
            result["creds"].append({"password": val, "source": "env_file", "key": m.group(0).split('=')[0].strip()})

    # SSH keys
    if "BEGIN RSA PRIVATE KEY" in text or "BEGIN OPENSSH PRIVATE KEY" in text:
        result["findings"].append({
            "category": "credential",
            "severity": "critical",
            "description": "SSH private key found",
            "evidence": "RSA/OpenSSH private key in response",
        })

    # Hash patterns
    for m in re.finditer(r'\b([a-f0-9]{32})\b', text):
        # Could be MD5 hash
        context = text[max(0, m.start()-30):m.end()+30]
        if re.search(r'hash|password|md5|ntlm', context, re.I):
            result["creds"].append({"hash": m.group(1), "hash_type": "md5/ntlm", "source": "web_response"})

    for m in re.finditer(r'\$2[aby]\$\d+\$[\w./]+', text):
        result["creds"].append({"hash": m.group(0), "hash_type": "bcrypt", "source": "web_response"})

    for m in re.finditer(r'\$6\$[\w./]+\$[\w./]+', text):
        result["creds"].append({"hash": m.group(0), "hash_type": "sha512crypt", "source": "web_response"})


def _extract_paths(text: str, result: dict):
    """Extract interesting file paths and URLs from output."""
    # Absolute paths
    for m in re.finditer(r'(/(?:etc|var|home|opt|usr|tmp|root|proc|sys|Windows|Users|inetpub)/[\w./\-]+)', text):
        path = m.group(1)
        if len(path) > 5 and path not in result["paths"]:
            result["paths"].append(path)

    # URLs
    for m in re.finditer(r'(https?://[\w./:@\-?=&%#+]+)', text):
        url = m.group(1)
        if url not in result["paths"]:
            result["paths"].append(url)


def update_world_model(db_path: str, parsed: dict):
    """Write parsed web results into world_model."""
    sys.path.insert(0, str(SCRIPTS_DIR))
    from world_model import WorldModel

    wm = WorldModel(db_path)

    # Add findings
    for f in parsed["findings"]:
        wm.add_finding(
            category=f["category"],
            severity=f["severity"],
            description=f["description"],
            evidence_path=f.get("evidence", "")[:500],
        )

    # Add credentials
    for c in parsed["creds"]:
        if c.get("username") or c.get("password") or c.get("hash"):
            wm.add_cred(
                username=c.get("username", ""),
                password=c.get("password", ""),
                hash_value=c.get("hash", ""),
                hash_type=c.get("hash_type", ""),
                source=c.get("source", "web_response"),
            )

    # Add tech stack as findings
    for t in parsed["tech_stack"]:
        wm.add_finding(
            category="tech_stack",
            severity="info",
            description=f"{t['component']}: {t['version']}",
            evidence_path=f"source: {t['source']}",
        )

    wm.close()

    # Summary
    parts = []
    if parsed["findings"]:
        parts.append(f"{len(parsed['findings'])} findings")
    if parsed["creds"]:
        parts.append(f"{len(parsed['creds'])} creds")
    if parsed["tech_stack"]:
        parts.append(f"{len(parsed['tech_stack'])} tech fingerprints")
    if parsed["paths"]:
        parts.append(f"{len(parsed['paths'])} paths")

    return ", ".join(parts) if parts else "no findings"


def main():
    import argparse
    parser = argparse.ArgumentParser(description="TAR Web Response Parser")
    parser.add_argument("input", nargs="?", default="-", help="Input file (- for stdin)")
    parser.add_argument("--db", help="Path to world_model.db")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    if args.input == "-":
        text = sys.stdin.read()
    else:
        text = Path(args.input).read_text()

    parsed = parse_web_response(text)

    if args.db:
        summary = update_world_model(args.db, parsed)
        print(summary)
    elif args.json:
        print(json.dumps(parsed, indent=2))
    else:
        if parsed["findings"]:
            print("Findings:")
            for f in parsed["findings"]:
                print(f"  [{f['severity']}] {f['category']}: {f['description']}")
        if parsed["creds"]:
            print("Credentials:")
            for c in parsed["creds"]:
                print(f"  {c}")
        if parsed["tech_stack"]:
            print("Tech Stack:")
            for t in parsed["tech_stack"]:
                print(f"  {t['component']}: {t['version']}")
        if parsed["paths"]:
            print(f"Paths: {len(parsed['paths'])} found")
        if not any([parsed["findings"], parsed["creds"], parsed["tech_stack"]]):
            print("No findings extracted.")


if __name__ == "__main__":
    main()
