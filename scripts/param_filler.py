#!/usr/bin/env python3
"""
param_filler.py — Resolves YAML action placeholders from world_model state.

Fills {target_ip}, {username}, {password}, {domain}, {port}, etc. from
the engagement's world_model.db, producing runnable commands.

Usage:
    python3 param_filler.py <world_model.db> <action_name>
    python3 param_filler.py <world_model.db> <action_name> --json
"""

import json
import re
import sys
from pathlib import Path

import yaml

ACTIONS_DIR = Path("/home/kali/knowledge/actions")
SCRIPTS_DIR = Path("/home/kali/.claude/scripts")


def load_action(action_name: str) -> dict | None:
    """Find and load an action YAML by name."""
    for yml_file in ACTIONS_DIR.rglob("*.yml"):
        try:
            with open(yml_file) as f:
                action = yaml.safe_load(f)
            if action and action.get("name") == action_name:
                return action
        except Exception:
            continue
    return None


def get_fill_context(db_path: str) -> dict:
    """
    Build a parameter resolution context from world_model state.

    Returns a dict with all available parameter values:
      target_ip, hostname, domain, os,
      username, password, hash, hash_type,
      port, product, version,
      interface, lhost, attacker_ip,
      base_dn, dc_ip, ca, template,
      lport, share, writable_share,
      ...
    """
    sys.path.insert(0, str(SCRIPTS_DIR))
    from world_model import WorldModel

    wm = WorldModel(db_path)
    ctx = {}

    # Engagement basics
    eng = wm.conn.execute(
        "SELECT * FROM engagement ORDER BY id DESC LIMIT 1"
    ).fetchone()
    if eng:
        ctx["target_ip"] = eng["target_ip"] or ""
        ctx["tier"] = eng["tier"] or "balanced"

    # Primary host
    hosts = wm.get_hosts()
    if hosts:
        h = hosts[0]
        ctx.setdefault("target_ip", h["ip"])
        ctx["hostname"] = h.get("hostname") or ""
        ctx["os"] = h.get("os") or ""
        ctx["domain"] = h.get("domain") or ""
        # Derive base_dn from domain
        if ctx["domain"]:
            parts = ctx["domain"].split(".")
            ctx["base_dn"] = ",".join(f"DC={p}" for p in parts)
            ctx["dc_ip"] = ctx["target_ip"]
            ctx["dc_name"] = ctx["hostname"] or ctx["domain"].split(".")[0]

    # Best credential (prefer verified, then password over hash)
    creds = wm.get_creds()
    if creds:
        # Sort: verified first, then password > hash
        creds.sort(key=lambda c: (
            -c.get("verified", 0),
            -1 if c.get("password") else 0,
            -1 if c.get("hash") else 0,
        ))
        best = creds[0]
        ctx["username"] = best.get("username") or ""
        ctx["password"] = best.get("password") or ""
        ctx["hash"] = best.get("hash") or ""
        ctx["hash_type"] = best.get("hash_type") or ""
        if best.get("domain"):
            ctx.setdefault("domain", best["domain"])

        # Also provide all unique usernames for spray
        ctx["userlist"] = list({c["username"] for c in creds if c.get("username")})

    # Services — find specific ports
    services = wm.get_services()
    service_by_port = {}
    for svc in services:
        service_by_port[svc["port"]] = svc
        # Convenience: first web port
        if svc["port"] in (80, 443, 8080, 8443) and "target_url" not in ctx:
            proto = "https" if svc["port"] in (443, 8443) else "http"
            host = ctx.get("hostname") or ctx.get("target_ip", svc["host_ip"])
            port_suffix = "" if svc["port"] in (80, 443) else f":{svc['port']}"
            ctx["target_url"] = f"{proto}://{host}{port_suffix}"
            ctx["web_port"] = svc["port"]

    ctx["services"] = service_by_port
    ctx["open_ports"] = sorted(service_by_port.keys())

    # Derived convenience params
    # ports: CSV of open ports (for nmap_scripts, nmap_targeted)
    if ctx["open_ports"]:
        ctx["ports"] = ",".join(str(p) for p in ctx["open_ports"])

    # url: alias for target_url (curl_request uses {url})
    if "target_url" in ctx:
        ctx.setdefault("url", ctx["target_url"])

    # port: first interesting non-web port, or web port (for netcat)
    non_web = [p for p in ctx["open_ports"] if p not in (80, 443, 8080, 8443)]
    if non_web:
        ctx.setdefault("port", str(non_web[0]))
    elif ctx["open_ports"]:
        ctx.setdefault("port", str(ctx["open_ports"][0]))

    # protocol: guess from services (for hydra)
    protocol_map = {22: "ssh", 21: "ftp", 80: "http-get", 443: "https-get",
                    3306: "mysql", 5432: "postgres", 3389: "rdp", 445: "smb",
                    25: "smtp", 110: "pop3", 143: "imap"}
    for p in ctx["open_ports"]:
        if p in protocol_map:
            ctx.setdefault("protocol", protocol_map[p])
            break

    # hash_file: default location for captured hashes
    ctx.setdefault("hash_file", "/tmp/hashes.txt")

    # Shares
    shares = wm.get_shares()
    if shares:
        # Find writable share
        writable = [s for s in shares if s.get("access_level") in ("write", "admin")]
        readable = [s for s in shares if s.get("access_level") in ("read", "write", "admin")]
        if writable:
            ctx["writable_share"] = writable[0]["name"]
            ctx["share_path"] = f"//{ctx.get('target_ip','')}/{writable[0]['name']}"
        if readable:
            ctx["share"] = readable[0]["name"]

    # Users
    users = wm.get_users()
    if users:
        spn_users = [u for u in users if u.get("spn")]
        admin_users = [u for u in users if u.get("is_admin")]
        if spn_users:
            ctx["spn_user"] = spn_users[0]["username"]
        if admin_users:
            ctx["admin_user"] = admin_users[0]["username"]

    # Attacker context (from network interface)
    ctx["interface"] = "tun0"
    ctx["lport"] = "9001"
    try:
        import subprocess
        result = subprocess.run(
            ["ip", "-4", "addr", "show", "tun0"],
            capture_output=True, text=True, timeout=2
        )
        for line in result.stdout.split("\n"):
            if "inet " in line:
                ctx["attacker_ip"] = line.strip().split()[1].split("/")[0]
                ctx["lhost"] = ctx["attacker_ip"]
                break
    except Exception:
        pass

    # Findings-derived context
    findings = wm.get_findings()
    for f in findings:
        desc = f.get("description", "").lower()
        # Extract CA name from ADCS finding
        if "certificate" in desc and "ca" not in ctx:
            m = re.search(r"ca[:\s]+([^\s,]+)", desc, re.I)
            if m:
                ctx["ca"] = m.group(1)
        # Extract template name
        if "template" in desc and "template" not in ctx:
            m = re.search(r"template[:\s]+([^\s,]+)", desc, re.I)
            if m:
                ctx["template"] = m.group(1)

    wm.close()
    return ctx


def fill_command(command_template: str, ctx: dict) -> tuple[str, list[str]]:
    """
    Fill a command template with context values.

    Returns (filled_command, list_of_unfilled_placeholders).
    """
    # Find all {placeholder} patterns
    placeholders = re.findall(r"\{(\w+)\}", command_template)
    unfilled = []
    result = command_template

    for ph in placeholders:
        if ph in ctx and ctx[ph]:
            value = str(ctx[ph])
            result = result.replace(f"{{{ph}}}", value)
        else:
            unfilled.append(ph)

    return result, unfilled


def _apply_yaml_defaults(action: dict, ctx: dict) -> dict:
    """Merge YAML parameter defaults into context (ctx takes priority)."""
    params = action.get("parameters", {})
    if not isinstance(params, dict):
        return ctx
    merged = dict(ctx)
    for key, value in params.items():
        if key not in merged or not merged[key]:
            # Only use literal defaults, not "from_engagement.*" references
            if isinstance(value, str) and not value.startswith("from_"):
                merged[key] = value
    return merged


def fill_action(db_path: str, action_name: str) -> dict:
    """
    Fill an action's command template from world_model state.

    Returns {
        name, command, unfilled, ready (bool),
        description, mechanism, category
    }
    """
    action = load_action(action_name)
    if not action:
        return {"error": f"Action '{action_name}' not found"}

    ctx = get_fill_context(db_path)
    ctx = _apply_yaml_defaults(action, ctx)
    template = action.get("command_template", "")
    filled, unfilled = fill_command(template, ctx)

    return {
        "name": action_name,
        "command": filled,
        "unfilled": unfilled,
        "ready": len(unfilled) == 0,
        "description": action.get("description", ""),
        "mechanism": action.get("mechanism", ""),
        "category": action.get("category", ""),
        "parser": action.get("parser"),
        "falsifier": action.get("falsifier"),
    }


def fill_multiple(db_path: str, action_names: list[str]) -> list[dict]:
    """Fill multiple actions at once (shares context lookup)."""
    ctx = get_fill_context(db_path)
    results = []
    for name in action_names:
        action = load_action(name)
        if not action:
            results.append({"name": name, "error": "not found"})
            continue
        template = action.get("command_template", "")
        action_ctx = _apply_yaml_defaults(action, ctx)
        filled, unfilled = fill_command(template, action_ctx)
        results.append({
            "name": name,
            "command": filled,
            "unfilled": unfilled,
            "ready": len(unfilled) == 0,
            "description": action.get("description", ""),
            "mechanism": action.get("mechanism", "")[:120],
            "category": action.get("category", ""),
        })
    return results


def main():
    import argparse
    parser = argparse.ArgumentParser(description="TAR Parameter Filler")
    parser.add_argument("db_path", help="Path to world_model.db")
    parser.add_argument("action", nargs="?", help="Action name to fill")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--context", action="store_true", help="Show available context")
    parser.add_argument("--batch", nargs="+", help="Fill multiple actions")
    args = parser.parse_args()

    if args.context:
        ctx = get_fill_context(args.db_path)
        # Redact sensitive values for display
        display = {}
        for k, v in ctx.items():
            if k in ("password", "hash") and v:
                display[k] = v[:4] + "..." if len(str(v)) > 4 else "***"
            elif k == "services":
                display[k] = {str(port): svc.get("product", "?") for port, svc in v.items()}
            else:
                display[k] = v
        print(json.dumps(display, indent=2, default=str))
        return

    if args.batch:
        results = fill_multiple(args.db_path, args.batch)
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            for r in results:
                ready = "READY" if r.get("ready") else f"NEED: {r.get('unfilled', [])}"
                print(f"  [{ready}] {r['name']}: {r.get('command', r.get('error', '?'))[:100]}")
        return

    if not args.action:
        parser.print_help()
        return

    result = fill_action(args.db_path, args.action)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if "error" in result:
            print(f"Error: {result['error']}")
        else:
            ready = "READY" if result["ready"] else "INCOMPLETE"
            print(f"[{ready}] {result['name']} ({result['category']})")
            print(f"Command: {result['command']}")
            if result["unfilled"]:
                print(f"Missing: {', '.join(result['unfilled'])}")
            print(f"Mechanism: {result['mechanism'][:150]}")


if __name__ == "__main__":
    main()
