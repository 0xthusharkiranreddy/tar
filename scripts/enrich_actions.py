#!/usr/bin/env python3
"""
enrich_actions.py — Batch-improve action YAMLs using HackTricks/PAT knowledge.

Enriches:
  1. Mechanism field: Replace short one-liners with HackTricks excerpts
  2. Falsifier patterns: Add technique-specific failure patterns from curated knowledge
  3. Parser assignments: Map actions to existing parsers based on tool output format
  4. HackTricks reference: Add hacktricks_ref field pointing to relevant HackTricks page

Usage:
    python3 enrich_actions.py --dry-run          # Show what would change
    python3 enrich_actions.py --apply            # Apply changes
    python3 enrich_actions.py --category web     # Only enrich web actions
    python3 enrich_actions.py --action kerberoast  # Only enrich one action
"""

import os
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent))

from knowledge_index import get_index, TECHNIQUE_ALIASES
from technique_advisor import FAILURE_PATTERNS, PREREQUISITES

ACTIONS_DIR = Path("/home/kali/knowledge/actions")

# ── Parser assignment rules ──
# Maps action name patterns → parser name based on what tool they use
PARSER_RULES = {
    # SMB tools → crackmapexec_parser or smbclient_parser
    "crackmapexec": "crackmapexec_parser",
    "nxc_smb": "crackmapexec_parser",
    "nxc_winrm": "crackmapexec_parser",
    "nxc_ldap": "crackmapexec_parser",
    "nxc_mssql": "crackmapexec_parser",
    "smb_": "smbclient_parser",
    "smbclient": "smbclient_parser",
    "enum4linux": "smbclient_parser",
    # Nmap tools → nmap_parser
    "nmap_": "nmap_parser",
    # Web fuzzers → gobuster_parser
    "feroxbuster": "gobuster_parser",
    "gobuster": "gobuster_parser",
    "ffuf": "gobuster_parser",
    "wfuzz": "gobuster_parser",
    "dirsearch": "gobuster_parser",
    # Impacket tools → impacket_parser
    "kerberoast": "impacket_parser",
    "asreproast": "impacket_parser",
    "secretsdump": "impacket_parser",
    "dcsync": "impacket_parser",
    "psexec": "impacket_parser",
    "wmiexec": "impacket_parser",
    "impacket_": "impacket_parser",
    "GetUserSPNs": "impacket_parser",
    "GetNPUsers": "impacket_parser",
    # Hash cracking → hashcat_parser
    "hashcat": "hashcat_parser",
    "john": "hashcat_parser",
    # Bloodhound → bloodhound_parser
    "bloodhound": "bloodhound_parser",
    # Linux privesc → linpeas_parser
    "linpeas": "linpeas_parser",
    "suid": "linpeas_parser",
    "capabilities": "linpeas_parser",
    # Windows privesc → winpeas_parser
    "winpeas": "winpeas_parser",
}

# ── Curated falsifier improvements ──
# Better falsifier patterns for specific actions (from HackTricks failure knowledge)
IMPROVED_FALSIFIERS = {
    "kerberoast": {"pattern": "No entries found|KDC_ERR_S_PRINCIPAL_UNKNOWN|KRB_AP_ERR_SKEW|error|LOGON_FAILURE", "timeout": 45},
    "asreproast": {"pattern": "No entries found|KRB_AP_ERR_SKEW|error", "timeout": 45},
    "secretsdump": {"pattern": "ACCESS_DENIED|LOGON_FAILURE|STATUS_NOT_SUPPORTED|error", "timeout": 60},
    "psexec": {"pattern": "ACCESS_DENIED|LOGON_FAILURE|STATUS_SHARING_VIOLATION|refused", "timeout": 30},
    "wmiexec": {"pattern": "ACCESS_DENIED|LOGON_FAILURE|error|refused", "timeout": 30},
    "evil_winrm": {"pattern": "LOGON_FAILURE|refused|WinRM.*disabled|error", "timeout": 15},
    "ntlmrelayx": {"pattern": "signing is required|error|refused", "timeout": 120},
    "responder": {"pattern": "error|Address already in use", "timeout": 300},
    "certipy": {"pattern": "No CAs found|Access denied|CERTSRV_E_TEMPLATE_DENIED|error", "timeout": 60},
    "bloodhound": {"pattern": "ACCESS_DENIED|Connection error|error", "timeout": 120},
    "sqli_union": {"pattern": "no UNION columns|403|500|WAF|blocked", "timeout": 30},
    "sqli_blind": {"pattern": "timeout|no difference|WAF|blocked", "timeout": 60},
    "sqlmap": {"pattern": "all tested parameters do not appear|critical|WAF", "timeout": 300},
    "ssti": {"pattern": "500|error|blocked|filtered", "timeout": 30},
    "ssrf": {"pattern": "403|refused|blocked|filtered|timeout", "timeout": 30},
    "lfi": {"pattern": "403|not found|blocked|filtered", "timeout": 15},
    "xxe": {"pattern": "403|not found|blocked|filtered|parsing error", "timeout": 30},
    "file_upload": {"pattern": "not allowed|forbidden|rejected|blocked|invalid", "timeout": 30},
    "hydra": {"pattern": "0 valid passwords|error|refused|timeout", "timeout": 600},
    "hashcat": {"pattern": "Exhausted|No hashes loaded|error", "timeout": 3600},
    "john": {"pattern": "No password hashes loaded|error", "timeout": 3600},
    "ftp_anon": {"pattern": "Login incorrect|refused|530", "timeout": 15},
    "ssh": {"pattern": "Permission denied|refused|timeout", "timeout": 15},
    "mysql": {"pattern": "Access denied|refused|error", "timeout": 15},
    "redis": {"pattern": "NOAUTH|refused|error", "timeout": 15},
    "potato": {"pattern": "failed|error|not vulnerable", "timeout": 30},
    "printspoofer": {"pattern": "failed|error|not vulnerable", "timeout": 30},
    "rbcd": {"pattern": "ACCESS_DENIED|INSUFFICIENT_ACCESS|error", "timeout": 60},
    "golden_ticket": {"pattern": "error|KRB_AP_ERR", "timeout": 30},
    "silver_ticket": {"pattern": "error|KRB_AP_ERR", "timeout": 30},
    "kerbrute_userenum": {"pattern": "0 valid usernames|error|timeout", "timeout": 120},
    "kerbrute_spray": {"pattern": "0 valid passwords|error|timeout|locked out", "timeout": 120},
    "ldapsearch": {"pattern": "Can't contact|Operations error|refused", "timeout": 30},
    "nikto": {"pattern": "ERROR|0 host.*tested", "timeout": 300},
    "feroxbuster": {"pattern": "error|Could not connect|refused", "timeout": 300},
    "gobuster": {"pattern": "error|refused|timeout", "timeout": 300},
    "wpscan": {"pattern": "not running WordPress|error|refused", "timeout": 120},
}


def assign_parser(action_name: str, current_parser) -> str:
    """Determine the best parser for an action."""
    if current_parser and current_parser != "null":
        return current_parser

    for pattern, parser_name in PARSER_RULES.items():
        if pattern in action_name:
            return parser_name

    # Check command template for tool hints
    return None


def improve_falsifier(action_name: str, current_falsifier: dict) -> dict:
    """Improve falsifier with technique-specific patterns."""
    if action_name in IMPROVED_FALSIFIERS:
        improved = IMPROVED_FALSIFIERS[action_name].copy()
        # Merge with existing timeout if longer
        if isinstance(current_falsifier, dict):
            existing_timeout = current_falsifier.get('timeout', 0)
            if existing_timeout > improved.get('timeout', 0):
                improved['timeout'] = existing_timeout
        return improved
    return None


def enrich_mechanism(action_name: str, current_mechanism: str, ki) -> str:
    """Enrich mechanism with HackTricks content if current is short."""
    if len(current_mechanism) >= 150:
        # Already detailed enough
        return None

    ctx = ki.get_technique_context(action_name, max_chars=300)
    if not ctx:
        return None

    # Extract text without the source header
    lines = ctx.split('\n')
    text_parts = []
    for line in lines[1:]:  # Skip header
        line = line.strip()
        if line and not line.startswith('```') and not line.startswith('|') and not line.startswith('#'):
            text_parts.append(line)
        if len(' '.join(text_parts)) > 200:
            break

    new_text = ' '.join(text_parts)[:250]
    if len(new_text) > len(current_mechanism) * 1.3:
        return new_text.strip()
    return None


def get_hacktricks_ref(action_name: str, ki) -> str:
    """Find the most relevant HackTricks page for this action."""
    keywords = TECHNIQUE_ALIASES.get(action_name, action_name.replace('_', ' '))
    results = ki.search(keywords, source="hacktricks", top_n=3)
    if results:
        fp = results[0]['filepath']
        # Convert to relative path
        prefix = "/home/kali/hacktricks/src/"
        if fp.startswith(prefix):
            return fp[len(prefix):]
    return None


def enrich_action(yml_path: Path, ki, dry_run=True) -> dict:
    """Enrich a single action YAML. Returns dict of changes made."""
    try:
        content = yml_path.read_text()
        action = yaml.safe_load(content)
        if not action or 'name' not in action:
            return {}
    except Exception:
        return {}

    name = action['name']
    changes = {}

    # 1. Parser assignment
    new_parser = assign_parser(name, action.get('parser'))
    if new_parser and new_parser != action.get('parser'):
        changes['parser'] = new_parser

    # 2. Falsifier improvement
    current_falsifier = action.get('falsifier', {})
    new_falsifier = improve_falsifier(name, current_falsifier)
    if new_falsifier:
        # Only update if new pattern is longer/better
        old_pat = current_falsifier.get('pattern', '') if isinstance(current_falsifier, dict) else ''
        new_pat = new_falsifier.get('pattern', '')
        if len(new_pat) > len(old_pat):
            changes['falsifier'] = new_falsifier

    # 3. Mechanism enrichment
    current_mech = action.get('mechanism', '')
    new_mech = enrich_mechanism(name, current_mech, ki)
    if new_mech:
        changes['mechanism'] = new_mech

    # 4. HackTricks reference
    if 'hacktricks_ref' not in action:
        ref = get_hacktricks_ref(name, ki)
        if ref:
            changes['hacktricks_ref'] = ref

    if not changes:
        return {}

    if not dry_run:
        # Apply changes to YAML
        for key, value in changes.items():
            action[key] = value

        # Write back preserving format as much as possible
        with open(yml_path, 'w') as f:
            yaml.dump(action, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

    return changes


def main():
    import argparse
    parser = argparse.ArgumentParser(description="TAR Action YAML Enrichment")
    parser.add_argument('--dry-run', action='store_true', default=True, help='Show changes without applying (default)')
    parser.add_argument('--apply', action='store_true', help='Apply changes to YAML files')
    parser.add_argument('--category', help='Only enrich specific category')
    parser.add_argument('--action', help='Only enrich specific action by name')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show details of each change')
    args = parser.parse_args()

    if args.apply:
        args.dry_run = False

    ki = get_index()

    total = 0
    enriched = 0
    change_counts = {'parser': 0, 'falsifier': 0, 'mechanism': 0, 'hacktricks_ref': 0}

    for yml_path in sorted(ACTIONS_DIR.rglob('*.yml')):
        # Category filter
        if args.category:
            if args.category not in str(yml_path):
                continue

        try:
            action = yaml.safe_load(yml_path.read_text())
            if not action or 'name' not in action:
                continue
        except Exception:
            continue

        # Action name filter
        if args.action and action['name'] != args.action:
            continue

        total += 1
        changes = enrich_action(yml_path, ki, dry_run=args.dry_run)

        if changes:
            enriched += 1
            for key in changes:
                change_counts[key] = change_counts.get(key, 0) + 1

            if args.verbose:
                print(f"\n{action['name']} ({yml_path.relative_to(ACTIONS_DIR)}):")
                for key, value in changes.items():
                    if key == 'mechanism':
                        print(f"  {key}: {str(value)[:80]}...")
                    elif key == 'falsifier':
                        print(f"  {key}: pattern={value.get('pattern','')[:60]}...")
                    else:
                        print(f"  {key}: {value}")

    mode = "APPLIED" if not args.dry_run else "DRY-RUN"
    print(f"\n[{mode}] Processed {total} actions, enriched {enriched}")
    for key, count in change_counts.items():
        if count:
            print(f"  {key}: {count} changes")


if __name__ == "__main__":
    main()
