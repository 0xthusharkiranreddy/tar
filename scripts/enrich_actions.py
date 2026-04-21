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
    "api_enum": "gobuster_parser",
    # Impacket / AD tools → impacket_parser
    "kerberoast": "impacket_parser",
    "asreproast": "impacket_parser",
    "secretsdump": "impacket_parser",
    "dcsync": "impacket_parser",
    "psexec": "impacket_parser",
    "wmiexec": "impacket_parser",
    "impacket_": "impacket_parser",
    "golden_ticket": "impacket_parser",
    "silver_ticket": "impacket_parser",
    "diamond_ticket": "impacket_parser",
    "constrained_delegation": "impacket_parser",
    "unconstrained_delegation": "impacket_parser",
    "rbcd": "impacket_parser",
    "find_delegation": "impacket_parser",
    "addcomputer": "impacket_parser",
    "pass_the_": "impacket_parser",
    "overpass_the_hash": "impacket_parser",
    # Hash cracking → hashcat_parser
    "hashcat": "hashcat_parser",
    "john": "hashcat_parser",
    # Bloodhound → bloodhound_parser
    "bloodhound": "bloodhound_parser",
    # Linux privesc → linpeas_parser or generic
    "linpeas": "linpeas_parser",
    "suid": "generic_parser",
    "capabilities": "generic_parser",
    "cron_": "generic_parser",
    "sudo_": "generic_parser",
    "kernel_": "generic_parser",
    "docker_privesc": "generic_parser",
    "writable_": "generic_parser",
    # Windows privesc → winpeas_parser or generic
    "winpeas": "winpeas_parser",
    "potato": "generic_parser",
    "printspoofer": "generic_parser",
    "efspotato": "generic_parser",
    "godpotato": "generic_parser",
    "juicypotato": "generic_parser",
    "dll_hijack": "generic_parser",
    "always_install": "generic_parser",
    "backup_operators": "generic_parser",
    "unquoted_service": "generic_parser",
    "seimpersonate": "generic_parser",
    # Web attack tools → web_response_parser
    "sqli": "web_response_parser",
    "sqlmap": "web_response_parser",
    "blind_sqli": "web_response_parser",
    "ssti": "web_response_parser",
    "xss": "web_response_parser",
    "lfi": "web_response_parser",
    "rfi": "web_response_parser",
    "ssrf": "web_response_parser",
    "xxe": "web_response_parser",
    "command_injection": "web_response_parser",
    "file_upload": "web_response_parser",
    "deserialization": "web_response_parser",
    "path_traversal": "web_response_parser",
    "jwt": "web_response_parser",
    "idor": "web_response_parser",
    "cors": "web_response_parser",
    "csrf": "web_response_parser",
    "crlf": "web_response_parser",
    "open_redirect": "web_response_parser",
    "graphql": "web_response_parser",
    "nosql": "web_response_parser",
    "ldap_injection": "web_response_parser",
    "xpath_injection": "web_response_parser",
    "websocket": "web_response_parser",
    "cache_poisoning": "web_response_parser",
    "http_smuggling": "web_response_parser",
    "host_header": "web_response_parser",
    "webdav": "web_response_parser",
    "auth_bypass": "web_response_parser",
    "curl_request": "web_response_parser",
    "subdomain_enum": "web_response_parser",
    "git_dump": "web_response_parser",
    "race_condition": "web_response_parser",
    # CMS tools → web_response_parser
    "wpscan": "web_response_parser",
    "droopescan": "web_response_parser",
    "joomscan": "web_response_parser",
    "wordpress_": "web_response_parser",
    "drupal_": "web_response_parser",
    "joomla_": "web_response_parser",
    # Web fingerprinting → tech_detect_parser
    "nikto": "tech_detect_parser",
    "whatweb": "tech_detect_parser",
    # Service tools → generic_parser
    "hydra": "generic_parser",
    "ssh": "generic_parser",
    "ftp_": "generic_parser",
    "mysql": "generic_parser",
    "mssql": "generic_parser",
    "redis": "generic_parser",
    "mongodb": "generic_parser",
    "ldapsearch": "generic_parser",
    "snmp": "generic_parser",
    "smtp": "generic_parser",
    "pop3": "generic_parser",
    "imap": "generic_parser",
    "dns_": "generic_parser",
    "nfs_": "generic_parser",
    "rpc_": "generic_parser",
    "rdp": "generic_parser",
    "vnc": "generic_parser",
    "winrm": "generic_parser",
    "evil_winrm": "generic_parser",
    "tomcat": "generic_parser",
    "jenkins": "generic_parser",
    "docker_": "generic_parser",
    "kubernetes": "generic_parser",
    "netcat": "generic_parser",
    # AD tools → generic_parser or impacket_parser (those not covered above)
    "certipy": "generic_parser",
    "adcs_": "generic_parser",
    "acl_abuse": "generic_parser",
    "gpo_abuse": "generic_parser",
    "shadow_credentials": "generic_parser",
    "exchange_": "generic_parser",
    "coerce": "generic_parser",
    "ntlmrelayx": "generic_parser",
    "responder": "generic_parser",
    "petitpotam": "generic_parser",
    "adidns": "generic_parser",
    "dacledit": "generic_parser",
    "dpapi": "generic_parser",
    "forcechangepassword": "generic_parser",
    "getst": "impacket_parser",
    "gettgt": "impacket_parser",
    "gmsa": "generic_parser",
    "gpp_password": "generic_parser",
    "groupadd": "generic_parser",
    "kerberos_": "impacket_parser",
    "krbtgt": "impacket_parser",
    "laps_": "generic_parser",
    "ldapdomaindump": "generic_parser",
    "machine_account": "generic_parser",
    "maq_": "generic_parser",
    "msol_": "generic_parser",
    "ntds_": "generic_parser",
    "ntlm_theft": "generic_parser",
    "owneredit": "generic_parser",
    "passthehash": "impacket_parser",
    "passtheticket": "impacket_parser",
    "read_gmsa": "generic_parser",
    "read_laps": "generic_parser",
    "rpcclient": "generic_parser",
    "samaccountname": "impacket_parser",
    "sccm_": "generic_parser",
    "sid_history": "impacket_parser",
    "skeleton_key": "generic_parser",
    "smbexec": "impacket_parser",
    "spoolsample": "generic_parser",
    "ticketer": "impacket_parser",
    "trusts_enum": "generic_parser",
    "wmi_enum": "generic_parser",
    "wsus_": "generic_parser",
    "zerologon": "generic_parser",
    "dcomexec": "impacket_parser",
    "atexec": "impacket_parser",
    "printnightmare": "generic_parser",
    # Pivoting → generic_parser
    "chisel": "generic_parser",
    "ligolo": "generic_parser",
    "proxychains": "generic_parser",
    "ssh_tunnel": "generic_parser",
    "tunnel": "generic_parser",
    "double_pivot": "generic_parser",
    "port_forward": "generic_parser",
    "proxy_check": "generic_parser",
    # Creds → generic_parser
    "kerbrute": "generic_parser",
    "rid_brute": "generic_parser",
    "spray": "generic_parser",
    "stored_credentials": "generic_parser",
    # Web — additional specific actions
    "api_key": "web_response_parser",
    "cgi_": "web_response_parser",
    "shellshock": "web_response_parser",
    "file_read": "web_response_parser",
    "graphql": "web_response_parser",
    "header_injection": "web_response_parser",
    "insecure_deserialization": "web_response_parser",
    "insecure_upload": "web_response_parser",
    "log_poisoning": "web_response_parser",
    "mass_assignment": "web_response_parser",
    "nosqli": "web_response_parser",
    "oauth": "web_response_parser",
    "padding_oracle": "web_response_parser",
    "php_filter": "web_response_parser",
    "php_object": "web_response_parser",
    "prototype_pollution": "web_response_parser",
    "rce_": "web_response_parser",
    "request_smuggling": "web_response_parser",
    "saml_": "web_response_parser",
    "sqli_stacked": "web_response_parser",
    "subdomain_takeover": "web_response_parser",
    "template_engine": "web_response_parser",
    "type_juggling": "web_response_parser",
    "waf_bypass": "web_response_parser",
    "django_debug": "web_response_parser",
    "laravel_debug": "web_response_parser",
    "log4shell": "web_response_parser",
    "phpmyadmin": "web_response_parser",
    "spring_boot": "web_response_parser",
    "struts_rce": "web_response_parser",
    "weblogic": "web_response_parser",
    "confluence": "web_response_parser",
    "grafana": "web_response_parser",
    "gitea": "web_response_parser",
    "solr": "web_response_parser",
    "splunk": "web_response_parser",
    "activemq": "web_response_parser",
    "apache_rce": "web_response_parser",
    "ajp_ghostcat": "web_response_parser",
    "iis_shortname": "web_response_parser",
    "nginx_misconfiguration": "web_response_parser",
    "magento": "web_response_parser",
    "java_rmi": "generic_parser",
    # Privesc — additional specific actions
    "apt_get_privesc": "generic_parser",
    "dbus_exploit": "generic_parser",
    "env_variable": "generic_parser",
    "gtfobins": "generic_parser",
    "logrotate": "generic_parser",
    "lxd_privesc": "generic_parser",
    "npm_privesc": "generic_parser",
    "passwd_write": "generic_parser",
    "path_hijack": "generic_parser",
    "pip_install": "generic_parser",
    "pkexec": "generic_parser",
    "polkit": "generic_parser",
    "pspy": "generic_parser",
    "python_library": "generic_parser",
    "rbash_escape": "generic_parser",
    "registry_autorun": "generic_parser",
    "runas_savecred": "generic_parser",
    "sambacry": "generic_parser",
    "scheduled_task": "generic_parser",
    "sebackup_privesc": "generic_parser",
    "serestore_privesc": "generic_parser",
    "setakeownership": "generic_parser",
    "service_exploit": "generic_parser",
    "service_file_overwrite": "generic_parser",
    "shared_library": "generic_parser",
    "snap_exploit": "generic_parser",
    "systemd_timer": "generic_parser",
    "token_manipulation": "generic_parser",
    "wildcard_injection": "generic_parser",
    "unquoted_service_path": "generic_parser",
    # Services — additional
    "cassandra": "generic_parser",
    "elasticsearch": "generic_parser",
    "ipmi": "generic_parser",
    "ldap_anon": "generic_parser",
    "ldap_passback": "generic_parser",
    "memcached": "generic_parser",
    "oracle_enum": "generic_parser",
    "postgres_enum": "generic_parser",
    "proftpd": "generic_parser",
    "rsync": "generic_parser",
    # Shell/binary/crypto → generic_parser
    "metasploit": "generic_parser",
    "shellcode": "generic_parser",
    "file_download": "generic_parser",
    "http_server": "generic_parser",
    "buffer_overflow": "generic_parser",
    "canary_leak": "generic_parser",
    "checksec": "generic_parser",
    "format_string": "generic_parser",
    "ghidra": "generic_parser",
    "heap_exploit": "generic_parser",
    "ret2libc": "generic_parser",
    "rop_chain": "generic_parser",
    "srop": "generic_parser",
    "aes_ecb": "generic_parser",
    "cbc_": "generic_parser",
    "ecb_": "generic_parser",
    "hash_collision": "generic_parser",
    "hash_length": "generic_parser",
    "known_plaintext": "generic_parser",
    "padding_oracle_attack": "generic_parser",
    "prng_": "generic_parser",
    "rsa_": "generic_parser",
    "timing_attack": "generic_parser",
    "weak_rsa": "generic_parser",
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
