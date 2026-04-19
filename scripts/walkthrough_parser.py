#!/usr/bin/env python3
"""
walkthrough_parser.py — Parse 0xdf walkthrough markdown into structured steps.json.
Extracts (phase, command, action_name, params) tuples from walkthrough raw.md files.
No LLM needed — pure pattern matching on 0xdf's consistent format.
"""

import json
import re
import sys
from pathlib import Path


# Phase mapping from 0xdf section headers
PHASE_KEYWORDS = {
    "recon": ["recon", "enumeration", "initial scan", "nmap", "scanning", "information gathering"],
    "foothold": ["foothold", "initial access", "shell as", "exploitation", "getting a shell", "rce", "reverse shell"],
    "user": ["user", "lateral", "pivoting to", "as user", "user flag", "user.txt"],
    "privesc": ["privesc", "privilege escalation", "root", "admin", "escalation", "beyond", "getting root", "domain admin"],
    "root": ["root flag", "root.txt", "system", "nt authority"],
}

# Command-to-action classification patterns
ACTION_PATTERNS = [
    # Recon
    (r"nmap\s+-p-", "nmap_full"),
    (r"nmap\s+.*-sC.*-sV|nmap\s+.*-sCV|nmap\s+.*-sV.*-sC", "nmap_scripts"),
    (r"nmap\s+.*-sU", "nmap_udp"),
    (r"nmap\s+", "nmap_targeted"),

    # SMB
    (r"smbclient\s+-[NL]|smbclient\s+.*-L\s", "smbclient_list_shares"),
    (r"smbclient\s+//", "smbclient_connect"),
    (r"smbmap\s+", "smbmap"),
    (r"enum4linux", "enum4linux_ng"),
    (r"rpcclient\s+.*-U\s+['\"]?\s*['\"]?\s+-N|rpcclient.*enumdom", "smb_null_session"),
    (r"rpcclient", "rpcclient"),

    # NetExec / CrackMapExec
    (r"(?:netexec|crackmapexec)\s+smb.*--shares", "smb_share_enum"),
    (r"(?:netexec|crackmapexec)\s+smb.*--users", "smb_user_enum"),
    (r"(?:netexec|crackmapexec)\s+smb.*--rid-brute", "rid_brute"),
    (r"(?:netexec|crackmapexec)\s+smb", "crackmapexec_spray"),
    (r"(?:netexec|crackmapexec)\s+winrm", "winrm_check"),
    (r"(?:netexec|crackmapexec)\s+ldap", "ldap_enum"),
    (r"(?:netexec|crackmapexec)\s+mssql", "mssql_check"),

    # Web
    (r"gobuster\s+dir|gobuster\s+vhost", "gobuster"),
    (r"feroxbuster", "feroxbuster"),
    (r"ffuf\s+", "ffuf"),
    (r"wfuzz\s+", "wfuzz"),
    (r"nikto\s+", "nikto"),
    (r"whatweb\s+", "whatweb"),
    (r"curl\s+", "curl_request"),
    (r"burp|sqlmap", "sqlmap"),
    (r"hydra\s+", "hydra"),

    # Kerberos / AD
    (r"impacket-GetUserSPNs|GetUserSPNs", "kerberoast"),
    (r"impacket-GetNPUsers|GetNPUsers", "asreproast"),
    (r"impacket-GetADUsers|GetADUsers", "impacket_getusers"),
    (r"kerbrute\s+userenum", "kerbrute_userenum"),
    (r"kerbrute\s+passwordspray", "kerbrute_spray"),
    (r"bloodhound-python|bloodhound\.py|SharpHound", "bloodhound"),
    (r"impacket-secretsdump|secretsdump", "secretsdump"),
    (r"impacket-dacledit|dacledit", "dacledit"),
    (r"impacket-rbcd|rbcd", "rbcd"),
    (r"impacket-addcomputer|addcomputer", "addcomputer"),
    (r"impacket-findDelegation|findDelegation", "find_delegation"),
    (r"certipy|certipy-ad", "certipy"),
    (r"ldapsearch\s+", "ldapsearch"),
    (r"ldapdomaindump", "ldapdomaindump"),

    # Shells
    (r"impacket-psexec|psexec\.py", "psexec"),
    (r"impacket-wmiexec|wmiexec\.py", "wmiexec"),
    (r"impacket-smbexec|smbexec\.py", "smbexec"),
    (r"impacket-atexec|atexec\.py", "atexec"),
    (r"impacket-dcomexec|dcomexec\.py", "dcomexec"),
    (r"evil-winrm", "evil_winrm"),
    (r"ssh\s+", "ssh"),
    (r"nc\s+.*-[le]|ncat\s+", "netcat"),
    (r"msfconsole|msfvenom|metasploit", "metasploit"),
    (r"impacket-mssqlclient|mssqlclient", "mssqlclient"),

    # Privesc
    (r"linpeas|LinPEAS", "linpeas"),
    (r"winpeas|WinPEAS", "winpeas"),
    (r"sudo\s+-l", "sudo_check"),
    (r"find\s+.*-perm.*4000|find.*-perm.*suid", "suid_search"),
    (r"getcap\s+", "capabilities_check"),

    # File transfer
    (r"python3?\s+.*http\.server|SimpleHTTPServer", "http_server"),
    (r"impacket-smbserver|smbserver", "smb_server"),
    (r"wget\s+|curl\s+.*-[oO]", "file_download"),

    # Cracking
    (r"hashcat\s+", "hashcat"),
    (r"john\s+", "john"),

    # Tunneling
    (r"chisel\s+", "chisel"),
    (r"ligolo|proxychains", "tunnel"),

    # Responder / Relay
    (r"responder\s+", "responder"),
    (r"impacket-ntlmrelayx|ntlmrelayx", "ntlmrelayx"),
    (r"coercer|PetitPotam|printerbug|dfscoerce", "coerce"),
]


def classify_command(cmd: str) -> str:
    """Map a command string to an action name."""
    cmd_lower = cmd.lower()
    for pattern, action_name in ACTION_PATTERNS:
        if re.search(pattern, cmd, re.IGNORECASE):
            return action_name
    return "unknown"


def detect_phase(header: str, text_after: str = "") -> str:
    """Map a section header to a phase."""
    combined = (header + " " + text_after[:200]).lower()
    for phase, keywords in PHASE_KEYWORDS.items():
        for kw in keywords:
            if kw in combined:
                return phase
    return "unknown"


def extract_target_ip(text: str) -> str | None:
    """Extract the most common IP from the walkthrough (the target)."""
    ips = re.findall(r"\b(?:10|172|192)\.\d+\.\d+\.\d+\b", text)
    if not ips:
        return None
    # Most frequent non-scanner IP
    from collections import Counter
    counts = Counter(ips)
    return counts.most_common(1)[0][0]


def extract_commands(code_block: str) -> list[str]:
    """Extract commands from a code block (lines with shell prompts)."""
    commands = []
    for line in code_block.split("\n"):
        line = line.strip()
        # 0xdf prompt patterns
        match = re.match(r"^(?:oxdf@\w+\$|root@\w+[#$]|\$|#|kali@\w+[#$]|PS\s+\w:\\.*>)\s*(.*)", line)
        if match:
            cmd = match.group(1).strip()
            if cmd and len(cmd) > 3:
                commands.append(cmd)
    return commands


def parse_walkthrough(raw_md_path: str) -> dict:
    """Parse a single walkthrough markdown into structured steps."""
    text = Path(raw_md_path).read_text(errors="replace")
    target_ip = extract_target_ip(text)

    steps = []
    current_phase = "recon"
    current_section = ""

    # Split into sections by headers
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]

        # Detect headers
        header_match = re.match(r"^(#{1,4})\s+(.*)", line)
        if header_match:
            level = len(header_match.group(1))
            header_text = header_match.group(2).strip()
            current_section = header_text

            # Look ahead for phase context
            lookahead = "\n".join(lines[i:i+10])
            new_phase = detect_phase(header_text, lookahead)
            if new_phase != "unknown":
                current_phase = new_phase
            i += 1
            continue

        # Detect code blocks
        if line.strip().startswith("```"):
            code_lines = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                code_lines.append(lines[i])
                i += 1
            i += 1  # skip closing ```

            code_block = "\n".join(code_lines)
            commands = extract_commands(code_block)

            for cmd in commands:
                action_name = classify_command(cmd)
                # Extract target IP from command if present
                cmd_ip = None
                ip_match = re.search(r"\b(?:10|172|192)\.\d+\.\d+\.\d+\b", cmd)
                if ip_match:
                    cmd_ip = ip_match.group(0)

                steps.append({
                    "phase": current_phase,
                    "section": current_section,
                    "command": cmd,
                    "action": action_name,
                    "target_ip": cmd_ip or target_ip,
                })
            continue

        i += 1

    # Extract metadata
    os_type = "unknown"
    if re.search(r"windows|microsoft|iis|mssql|winrm|active.directory", text[:3000], re.I):
        os_type = "windows"
    elif re.search(r"linux|ubuntu|debian|apache|nginx|ssh.*22", text[:3000], re.I):
        os_type = "linux"

    return {
        "target_ip": target_ip,
        "os": os_type,
        "steps": steps,
        "total_commands": len(steps),
        "actions_used": list(set(s["action"] for s in steps)),
    }


def process_all_walkthroughs(walkthroughs_dir: str, limit: int = None):
    """Process all walkthroughs and write steps.json files."""
    wt_dir = Path(walkthroughs_dir)
    processed = 0
    skipped = 0
    errors = 0

    for box_dir in sorted(wt_dir.iterdir()):
        if not box_dir.is_dir():
            continue
        raw_path = box_dir / "raw.md"
        steps_path = box_dir / "steps.json"

        if not raw_path.exists():
            continue

        if steps_path.exists() and steps_path.stat().st_size > 100:
            skipped += 1
            continue

        if limit and processed >= limit:
            break

        try:
            result = parse_walkthrough(str(raw_path))
            result["box_name"] = box_dir.name

            steps_path.write_text(json.dumps(result, indent=2))
            processed += 1

            action_count = len(result["actions_used"])
            step_count = result["total_commands"]
            print(f"  [+] {box_dir.name}: {step_count} steps, {action_count} unique actions, os={result['os']}")

        except Exception as e:
            print(f"  [!] {box_dir.name}: {e}", file=sys.stderr)
            errors += 1

    return processed, skipped, errors


def cmd_parse(args):
    if args.box:
        # Parse single box
        raw_path = Path(args.walkthroughs_dir) / args.box / "raw.md"
        if not raw_path.exists():
            print(f"[!] {raw_path} not found", file=sys.stderr)
            return 1
        result = parse_walkthrough(str(raw_path))
        result["box_name"] = args.box
        output_path = raw_path.parent / "steps.json"
        output_path.write_text(json.dumps(result, indent=2))
        print(json.dumps(result, indent=2))
    else:
        # Parse all
        print(f"[*] Parsing walkthroughs in {args.walkthroughs_dir}...")
        processed, skipped, errors = process_all_walkthroughs(
            args.walkthroughs_dir, limit=args.limit
        )
        print(f"\n[=] Processed: {processed}, Skipped: {skipped}, Errors: {errors}")
    return 0


def cmd_stats(args):
    """Show statistics about parsed walkthroughs."""
    wt_dir = Path(args.walkthroughs_dir)
    total = 0
    parsed = 0
    action_freq = {}
    phase_freq = {}
    os_freq = {}

    for box_dir in sorted(wt_dir.iterdir()):
        if not box_dir.is_dir():
            continue
        total += 1
        steps_path = box_dir / "steps.json"
        if not steps_path.exists():
            continue

        data = json.loads(steps_path.read_text())
        parsed += 1
        os_freq[data.get("os", "unknown")] = os_freq.get(data.get("os", "unknown"), 0) + 1

        for step in data.get("steps", []):
            action = step.get("action", "unknown")
            phase = step.get("phase", "unknown")
            action_freq[action] = action_freq.get(action, 0) + 1
            phase_freq[phase] = phase_freq.get(phase, 0) + 1

    print(f"Total boxes: {total}, Parsed: {parsed}")
    print(f"\nOS distribution: {json.dumps(os_freq)}")
    print(f"\nPhase distribution: {json.dumps(phase_freq)}")
    print(f"\nTop 30 actions:")
    for action, count in sorted(action_freq.items(), key=lambda x: -x[1])[:30]:
        print(f"  {action:30s} {count:5d}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Parse HTB walkthroughs into structured steps")
    parser.add_argument("--walkthroughs-dir", default="/home/kali/knowledge/walkthroughs")
    sub = parser.add_subparsers(dest="command")

    p_parse = sub.add_parser("parse", help="Parse walkthroughs into steps.json")
    p_parse.add_argument("--box", help="Parse single box by name")
    p_parse.add_argument("--limit", type=int, help="Max boxes to process")
    p_parse.set_defaults(func=cmd_parse)

    p_stats = sub.add_parser("stats", help="Show parsing statistics")
    p_stats.set_defaults(func=cmd_stats)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
