#!/usr/bin/env python3
"""
knowledge_index.py — Searchable index over HackTricks, PayloadsAllTheThings, and local knowledge.

Builds a section-level TF-IDF index over ~2,500 markdown files from three sources.
Caches to pickle for fast subsequent loads (~0.3s vs ~8s cold build).

Usage:
    python3 knowledge_index.py search "kerberoast"
    python3 knowledge_index.py search "SSTI Jinja2" --source pat --top 5
    python3 knowledge_index.py technique kerberoast
    python3 knowledge_index.py technique certipy
    python3 knowledge_index.py failure kerberoast "No entries found"
    python3 knowledge_index.py alternatives sqli --services "80:Apache,3306:MySQL"
"""

import hashlib
import math
import os
import pickle
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

SOURCES = {
    "hacktricks": "/home/kali/hacktricks/src/",
    "pat": "/home/kali/PayloadsAllTheThings/",
    "knowledge": "/home/kali/knowledge/",
}

CACHE_PATH = "/tmp/tar_knowledge_index.pkl"

# Technique name → search keywords mapping for action→HackTricks lookup
TECHNIQUE_ALIASES = {
    # Recon
    "nmap_full": "nmap port scanning",
    "nmap_scripts": "nmap NSE scripts",
    "nmap_udp": "nmap UDP scanning",
    # SMB
    "smbclient": "SMB smbclient enumeration shares",
    "smbclient_list_shares": "SMB smbclient list shares",
    "smb_null_session": "SMB null session anonymous",
    "smb_guest_access": "SMB guest access",
    "crackmapexec_smb": "crackmapexec SMB enumeration",
    "crackmapexec_spray": "crackmapexec password spraying",
    "enum4linux": "enum4linux SMB enumeration",
    # AD / Kerberos
    "kerberoast": "kerberoasting SPN GetUserSPNs",
    "asreproast": "AS-REP roasting GetNPUsers",
    "bloodhound": "bloodhound active directory attack paths",
    "kerbrute_userenum": "kerbrute user enumeration kerberos",
    "kerbrute_spray": "kerbrute password spraying kerberos",
    "impacket_getusers": "impacket GetADUsers enumeration",
    "secretsdump": "secretsdump NTDS SAM LSA",
    "dcsync": "DCSync replication mimikatz",
    "golden_ticket": "golden ticket kerberos",
    "silver_ticket": "silver ticket kerberos",
    "psexec": "psexec remote execution SMB",
    "wmiexec": "wmiexec WMI remote execution",
    "evil_winrm": "evil-winrm WinRM",
    "ntlmrelayx": "NTLM relay ntlmrelayx",
    "responder": "responder LLMNR NBT-NS poisoning",
    "petitpotam": "PetitPotam coercion NTLM",
    "certipy": "ADCS certipy certificate abuse ESC",
    "rbcd": "resource-based constrained delegation",
    "constrained_delegation": "constrained delegation S4U",
    "unconstrained_delegation": "unconstrained delegation",
    "acl_abuse": "ACL abuse Active Directory DACL",
    "gpo_abuse": "GPO abuse Group Policy",
    "shadow_credentials": "shadow credentials msDS-KeyCredentialLink",
    # Web
    "feroxbuster": "directory brute force feroxbuster gobuster",
    "gobuster": "gobuster directory brute force",
    "ffuf": "ffuf fuzzing web",
    "nikto": "nikto web scanner",
    "whatweb": "whatweb fingerprint",
    "sqli": "SQL injection",
    "sqli_union": "SQL injection UNION based",
    "sqli_blind": "SQL injection blind boolean time",
    "sqli_error": "SQL injection error based",
    "sqlmap": "sqlmap SQL injection",
    "xss": "cross-site scripting XSS",
    "lfi": "local file inclusion LFI",
    "rfi": "remote file inclusion RFI",
    "ssti": "server-side template injection SSTI",
    "ssrf": "server-side request forgery SSRF",
    "xxe": "XML external entity XXE",
    "file_upload": "file upload bypass webshell",
    "jwt": "JWT JSON web token",
    "deserialization": "insecure deserialization",
    "command_injection": "command injection OS",
    "path_traversal": "path traversal directory",
    "idor": "IDOR insecure direct object reference",
    "csrf": "CSRF cross-site request forgery",
    "cors": "CORS misconfiguration",
    "open_redirect": "open redirect",
    "graphql": "GraphQL injection introspection",
    "nosql": "NoSQL injection MongoDB",
    "ldap_injection": "LDAP injection",
    "xpath_injection": "XPath injection",
    "crlf": "CRLF injection",
    "websocket": "websocket hijacking",
    # CMS
    "wpscan": "WordPress wpscan",
    "droopescan": "Drupal droopescan",
    "joomscan": "Joomla joomscan",
    # Services
    "ftp_anon": "FTP anonymous login",
    "ssh": "SSH brute force",
    "hydra": "hydra brute force",
    "ssh_key": "SSH key authentication",
    "mysql": "MySQL enumeration pentesting",
    "mssql": "MSSQL pentesting xp_cmdshell",
    "redis": "Redis pentesting",
    "mongodb": "MongoDB pentesting",
    "ldapsearch": "LDAP search enumeration",
    "snmp": "SNMP enumeration",
    "smtp": "SMTP user enumeration",
    "pop3": "POP3 pentesting",
    "imap": "IMAP pentesting",
    "dns": "DNS enumeration zone transfer",
    "nfs": "NFS enumeration mount",
    "rpc": "RPC enumeration",
    "winrm": "WinRM pentesting",
    "rdp": "RDP pentesting",
    "vnc": "VNC pentesting",
    "tomcat": "Apache Tomcat exploitation",
    "jenkins": "Jenkins exploitation",
    # Privesc
    "linpeas": "linpeas linux privilege escalation",
    "winpeas": "winpeas windows privilege escalation",
    "suid": "SUID privilege escalation",
    "sudo": "sudo privilege escalation",
    "cron": "cron job privilege escalation",
    "capabilities": "Linux capabilities privilege escalation",
    "kernel_exploit": "kernel exploit privilege escalation",
    "potato": "potato privilege escalation SeImpersonate",
    "printspoofer": "PrintSpoofer privilege escalation",
    "juicypotato": "JuicyPotato privilege escalation",
    # Creds
    "hashcat": "hashcat hash cracking",
    "john": "john the ripper hash cracking",
    # Pivoting
    "chisel": "chisel tunneling pivot",
    "ligolo": "ligolo-ng pivot",
    "proxychains": "proxychains pivot SOCKS",
    "ssh_tunnel": "SSH tunnel port forwarding",
}


def tokenize(text: str) -> List[str]:
    """Tokenize text into lowercase words."""
    return re.findall(r'\w+', text.lower())


def _split_sections(content: str, filepath: str) -> List[dict]:
    """Split markdown content into sections by headings.

    Returns list of {heading, text, filepath, source, level}.
    """
    sections = []
    lines = content.split('\n')
    current_heading = os.path.basename(filepath).replace('.md', '').replace('-', ' ')
    current_lines = []
    current_level = 0

    for line in lines:
        # Match markdown headings
        m = re.match(r'^(#{1,4})\s+(.+)', line)
        if m:
            # Save previous section if non-empty
            text = '\n'.join(current_lines).strip()
            if text and len(text) > 50:  # Skip trivially short sections
                sections.append({
                    'heading': current_heading,
                    'text': text,
                    'filepath': filepath,
                    'level': current_level,
                })
            current_heading = m.group(2).strip()
            current_level = len(m.group(1))
            current_lines = []
        else:
            current_lines.append(line)

    # Last section
    text = '\n'.join(current_lines).strip()
    if text and len(text) > 50:
        sections.append({
            'heading': current_heading,
            'text': text,
            'filepath': filepath,
            'level': current_level,
        })

    return sections


def _detect_source(filepath: str) -> str:
    """Detect which source a file belongs to."""
    for name, root in SOURCES.items():
        if filepath.startswith(root):
            return name
    return "unknown"


def _discover_files() -> List[str]:
    """Discover all markdown files across all sources."""
    files = []
    for source_name, root in SOURCES.items():
        if not os.path.isdir(root):
            continue
        for dirpath, _, filenames in os.walk(root):
            # Skip hidden dirs, .git, images, etc.
            if '/.git/' in dirpath or '/images/' in dirpath or '/Intruder/' in dirpath:
                continue
            for f in filenames:
                if f.endswith('.md') and not f.startswith('.'):
                    files.append(os.path.join(dirpath, f))
    return files


def _get_source_mtime(sources: dict) -> float:
    """Get the most recent mtime across all source dirs."""
    latest = 0
    for root in sources.values():
        if os.path.isdir(root):
            # Check dir mtime (good enough proxy)
            latest = max(latest, os.path.getmtime(root))
    return latest


class KnowledgeIndex:
    """Searchable TF-IDF index over HackTricks, PAT, and local knowledge."""

    def __init__(self, rebuild=False):
        self.sections = []       # List of section dicts
        self.doc_tokens = []     # Tokenized sections
        self.idf = {}            # IDF scores
        self.doc_tfs = []        # Pre-computed TF per section
        self._loaded = False

        if not rebuild and os.path.exists(CACHE_PATH):
            try:
                with open(CACHE_PATH, 'rb') as f:
                    cache = pickle.load(f)
                # Validate cache version
                if cache.get('version') == 2:
                    self.sections = cache['sections']
                    self.idf = cache['idf']
                    self.doc_tfs = cache['doc_tfs']
                    self._loaded = True
                    return
            except Exception:
                pass

        self._build_index()

    def _build_index(self):
        """Build the full index from scratch."""
        t0 = time.time()
        files = _discover_files()

        # Parse all files into sections
        self.sections = []
        for fp in files:
            try:
                with open(fp, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                source = _detect_source(fp)
                for sec in _split_sections(content, fp):
                    sec['source'] = source
                    self.sections.append(sec)
            except OSError:
                continue

        # Compute IDF efficiently using document frequency counter
        total_docs = len(self.sections)
        doc_freq = Counter()  # token → number of docs containing it

        self.doc_tfs = []
        for sec in self.sections:
            combined = sec['heading'] + ' ' + sec['text']
            tokens = tokenize(combined)
            tf = Counter(tokens)
            total = len(tokens) if tokens else 1
            self.doc_tfs.append({k: v / total for k, v in tf.items()})
            # Count each unique token once per document
            doc_freq.update(tf.keys())

        # IDF from doc_freq
        self.idf = {
            t: math.log10(total_docs / count)
            for t, count in doc_freq.items()
        }

        self._loaded = True

        # Cache
        try:
            with open(CACHE_PATH, 'wb') as f:
                pickle.dump({
                    'version': 2,
                    'sections': self.sections,
                    'idf': self.idf,
                    'doc_tfs': self.doc_tfs,
                }, f, protocol=pickle.HIGHEST_PROTOCOL)
        except Exception:
            pass

        elapsed = time.time() - t0
        print(f"[KnowledgeIndex] Built index: {len(self.sections)} sections from {len(files)} files in {elapsed:.1f}s", file=sys.stderr)

    def search(self, query: str, source: Optional[str] = None, top_n: int = 5) -> List[dict]:
        """Search the index. Returns list of {heading, text, filepath, source, score}.

        Args:
            query: Search terms
            source: Filter to 'hacktricks', 'pat', or 'knowledge'
            top_n: Number of results
        """
        query_tokens = tokenize(query)
        if not query_tokens:
            return []

        results = []
        for i, sec in enumerate(self.sections):
            if source and sec.get('source') != source:
                continue

            tf = self.doc_tfs[i]
            score = sum(tf.get(t, 0) * self.idf.get(t, 0) for t in query_tokens)

            if score > 0:
                # Source weighting: HackTricks technique sections get 1.5x boost
                if sec['source'] == 'hacktricks':
                    score *= 1.5
                elif sec['source'] == 'pat':
                    score *= 1.3

                # Heading match bonus: if query terms appear in heading, 2x
                heading_tokens = set(tokenize(sec['heading']))
                heading_overlap = sum(1 for t in query_tokens if t in heading_tokens)
                if heading_overlap > 0:
                    score *= (1.0 + 0.5 * heading_overlap)

                results.append({
                    'heading': sec['heading'],
                    'text': sec['text'][:2000],  # Cap text length
                    'filepath': sec['filepath'],
                    'source': sec['source'],
                    'score': score,
                })

        results.sort(key=lambda x: x['score'], reverse=True)
        return results[:top_n]

    def get_technique_context(self, action_name: str, max_chars: int = 1500) -> str:
        """Get HackTricks/PAT context for a named action/technique.

        Returns a concise excerpt suitable for injection into planner context.
        Prefers sections from pages whose filepath matches the technique name.
        """
        # Look up search keywords for this action
        keywords = TECHNIQUE_ALIASES.get(action_name, action_name.replace('_', ' '))

        results = self.search(keywords, top_n=10)
        if not results:
            return ""

        # Prefer the introductory section from a page whose filepath matches the technique
        action_slug = action_name.lower().replace('_', '')
        best = results[0]

        # First pass: find results from a dedicated technique page
        page_results = []
        for r in results:
            fp_lower = r['filepath'].lower().replace('-', '').replace('_', '')
            if action_slug in fp_lower:
                page_results.append(r)

        if page_results:
            # Prefer the section with the longest text (usually the intro/overview)
            # among high-level headings from the matching page
            page_results.sort(key=lambda r: len(r['text']), reverse=True)
            best = page_results[0]

        text = best['text']

        # Trim to max_chars at a sentence boundary
        if len(text) > max_chars:
            cut = text[:max_chars].rfind('.')
            if cut > max_chars // 2:
                text = text[:cut + 1]
            else:
                text = text[:max_chars] + "..."

        source_label = best['source'].upper()
        return f"[{source_label}: {best['heading']}]\n{text}"

    def get_failure_guidance(self, action_name: str, error_pattern: str, max_chars: int = 800) -> str:
        """Get guidance for a specific failure pattern from HackTricks/PAT.

        Searches for the error pattern in context of the technique to find
        explanations and alternative approaches.
        """
        # Build query combining action and error
        keywords = TECHNIQUE_ALIASES.get(action_name, action_name.replace('_', ' '))
        query = f"{keywords} {error_pattern}"

        results = self.search(query, top_n=3)
        if not results:
            return ""

        # Look for sections that actually mention the error or related concepts
        for r in results:
            text_lower = r['text'].lower()
            error_lower = error_pattern.lower()
            # Check if result is relevant to the error
            error_words = tokenize(error_pattern)
            matches = sum(1 for w in error_words if w in text_lower)
            if matches >= len(error_words) // 2 or len(error_words) <= 2:
                text = r['text']
                if len(text) > max_chars:
                    cut = text[:max_chars].rfind('.')
                    text = text[:cut + 1] if cut > max_chars // 2 else text[:max_chars]
                return f"[{r['source'].upper()}: {r['heading']}]\n{text}"

        # Fallback: return top result anyway
        top = results[0]
        text = top['text'][:max_chars]
        return f"[{top['source'].upper()}: {top['heading']}]\n{text}"

    def get_alternatives(self, action_name: str, services: Optional[List[Tuple[int, str]]] = None, top_n: int = 5) -> List[dict]:
        """Get alternative techniques from HackTricks/PAT for the current attack surface.

        Args:
            action_name: The action that failed/is stuck
            services: List of (port, product) tuples from world model
        """
        # Build query from services if available
        queries = []

        keywords = TECHNIQUE_ALIASES.get(action_name, action_name.replace('_', ' '))
        queries.append(keywords)

        if services:
            for port, product in services[:5]:
                if product:
                    queries.append(f"pentesting {product} {port}")

        # Search with combined query
        combined_query = ' '.join(queries)
        results = self.search(combined_query, top_n=top_n * 2)

        # Filter out results about the same action
        action_words = set(tokenize(action_name))
        filtered = []
        for r in results:
            heading_words = set(tokenize(r['heading']))
            # Skip if heading is too similar to the original action
            if len(action_words & heading_words) >= len(action_words) * 0.7:
                continue
            filtered.append(r)

        return filtered[:top_n]

    def get_service_techniques(self, port: int, product: str = "", version: str = "") -> List[dict]:
        """Find HackTricks pages for a specific service.

        Useful for: given port 3306/MySQL 8.0, find all relevant exploitation pages.
        """
        query_parts = [f"pentesting {port}"]
        if product:
            query_parts.append(product)
        if version:
            query_parts.append(version)

        query = ' '.join(query_parts)
        return self.search(query, source="hacktricks", top_n=5)

    def get_version_vulns(self, product: str, version: str) -> List[dict]:
        """Search for known vulnerabilities for a specific product version.

        e.g., get_version_vulns("Apache", "2.4.49") → CVE-2021-41773 path traversal
        """
        query = f"{product} {version} exploit vulnerability CVE"
        results = self.search(query, top_n=10)

        # Filter for results that actually mention the version
        version_matched = []
        for r in results:
            if version in r['text'] or product.lower() in r['text'].lower():
                version_matched.append(r)

        return version_matched[:5] if version_matched else results[:3]

    def stats(self) -> dict:
        """Return index statistics."""
        source_counts = Counter(s['source'] for s in self.sections)
        return {
            'total_sections': len(self.sections),
            'sources': dict(source_counts),
            'idf_terms': len(self.idf),
        }


# ── Singleton for module-level use ──
_index = None

def get_index(rebuild=False) -> KnowledgeIndex:
    """Get or create the singleton KnowledgeIndex."""
    global _index
    if _index is None or rebuild:
        _index = KnowledgeIndex(rebuild=rebuild)
    return _index


def main():
    import argparse
    parser = argparse.ArgumentParser(description="TAR Knowledge Index — search HackTricks, PAT, and local knowledge")
    sub = parser.add_subparsers(dest='command')

    # search command
    sp = sub.add_parser('search', help='Search the index')
    sp.add_argument('query', help='Search query')
    sp.add_argument('--source', choices=['hacktricks', 'pat', 'knowledge'], default=None)
    sp.add_argument('--top', type=int, default=5)

    # technique command
    tp = sub.add_parser('technique', help='Get technique context for an action')
    tp.add_argument('action_name', help='Action name (e.g., kerberoast)')

    # failure command
    fp = sub.add_parser('failure', help='Get failure guidance')
    fp.add_argument('action_name', help='Action that failed')
    fp.add_argument('error', help='Error pattern or message')

    # alternatives command
    ap = sub.add_parser('alternatives', help='Get alternative techniques')
    ap.add_argument('action_name', help='Current stuck action')
    ap.add_argument('--services', help='Comma-separated port:product pairs')

    # stats command
    sub.add_parser('stats', help='Show index statistics')

    # rebuild command
    sub.add_parser('rebuild', help='Force rebuild the index')

    args = parser.parse_args()

    if args.command == 'rebuild':
        idx = get_index(rebuild=True)
        s = idx.stats()
        print(f"Index rebuilt: {s['total_sections']} sections, {s['idf_terms']} terms")
        for src, count in s['sources'].items():
            print(f"  {src}: {count} sections")
        return

    if args.command == 'stats':
        idx = get_index()
        s = idx.stats()
        print(f"Sections: {s['total_sections']}")
        print(f"Terms: {s['idf_terms']}")
        for src, count in s['sources'].items():
            print(f"  {src}: {count}")
        return

    if args.command == 'search':
        idx = get_index()
        results = idx.search(args.query, source=args.source, top_n=args.top)
        if not results:
            print("No results found.")
            return
        for i, r in enumerate(results, 1):
            print(f"\n── Result {i} [{r['source']}] score={r['score']:.4f} ──")
            print(f"  File: {r['filepath']}")
            print(f"  Heading: {r['heading']}")
            preview = r['text'][:300].replace('\n', ' ')
            print(f"  Preview: {preview}...")
        return

    if args.command == 'technique':
        idx = get_index()
        ctx = idx.get_technique_context(args.action_name)
        if ctx:
            print(ctx)
        else:
            print(f"No technique context found for: {args.action_name}")
        return

    if args.command == 'failure':
        idx = get_index()
        guidance = idx.get_failure_guidance(args.action_name, args.error)
        if guidance:
            print(guidance)
        else:
            print(f"No failure guidance found for: {args.action_name} / {args.error}")
        return

    if args.command == 'alternatives':
        idx = get_index()
        services = None
        if args.services:
            services = []
            for pair in args.services.split(','):
                parts = pair.split(':')
                if len(parts) == 2:
                    services.append((int(parts[0]), parts[1]))
        results = idx.get_alternatives(args.action_name, services=services)
        if not results:
            print("No alternatives found.")
            return
        for i, r in enumerate(results, 1):
            print(f"\n── Alternative {i} [{r['source']}] ──")
            print(f"  {r['heading']}")
            preview = r['text'][:200].replace('\n', ' ')
            print(f"  {preview}...")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
