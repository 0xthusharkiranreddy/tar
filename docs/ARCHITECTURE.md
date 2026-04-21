# TAR Architecture

This document explains how TAR is built, layer by layer, and why each layer exists.

Read [`INTELLIGENCE.md`](INTELLIGENCE.md) alongside this document for the *why* behind the design. This file covers the *what* and *how*.

---

## Layered overview

```
          ┌──────────────────────────────────────────────────────────┐
          │                     Claude Code CLI                      │
          │                (the LLM, sees curated ctx)               │
          └──┬──────────────────────────────────────────────────▲────┘
             │ UserPromptSubmit                                  │ ToolResult
             ▼                                                   │
  ┌───────── Hooks ────────────────────────────────────────┐     │
  │ planner-context.sh → injects WM + ranked + mechanism  │     │
  │ pre-action.sh     → prerequisite gate                 │     │
  │ post-action.sh    → parse output → WM                 │     │
  │ phase-compact.sh  → context compaction                │     │
  └──┬──────────────────────────────────────▲─────────────┘     │
     │                                      │ parsers            │
     ▼                                      │                    │
 ┌── Reasoning Engine ────────────┐    ┌── Perception ───┐       │
 │ action_ranker.py               │    │ 13 parsers       │       │
 │ attack_chain_planner.py        │    │ web_response     │       │
 │ param_filler.py                │    │ tech_detect      │       │
 │ technique_advisor.py           │    │ generic          │       │
 │ knowledge_index.py             │    │ nmap, smbclient  │       │
 └──┬──────▲────────────┬─────────┘    │ crackmapexec …   │       │
    │      │            │              └────────▲─────────┘       │
    ▼      │            ▼                       │                 │
 ┌── World Model ─┐  ┌── Action Library ──┐   ┌── Tool runs ──┐   │
 │  SQLite        │  │ 310 YAML actions   │   │ shell cmds    │───┘
 │  10 tables     │  │ (preconditions,    │   │ via Claude    │
 │                │  │  effects, parser,  │   │ Code's Bash   │
 │                │  │  mechanism,        │   │ tool          │
 │                │  │  falsifier)        │   └───────────────┘
 └────────────────┘  └────────────────────┘
                            ▲
                            │ enrichment
         ┌──────────────────────────────────────┐
         │  HackTricks (1,938 MD files)         │
         │  PayloadsAllTheThings (483 files)    │
         │  OCD AD Mindmap 2025.03 (17 branches)│
         │  BloodHound Cypher (15 queries)      │
         │  Local knowledge (183 MD files)      │
         └──────────────────────────────────────┘
                 = 35,878 indexed sections
```

---

## 1. Perception Layer — `scripts/parsers/`

**Purpose**: turn unstructured terminal output into structured facts the world model can store and the ranker can query.

**Contract**: every parser exposes a function that takes raw stdout/stderr and returns a dict with standard keys:

```python
{
    "hosts":     [ {ip, os, hostname, domain}, ... ],
    "services":  [ {host_ip, port, protocol, product, version, banner}, ... ],
    "creds":     [ {username, password, hash, hash_type, domain, source}, ... ],
    "shares":    [ {host_ip, name, access_level}, ... ],
    "users":     [ {username, domain, rid, spn, is_admin}, ... ],
    "findings":  [ {category, severity, description, evidence}, ... ],
    "vulns":     [ {cve_id, component, version, cve_desc}, ... ],
    "detections":[ {component, version, source}, ... ],   # tech_detect only
}
```

| Parser | Handles | Key heuristics |
|---|---|---|
| `nmap_parser.py` | nmap XML/gnmap output | service/version/CPE → WM services |
| `smbclient_parser.py` | smbclient share listings | share + access-level detection |
| `crackmapexec_parser.py` | CME service output | creds, auth results, signing status |
| `gobuster_parser.py` | gobuster / ffuf output | discovered paths → findings |
| `impacket_parser.py` | secretsdump, GetNPUsers, GetUserSPNs | NTLM/Kerberos hashes → creds |
| `hashcat_parser.py` | hashcat cracked output | cracked creds → WM |
| `responder_parser.py` | Responder logs | captured hashes, SMB/HTTP |
| **`web_response_parser.py`** | SQLi, LFI, SSTI, XSS, file-read output | category-classified findings |
| **`tech_detect_parser.py`** | HTTP responses, HTML headers | component+version → CVE match from knowledge index |
| **`generic_parser.py`** | arbitrary command output | NTLM, uid=0, SUID, SUID-root bin, sudo NOPASSWD |

`web_response_parser` flow:
```
input:  "back-end DBMS: MySQL >= 5.0.12\navailable databases [3]:..."
output: findings: [ {category: "sqli", severity: "high", dbms: "MySQL", databases: [...]} ]
```

`tech_detect_parser` bridges directly into `knowledge_index.get_version_vulns()` — any detected `Apache/2.4.49` immediately becomes a CVE-2021-41773 finding, which the ranker then picks up.

---

## 2. World Model — `scripts/world_model.py`

**Purpose**: single typed source-of-truth for everything the agent has learned, so Claude does not re-discover facts across turns.

**SQLite schema** (10 tables):

```
engagement(id, name, target_ip, phase, tier, started_at, updated_at)
hosts(id, ip, hostname, os, domain, added_at)
services(id, host_id, port, protocol, state, product, version, cpe, banner, scripts)
creds(id, username, password, hash, hash_type, domain, source, verified, added_at)
users(id, username, domain, rid, spn, is_admin, groups)
shares(id, host_id, name, access_level, description)
findings(id, host_id, category, severity, description, evidence, added_at)
vulns(id, host_id, service_id, cve_id, component, version, cve_desc)
sessions(id, host_id, user, shell_type, is_privileged, opened_at)
failed_attempts(id, action_name, error_output, silence_pattern, attempted_at)
```

**Key API** (used by the ranker/planner/hooks):

```python
wm.add_service(host_id, port, product, version, …)
wm.add_cred(username, password, hash, domain, source)
wm.add_finding(category, severity, description, evidence)
wm.get_services() / get_creds() / get_hosts() / get_findings()
wm.get_state_predicates()  # → {"has_cred","service.port==445","smb_writable_share", …}
wm.get_failed_attempts()   # for retry-blocking
wm.current_phase()         # derives phase from state (recon → foothold → user → privesc → root)
wm.log_attempt(action_name, success, error_output)
```

**Why SQLite, not JSON?** Typed queries. The ranker needs `SELECT DISTINCT host_id FROM services WHERE port=445 AND product LIKE '%Samba%'` — tractable in SQL, painful over JSON grep. And it survives process restarts (context compaction events).

**Predicates** — the bridge to the planner. Every state query collapses to a set of boolean predicates like `{"has_cred","has_domain_credential","service.port==445","service.port==88","writable_share_found"}`. The chain planner does STRIPS-style reasoning on exactly that predicate set.

---

## 3. Knowledge Layer — `scripts/knowledge_index.py` + `technique_advisor.py`

The knowledge layer was extended in v2.1 to include two strategic sources alongside the original HackTricks/PAT/local corpora:

- **OCD AD Red Teaming Mindmap** (`mindmaps/ocd_ad_2025.md`) — 17 branches, ~150 techniques. Weighted 1.1× on methodology queries: it's the operator decision tree, not a per-technique reference.
- **BloodHound Cypher library** (`cypher/*.cypher`) — 15 canonical queries indexed as markdown-equivalent sections. Each query's header comment states its precondition and produced predicate.

These give the planner a *what to try next* signal that's orthogonal to HackTricks' *how does this work* signal.

### 3.1 Knowledge Index

**Purpose**: fast, scored lookup over the entire HackTricks + PAT + local knowledge corpus.

**Build process**:
1. Walk `SOURCES` dirs: `/home/kali/hacktricks/src/`, `/home/kali/PayloadsAllTheThings/`, `/home/kali/knowledge/`
2. For each markdown file, split on `#`-level headings into sections (heading + body + code blocks)
3. Tokenise (lowercase, strip markdown, split on non-alphanumeric)
4. Build document-frequency table, compute TF-IDF per (section, token)
5. Build **inverted token index**: `token_index[tok] = [section_ids]` — critical for sub-second lookup at 35k scale
6. Pickle to `/tmp/tar_knowledge_index.pkl` (version-stamped), invalidated on source mtime change

**Query API**:

```python
ki = get_index()                                     # 0.4s warm, 2.4s cold
ki.search("kerberoast", top_n=5)                     # TF-IDF top sections
ki.get_technique_context("kerberoast", max_chars=1500)  # cached per-technique excerpt
ki.get_version_vulns("Apache", "2.4.49")             # CVE matching via structured patterns
ki.get_alternatives("kerberoast", services=[(445,"Samba"),(389,"LDAP")])
ki.get_failure_guidance("kerberoast", "No entries found")
```

Source-weighted scoring: HackTricks technique sections carry 2× weight over raw walkthrough mentions for technique lookups. Version CVE matching uses regex patterns over section bodies for common `Component x.y.z → CVE-YYYY-NNNNN` text.

**Per-process caches**:
- `_tc_cache[(action_name, max_chars)]` — memoises `get_technique_context`
- `_vv_cache[(product, version)]` — memoises `get_version_vulns`
- Token-index shortlist — candidate sections narrowed from 35k to typically <200 before scoring

### 3.2 Technique Advisor

**Purpose**: translate generic knowledge sections into *action-specific* guidance.

Curated `TECHNIQUE_RULES` for 40+ techniques, each providing:

```python
{
    "prerequisites": ["valid domain credential", "SPN users in domain", "port 88 reachable"],
    "failure_patterns": {
        "No entries found": "no SPN users; try asreproast or rbcd",
        "KDC_ERR_PREAUTH_FAILED": "credential is wrong; check username case",
        "KDC_ERR_S_PRINCIPAL_UNKNOWN": "target SPN doesn't exist; re-enumerate",
    },
    "adaptations": {
        "python|flask": "SSTI engine: try Jinja2 payloads first",
        "ruby|rails":   "SSTI engine: try ERB payloads",
    },
    "mechanism_brief": "Kerberoast requests TGS for SPN users; the TGS is encrypted with the service account's NTLM hash, so capturing it gives an offline crack target..."
}
```

API:
```python
advisor.get_prerequisites(action_name) → List[str]
advisor.get_failure_interpretation(action_name, error_output) → str
advisor.suggest_adaptation(action_name, target_profile) → dict
advisor.get_mechanism_brief(action_name) → str  # 2-3 sentence HackTricks excerpt
```

---

## 4. Action Library — `actions/`

**Purpose**: the deterministic vocabulary the agent speaks in. Every action is declarative YAML, not procedural code — the ranker/planner reason over them as typed objects.

**Schema** (all 356 actions conform):

```yaml
name: kerberoast
category: ad
description: Request TGS tickets for SPN users and extract crackable hashes
mechanism: |
  Kerberos allows any authenticated principal to request a service ticket (TGS)
  for any SPN. The TGS is encrypted with the service account's NTLM hash, so
  offline cracking of the TGS yields the service account password. Requires any
  valid domain credential. Output hashes are $krb5tgs$ format crackable with
  hashcat mode 13100.

command_template: >
  GetUserSPNs.py -request -dc-ip {dc_ip}
  {domain}/{username}:{password} -outputfile {hash_file}

parameters:
  dc_ip: from_engagement.target_ip
  domain: from_engagement.domain
  username: from_engagement.creds.domain_user
  password: from_engagement.creds.domain_password
  hash_file: /tmp/kerberoast.hashes

preconditions:
  - has_domain_credential
  - service.port==88
  - service.port==389

expected_effects:
  - tgs_hashes_obtained
  - has_hash

falsifier: "No entries|KDC_ERR_S_PRINCIPAL_UNKNOWN|KDC_ERR_PREAUTH_FAILED"
parser: impacket_parser

references:
  hacktricks: windows-hardening/active-directory-methodology/kerberoast
  pat: Methodology/Active-Directory/Kerberoasting
```

**Coverage across the 356 actions**:

| Category | Count | Examples |
|---|---:|---|
| web | 68 | sqli, ssti, lfi, xxe, xss, ssrf, graphql_probe, log4shell, shellshock |
| ad | 65 | kerberoast, asreproast, dcsync, adcs_esc1..esc11, certipy variants, coerce |
| services | 56 | ssh_enum, rdp_check, mssql_xp_cmdshell, postgres_copy, redis_config_write |
| privesc | 50 | suid_abuse, pkexec, polkit_cve, dirty_cow, potato chain, python_library_hijack |
| crypto | 12 | hashcat modes, john rulesets, padding_oracle, weak_rsa |
| cms | 10 | wp_scan, joomla, drupal_druppalgeddon |
| smb | 10 | smb_enum, smb_null, petitpotam, printnightmare |
| binary | 10 | rop_chain, buffer_overflow, format_string, ghidra_analyse |
| shell | 10 | reverse_tcp, bind_shell, pty_upgrade |
| creds | 8 | password_spray, username_enum |
| pivoting | 7 | chisel, ligolo, proxychains, sshuttle |
| recon | 4 | nmap_scripts, masscan, full_portscan |

**Enrichment pipeline** (`enrich_actions.py` + `enrich_effects.py`):
- `enrich_actions.py` assigns parsers via pattern rules (~200 rules → 310/310 parser coverage), upgrades generic `error|failed` falsifiers to technique-specific patterns from HackTricks
- `enrich_effects.py` replaces generic `action_completed` effects with meaningful predicates (e.g., `kerberoast → [tgs_hashes_obtained, has_hash]`) so the chain planner can reason about state transitions

---

## 5. Reasoning Engine

### 5.1 `action_ranker.py` — 5-signal scoring

```python
score = knowledge_score  * 30    # HackTricks match for service+product
      + precondition_score * 25  # deep prerequisite validation via TechniqueAdvisor
      + service_score     * 20   # port+product matches
      + info_gain_score   * 15   # new predicates this action produces
      + transition_score  * 10   # walkthrough P(next|last) [demoted]
      - retry_penalty            # recent-failure block
      - cross_engagement_block   # predicate ledger says "we've seen this fail before"
```

v1 weighted walkthrough transitions at 25 points. v2 drops it to 10 and moves the 15-point delta onto knowledge and preconditions — which is the single most important code change in the codebase. Full rationale in [`INTELLIGENCE.md`](INTELLIGENCE.md).

**Cache strategy**: `_actions_cache` with mtime invalidation. On hot path (hook fires every user turn), action YAMLs are loaded once per process.

### 5.2 `attack_chain_planner.py` — STRIPS forward-chaining BFS

```
Input:  initial_state = WM predicate set
        goal          = "domain_admin" (one of 9 named goals)
        actions       = 310 YAML actions, each with preconditions + effects
        max_depth     = 4

Algo:   BFS; at each node, try every action whose preconditions ⊆ state,
        apply its effects to produce new_state, continue until goal ⊆ state.

Output: ordered list of actions (the plan), or None if unreachable, or []
        if goal already satisfied.
```

**Goal table**:
```python
GOALS = {
    "initial_foothold":  {"shell_obtained"},
    "credential_access": {"has_cred"},
    "user_flag":         {"user_flag_obtained"},
    "root_access":       {"root_shell"},
    "system_access":     {"system_shell"},
    "domain_user":       {"has_cred", "domain_joined"},
    "domain_admin":      {"domain_admin"},
    "lateral_movement":  {"shell_on_new_host"},
    "persistence":       {"backdoor_installed"},
}
```

**Effect aliases** normalise synonyms (`ntlm_hashes_obtained`, `tgs_hashes_obtained`, `hashes_dumped` → `has_hash`) so actions with different wording still chain cleanly.

Example: given WM state `{service.port==80, service.port==445}`, the planner outputs a 3-step chain like `[ffuf_dir_bust → sqli_probe → secretsdump_via_rce]` toward `root_access`. Integrated into the planner-context hook so Claude sees a *suggested path* alongside the top-ranked single actions.

### 5.3 `param_filler.py` — technique-aware parameter resolution

Resolves YAML placeholders (`{username}`, `{target_ip}`, `{domain}`, `{wordlist}`) from WM state. Technique-aware selection:

- DCSync / secretsdump → admin creds
- Kerberoast / ASREPRoast → any domain user
- PSExec → local admin (explicit filter)
- PtH actions → hash-only creds
- Web enum → `seclists/Discovery/Web-Content/raft-medium-directories.txt`
- Password spray → `rockyou.txt` or top-1M

Cached `_action_map` → O(1) action lookup across the 310-action library.

---

## 6. Runtime Hooks — `hooks/`

Claude Code fires hooks at specific lifecycle events. TAR uses 8:

| Hook | Event | Purpose |
|---|---|---|
| `session-start.sh` | Start | Load world model, kick off recon subagent |
| `session-init.sh` | Per-session | Restore cached knowledge index |
| `planner-context.sh` | `UserPromptSubmit` | **Inject WM + ranked actions + mechanism + chain plan** |
| `pre-action.sh` | `PreToolUse` (Bash) | Prerequisite gate; block if missing |
| `post-action.sh` | `PostToolUse` (Bash) | Parse output → WM update |
| `post-edit.sh` | `PostToolUse` (Write/Edit) | Log edit, update state timestamp |
| `phase-compact.sh` | Near-budget | Phase compaction |
| `compact.sh` | `Compact` | Persist compaction snapshot |

`planner-context.sh` is the main integration point. Its output is what Claude sees at the top of every turn:

```
## TAR World State
Phase: foothold
Services: 80/Apache, 445/Samba, 88/Kerberos
[!] Apache 2.4.49: see CVE-2021-41773 path traversal
Creds: lowpriv@HTB.LOCAL(pw)

## Top Actions (phase=foothold, last=nmap_scripts)
 1. [READY] **apache_path_traversal** (web, score=87)
    CVE-2021-41773: /cgi-bin path traversal + mod_cgi RCE
    `curl --path-as-is http://10.10.10.100/cgi-bin/.%2e/…`
    Mechanism: Apache 2.4.49 fails to normalise %2e in URL paths; when
    mod_cgi is enabled, an attacker can read arbitrary files and, via
    traversal into /bin/sh, achieve RCE.

 2. [READY] **kerberoast** (ad, score=72)
    ...

## Suggested Chain → root_access (3 steps)
  1. [web] **apache_path_traversal** → rce_achieved, shell_obtained
  2. [privesc] **linux_suid_enum** → suid_found
  3. [privesc] **suid_exploit** → root_shell

## Failure Analysis
- **smb_null_session** failed: STATUS_ACCESS_DENIED
  → Null session disabled; try guest auth or captured-cred enum
```

---

## 7. Tests — `scripts/tests/test_v2_integration.py`

35 integration checks across 9 sections:

1. **Knowledge Index** — search returns results, get_technique_context labels source, get_version_vulns catches Apache 2.4.49, cache hot-path under 5ms
2. **Technique Advisor** — kerberoast prereqs present, failure interpretation usable, mechanism brief non-empty, SSTI adaptation returns Jinja2
3. **Action Ranker** — returns sorted list, Apache+SMB+creds produces credible plan
4. **Attack Chain Planner** — loads 356 actions, already-satisfied returns [], unreachable returns None, reachable finds plan, WM→predicates extraction works
5. **Web Response Parser** — SQLi/LFI/SSTI detection
6. **Tech Detect Parser** — Apache CVE-2021-41773, WordPress detection
7. **Generic Parser** — NTLM hash, uid=0, SUID
8. **Parser Coverage** — 310/356 actions have parser assigned
9. **Hook Latency** — planner-context.sh runs under 5s, output contains world state + ranked actions

Run:
```bash
python3 scripts/tests/test_v2_integration.py
# → RESULTS: 35 passed, 0 failed
```

---

## What this architecture rejects

- **Self-supervised exploration** — we do not let the LLM "just try things". Every action passes through the ranker, prerequisite gate, and falsifier.
- **Retry loops** — `failed_attempts` + cross-engagement predicate ledger. If an approach failed in a WM state it is scored to zero next time.
- **Unbounded context growth** — phase compaction compresses completed phases to a summary + WM snapshot. Fresh phases inherit full context.
- **Black-box scoring** — every ranking output is explainable: `score = 30 (knowledge: CVE-2021-41773 match) + 25 (precondition: apache_detected) + 20 (service: port 80) + 15 (info_gain: new_shell_predicate) + 10 (transition: nmap→exploit).`
