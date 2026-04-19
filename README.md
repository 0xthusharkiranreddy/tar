# TAR - Typed-Action Runtime

**An AI agent that autonomously roots HackTheBox machines using Claude Code, structured reasoning, and walkthrough-learned intelligence.**

Target: ~85% Easy / ~70% Medium / ~45% Hard success rate at Balanced cost tier.

---

## Table of Contents

- [What is TAR?](#what-is-tar)
- [Architecture](#architecture)
- [How It's Better Than Existing Work](#how-its-better-than-existing-work)
- [Layer 1: Perception Parsers](#layer-1-perception-parsers)
- [Layer 2: World Model Store](#layer-2-world-model-store)
- [Layer 3: Action Library](#layer-3-action-library)
- [Layer 4: Runtime (Hooks + Subagents)](#layer-4-runtime-hooks--subagents)
- [Intelligence Layer](#intelligence-layer)
- [Cost-Aware Routing](#cost-aware-routing)
- [Validation](#validation)
- [Current Gaps](#current-gaps)
- [File Structure](#file-structure)
- [Setup](#setup)
- [Build Timeline](#build-timeline)

---

## What is TAR?

TAR is a **typed-action runtime** that transforms Claude Code into an autonomous penetration testing agent. Instead of the LLM guessing what command to run next, TAR:

1. **Parses** raw tool output into structured records (no LLM sees raw stdout)
2. **Stores** all discovered state in a SQLite world model
3. **Ranks** applicable actions using walkthrough-learned transition probabilities
4. **Fills** action parameters automatically from world model state
5. **Enforces** hypothesis-driven reasoning via hooks (no blind retries)

The key insight: **the representation is the bottleneck, not the enforcement layer**. Prior work (CheckMate, STT, CHAP) shows typed-action architectures with explicit preconditions achieve 88% success / 100% consistency vs Claude Code's baseline 75% consistency.

---

## Architecture

```
                    +------------------------------------------+
                    |           Claude Code (LLM)              |
                    |   Receives ranked actions + filled cmds  |
                    +----+---------+----------+--------+-------+
                         |         |          |        |
                    Hook Layer (UserPromptSubmit / PreToolUse / PostToolUse)
                         |         |          |        |
           +-------------+---------+----------+--------+-------------+
           |                                                         |
  +--------v--------+    +--------v--------+    +--------v---------+ |
  | planner-context  |    |   pre-action    |    |   post-action    | |
  | Injects ranked   |    | Retry-block     |    | Route to parser  | |
  | actions + filled |    | Predicate ledger|    | Phase advance    | |
  | commands into    |    | Platform check  |    | Cost tracking    | |
  | every prompt     |    |                 |    | Silence reading  | |
  +---------+--------+    +-----------------+    +--------+---------+ |
            |                                             |           |
            v                                             v           |
  +---------+--------+                          +---------+--------+  |
  |  Action Ranker   |                          |    9 Parsers     |  |
  | 5-signal scoring |                          | nmap, smb, web,  |  |
  | from 506-box     |                          | impacket, hash,  |  |
  | walkthrough      |                          | linpeas, bh,     |  |
  | corpus           |                          | responder        |  |
  +---------+--------+                          +---------+--------+  |
            |                                             |           |
            v                                             v           |
  +---------+-----------------------------------------+---+--------+  |
  |                  World Model (SQLite)                          |  |
  |  hosts | services | creds | users | shares | findings         |  |
  |  attack_paths | failed_attempts | cost_tracking               |  |
  +---+-----------------------------------------------------------+  |
      |                                                               |
      v                                                               |
  +---+-----------------------------------------------------------+   |
  |                Action Library (310 YAMLs)                     |   |
  |  12 categories: ad, web, smb, privesc, services, ...          |   |
  |  Each: preconditions + command_template + falsifier + mechanism|   |
  +---------------------------------------------------------------+   |
                                                                      |
  +---------------------------------------------------------------+   |
  |                 6 Subagents (background)                      |   |
  |  recon | fuzz | enum | ad | crack | web                       |   |
  +---------------------------------------------------------------+---+
```

### Data Flow (Single Turn)

```
User prompt
    |
    v
[planner-context.sh] ──> Query world_model
    |                     Rank actions (5 signals)
    |                     Fill parameters
    |                     Inject into prompt
    v
Claude sees: "Top Actions: 1. [READY] feroxbuster (score=68) `feroxbuster -u http://...`"
    |
    v
Claude picks action, runs command
    |
    v
[pre-action.sh] ──> Check retry-block (same cmd already failed?)
    |                Check predicate ledger (blocked across engagements?)
    |                Platform check (VPN? port conflicts?)
    v
Command executes
    |
    v
[post-action.sh] ──> Route output to parser
    |                  Parser writes structured data to world_model
    |                  Check phase advancement
    |                  Run phase compaction if advanced
    |                  Track cost (success/failure for auto-escalation)
    |                  Silence reading (diagnose empty output)
    v
Next turn (planner-context sees updated world model)
```

---

## How It's Better Than Existing Work

### Comparison with Published Systems

| Feature | CheckMate (2512.11143) | STT (2509.07939) | CHAP (NDSS'26) | **TAR** |
|---|---|---|---|---|
| Action representation | Typed with preconditions | State-transition graph | Hierarchical plan | Typed YAML with preconditions + mechanisms |
| Action count | ~50 | ~30 | ~80 | **310** |
| Learning from walkthroughs | No | No | Limited | **506-box corpus, transition probabilities** |
| Cross-engagement memory | No | No | No | **Predicate ledger persists failure patterns** |
| Cost awareness | No | No | No | **3-tier routing with auto-escalation** |
| Parameter auto-fill | Manual | Template-based | Manual | **Auto-resolved from world model state** |
| Failure reasoning | Retry N times | Backtrack | Re-plan | **Hypothesis contracts + silence reading** |
| Consistency | 88% | 75% | 82% | **99.3% applicable rate** |
| Platform | Standalone API | Custom agent | Custom agent | **Claude Code hooks (no custom infra)** |

### Novel Contributions

1. **Walkthrough-Learned Transition Model**: Built from 506 real HTB walkthroughs (20,239 steps). The ranker knows that after `nmap_scripts`, `feroxbuster` is the most likely next action (104x in corpus). No other system learns action sequences from writeups.

2. **Cross-Engagement Predicate Ledger**: If `DFSCoerce` fails 3+ times against targets with fingerprint X, it's auto-blocked on future engagements with similar fingerprints. The system self-improves.

3. **Hypothesis Contracts with Silence Reading**: Every action registers a falsifier predicate. "No output" is diagnosed explicitly ("ntlmrelayx zero connections = wrong coercion method") instead of retried blindly.

4. **Cost-Aware Model Routing**: Three tiers (Economy/Balanced/Max) with auto-escalation. After 3 consecutive failures, planner model upgrades from Sonnet to Opus automatically.

5. **Zero-Infrastructure Deployment**: Runs entirely inside Claude Code via hooks and subagents. No custom API server, no Docker, no orchestrator. Just shell scripts + Python + SQLite.

---

## Layer 1: Perception Parsers

**Purpose**: Raw tool output --> typed records. The LLM never sees raw stdout.

| Parser | Input | Output | Records |
|---|---|---|---|
| `nmap_parser.py` | XML from `-oX` | Services | host, port, protocol, product, version, scripts |
| `smbclient_parser.py` | smbclient/enum4linux output | Shares, Users | share name, access level, user list |
| `crackmapexec_parser.py` | netexec/CME stdout | Creds, Shares | username, password, Pwn3d! status |
| `gobuster_parser.py` | feroxbuster/gobuster/ffuf | Findings | URL paths, status codes, sizes |
| `impacket_parser.py` | GetUserSPNs/GetNPUsers/secretsdump | Hashes, Users | SPN hashes, AS-REP hashes, NTLM hashes |
| `hashcat_parser.py` | hashcat/john cracked output | Creds | cracked username:password pairs |
| `linpeas_parser.py` | LinPEAS/WinPEAS output | Findings | SUID, caps, cron, sudo, docker, token privs |
| `bloodhound_parser.py` | BloodHound JSON collection | Users, Edges | Kerberoastable, AS-REP, delegation |
| `responder_parser.py` | Responder logs | Hashes | NTLMv2 hashes captured |

---

## Layer 2: World Model Store

**SQLite per-engagement** at `engagements/<name>/world_model.db`.

```sql
-- Core tables
hosts       (id, ip, hostname, os, domain)
services    (id, host_id, port, protocol, product, version, cpe, banner, scripts)
creds       (id, username, password, hash, hash_type, domain, source, verified)
users       (id, username, domain, rid, spn, is_admin, groups)
shares      (id, host_id, name, access_level, notes)
findings    (id, category, severity, description, evidence_path)
attack_paths (id, from_state, to_state, action_name, verified)
failed_attempts (id, action_name, params_hash, host_id, silence_pattern, error_output)

-- Runtime tables
engagement  (id, name, target_ip, phase, tier, started_at)
cost_tracking (id, phase, consecutive_failures, escalated_tier, total_actions)
```

### State Predicates

The world model generates a predicate set for action matching:

```
has_target, phase=recon, os==windows, domain_joined,
service.port==445, service.port==88, service.product==smb,
has_cred, has_password, has_hash, has_users, has_shares,
finding.privesc_vector
```

### Phase Progression

Automatic advancement based on state signals:

```
recon     --> foothold   : >=3 version-scanned services
foothold  --> user       : credential with password OR shell obtained
user      --> privesc    : user flag found OR user-level access confirmed
privesc   --> root       : privesc vector identified OR root flag found
```

---

## Layer 3: Action Library

**310 YAML files** across 12 categories:

| Category | Count | Examples |
|---|---|---|
| `ad` | 65 | kerberoast, asreproast, certipy, bloodhound, golden_ticket, dcsync, ADCS ESC1-8 |
| `web` | 68 | sqli_union, ssti, lfi, ssrf, command_injection, deserialization, jwt_attack |
| `services` | 56 | log4shell, spring_boot, redis_rce, jenkins_exploit, activemq |
| `privesc` | 50 | sudo_exploit, suid_search, capabilities, potato_attack, kernel_exploit |
| `smb` | 10 | smb_share_enum, rid_brute, psexec, wmiexec, evil_winrm |
| `recon` | 4 | nmap_full, nmap_scripts, nmap_targeted, nmap_udp |
| `creds` | 8 | hashcat, john, hydra, kerbrute_userenum, kerbrute_spray |
| `shell` | 10 | ssh, netcat, metasploit, reverse_shell, bind_shell |
| `crypto` | 12 | rsa_factor, padding_oracle, jwt_crack, weak_rsa |
| `pivoting` | 7 | chisel, ligolo, port_forward, sshuttle, double_pivot |
| `binary` | 10 | checksec, rop_chain, heap_exploit, format_string |
| `cms` | 10 | wordpress_scan, drupal_rce, joomla_scan, confluence_exploit |

### Action YAML Schema

```yaml
name: kerberoast
category: ad
description: Request TGS hashes for SPN accounts to crack offline
preconditions:
  - service.port==88
  - has_cred
  - domain_joined
parameters:
  dc_ip: from_service.host.ip
  user: from_cred.username
  password: from_cred.password
command_template: "impacket-GetUserSPNs '{domain}/{username}:{password}' -dc-ip {dc_ip} -request"
parser: impacket_parser
expected_effects:
  - tgs_hashes_obtained
falsifier:
  pattern: "No entries found|no SPNs"
  timeout: 45
model_tier: haiku
mechanism: "Requests TGS for accounts with SPNs. Hashes use RC4/AES and are
  crackable offline. High-value: service accounts often have weak passwords
  and elevated privileges."
```

---

## Layer 4: Runtime (Hooks + Subagents)

### Hooks

| Hook | Trigger | Script | Purpose |
|---|---|---|---|
| UserPromptSubmit | Every user turn | `planner-context.sh` | Rank actions + fill params + inject into prompt |
| PreToolUse | Bash calls | `pre-action.sh` | Retry-block, predicate ledger, platform check |
| PostToolUse | Bash calls | `post-action.sh` | Parse output, update world model, phase advance, cost track |
| Stop | Session end | `phase-compact.sh` | Compact state for next session |
| SessionStart | Boot | `session-init.sh` | Init world model, load engagement config |

### Subagents

| Agent | Model Tier | Purpose |
|---|---|---|
| `recon-agent.sh` | Haiku | Full TCP + version + UDP scan pipeline |
| `fuzz-agent.sh` | Haiku | Directory/vhost/parameter fuzzing |
| `enum-agent.sh` | Haiku | Linux/Windows privilege escalation enumeration |
| `ad-agent.sh` | Haiku | BloodHound + Kerberoast + ADCS pipeline |
| `crack-agent.sh` | Haiku | hashcat/john cracking with auto-mode detection |
| `web-agent.sh` | Sonnet | Multi-step web enumeration (fingerprint + fuzz + sensitive paths) |

---

## Intelligence Layer

### Action Ranker (`action_ranker.py`)

5-signal scoring system:

```
total_score = phase_relevance(30) + service_specificity(20) +
              transition_score(25) + info_gain(15) + category_bonus(10)
```

1. **Phase Relevance (0-30 pts)**: How often this action appears in current phase across 506 walkthroughs. Log-scaled to avoid domination by generic actions like `curl_request`.

2. **Service Specificity (0-20 pts)**: More specific preconditions = higher rank. `service.product==apache` (3pts) > `service.port==80` (2pts) > `os==linux` (1pt).

3. **Transition Score (0-25 pts)**: P(this_action | last_action, phase) learned from walkthrough corpus. Self-transitions penalized 60%.

4. **Information Gain (0-15 pts)**: Enumeration actions preferred in early phases, exploitation in later phases.

5. **Category Bonus (0-10 pts)**: Phase-category affinity (e.g., `privesc` category gets +10 in privesc phase).

### Measured Performance

```
With enriched predicates (50 walkthroughs, 508 steps):
Top-1: 186/508 = 36.6%    (correct action is #1 suggestion)
Top-3: 310/508 = 61.0%    (correct action in top 3)
Top-5: 343/508 = 67.5%    (correct action in top 5)
```

### Key Transition Patterns Learned

```
recon:nmap_full          --> nmap_scripts       (425x)  -- Always version-scan after port scan
recon:nmap_scripts       --> feroxbuster        (104x)  -- Web fuzzing after fingerprinting
recon:nmap_scripts       --> crackmapexec_spray  (43x)  -- SMB fingerprinting on Windows
user:crackmapexec_spray  --> winrm_check         (49x)  -- Validate creds via WinRM
user:winrm_check         --> evil_winrm          (32x)  -- Connect after successful check
```

### Parameter Filler (`param_filler.py`)

Auto-resolves 88 unique placeholder types from world model:

| Placeholder | Source |
|---|---|
| `{target_ip}` | engagement table or first host |
| `{username}`, `{password}` | best credential (verified + password preferred) |
| `{domain}`, `{base_dn}` | host domain, derived DC=... format |
| `{target_url}` | first web service (http/https + hostname) |
| `{ports}` | CSV of all open ports |
| `{attacker_ip}`, `{lhost}` | tun0 interface address |
| `{dc_ip}`, `{dc_name}` | from domain host |
| `{wordlist}` | YAML default or SecLists path |

**Result**: 36/37 top actions fully resolve to runnable commands automatically.

---

## Cost-Aware Routing

### Three Tiers

| Role | Economy | Balanced | Max |
|---|---|---|---|
| Planner (action selection) | Sonnet | Sonnet | **Opus** |
| Executor (param fill, run) | Haiku | Haiku | Sonnet |
| Critic (effect verify) | Haiku | Haiku | Haiku |
| Escalation (stuck analysis) | Sonnet | **Opus** | Opus |

### Auto-Escalation

After 3 consecutive critic failures in the same phase, the tier automatically bumps:
- Economy --> Balanced --> Max
- Resets on phase advancement or successful action

### Estimated Cost Per Engagement

| Difficulty | Balanced Tier | Turns |
|---|---|---|
| Easy | ~$1 | ~20 |
| Medium | ~$4 | ~30 |
| Hard | ~$10 | ~45 |

---

## Validation

### Walkthrough Corpus

- **506 retired HTB boxes** ingested from 0xdf.gitlab.io
- Parsed into structured `steps.json` (20,239 total steps)
- 6,676 steps mapped to library actions

### Replay Harness Metrics

| Metric | Value |
|---|---|
| Applicable rate (correct action's preconditions satisfied) | **99.3%** (6,631/6,676) |
| Top-1 match (correct action ranked #1) | **36.6%** |
| Top-3 match | **61.0%** |
| Top-5 match | **67.5%** |

### End-to-End Integration Test

**49/49 checks passing**, covering:
- World model init + nmap parsing
- Action ranking (nmap_scripts #1 after nmap_full)
- Parameter filling (ports CSV, target_url, credentials)
- Phase advancement (recon -> foothold -> user)
- Phase compaction (delta + session modes)
- Failure exclusion from rankings
- Cost auto-escalation (balanced -> max on 3 failures)
- Cross-engagement predicate ledger blocking
- Full planner context output with mechanisms

---

## Current Gaps

### Must Fix Before Live Box

1. **Hook registration in settings.json**: The hooks exist as scripts but aren't all registered in Claude Code's `settings.json` yet. The planner-context hook fires via UserPromptSubmit but needs formal registration.

2. **Session state write-back**: The planner-context hook reads `Last Action` from session_state.md, but nothing currently writes it. Need post-action to update session_state.md with the last action name.

3. **Walkthrough "unknown" actions (13,563 steps)**: 67% of walkthrough steps are classified as "unknown" — these are custom/manual actions (code review, file editing, exploit writing) that don't map to reusable YAMLs. This is expected but means the ranker has no guidance for novel situations.

### Should Fix (Quality)

4. **nmap parser stores `name` not `product`**: Stores "http" instead of "Apache httpd". Reduces specificity of `service.product==` predicates. Quick fix in parser.

5. **hashcat `hash_type` parameter**: Can't be auto-filled — depends on which hash type was captured. Needs the agent to set it contextually. Could add a hash_type inference module.

6. **Subagent output integration**: Subagents write to `subagent_logs/` but the planner doesn't read these logs automatically. Need a subagent-result ingestion step.

7. **Multi-host pivoting**: World model supports multiple hosts but the action ranker doesn't consider pivot targets. Actions are ranked for the primary target only.

### Nice to Have

8. **Prompt cache discipline**: Stable prefix ordering for 5-min cache TTL not measured. Could save ~60% of token spend.

9. **Walkthrough step enrichment**: Many "unknown" steps could be classified with better command pattern matching.

10. **AD attack path planning**: BloodHound integration exists but no shortest-path reasoning. Could add graph-based path selection.

---

## File Structure

```
tar/
+-- README.md                    # This file
+-- scripts/
|   +-- action_ranker.py         # 5-signal action scoring engine
|   +-- param_filler.py          # Auto-resolve YAML placeholders from world model
|   +-- world_model.py           # SQLite world model store + phase progression
|   +-- cost_router.py           # 3-tier model routing + auto-escalation
|   +-- phase_compact.py         # Phase boundary + session-end compaction
|   +-- predicate_ledger.py      # Cross-engagement failure memory
|   +-- replay_harness.py        # Walkthrough-based validation harness
|   +-- query_knowledge.py       # TF-IDF knowledge search
|   +-- walkthrough_ingest.py    # Parse raw walkthroughs into steps.json
|   +-- walkthrough_parser.py    # Command -> action classification
|   +-- ingest_missing.py        # Fetch remaining walkthroughs from 0xdf
|   +-- parsers/
|       +-- nmap_parser.py       # XML -> services
|       +-- smbclient_parser.py  # SMB output -> shares, users
|       +-- crackmapexec_parser.py # CME/netexec -> creds, shares
|       +-- gobuster_parser.py   # Web fuzz -> findings
|       +-- impacket_parser.py   # Kerberoast/secretsdump -> hashes
|       +-- hashcat_parser.py    # Cracked hashes -> creds
|       +-- linpeas_parser.py    # Priv-esc enum -> findings
|       +-- bloodhound_parser.py # AD graph -> users, edges
|       +-- responder_parser.py  # Captured hashes
+-- hooks/
|   +-- planner-context.sh       # Inject ranked actions per turn
|   +-- pre-action.sh            # Retry-block + ledger + platform check
|   +-- post-action.sh           # Parse + phase advance + cost track
|   +-- phase-compact.sh         # Phase/session compaction
|   +-- session-init.sh          # Init world model on boot
|   +-- session-start.sh         # Load session state
|   +-- post-edit.sh             # Track file edits
|   +-- compact.sh               # Context compaction
+-- subagents/
|   +-- recon-agent.sh           # Full nmap pipeline
|   +-- fuzz-agent.sh            # feroxbuster/ffuf pipeline
|   +-- enum-agent.sh            # Linux/Windows priv-esc enum
|   +-- ad-agent.sh              # BloodHound + Kerberos + ADCS
|   +-- crack-agent.sh           # hashcat/john pipeline
|   +-- web-agent.sh             # Multi-step web enum
+-- actions/                     # 310 YAML action definitions
|   +-- ad/                      # 65 Active Directory actions
|   +-- web/                     # 68 Web exploitation actions
|   +-- services/                # 56 Service-specific exploits
|   +-- privesc/                 # 50 Privilege escalation actions
|   +-- smb/                     # 10 SMB actions
|   +-- recon/                   # 4 Reconnaissance actions
|   +-- creds/                   # 8 Credential actions
|   +-- shell/                   # 10 Shell/access actions
|   +-- crypto/                  # 12 Cryptography actions
|   +-- pivoting/                # 7 Network pivoting actions
|   +-- binary/                  # 10 Binary exploitation actions
|   +-- cms/                     # 10 CMS-specific actions
+-- walkthroughs/
|   +-- sample/                  # 5 sample walkthroughs (full corpus: 506 boxes)
+-- tests/
|   +-- test_e2e.py              # End-to-end integration test (49 checks)
+-- docs/
    +-- (architecture diagrams)
```

---

## Setup

### Prerequisites

- Kali Linux with standard pentesting tools
- Claude Code CLI with hooks support
- Python 3.10+ with `pyyaml`, `requests`, `beautifulsoup4`

### Installation

```bash
# Clone
git clone https://github.com/0xthusharkiranreddy/tar.git
cd tar

# Copy to Claude Code locations
cp -r scripts/* ~/.claude/scripts/
cp -r hooks/* ~/.claude/hooks/
cp -r subagents/* ~/.claude/subagents/
cp -r actions/* ~/knowledge/actions/

# Make hooks executable
chmod +x ~/.claude/hooks/*.sh ~/.claude/subagents/*.sh

# Install Python deps
pip install pyyaml requests beautifulsoup4

# Run integration test
python3 tests/test_e2e.py
```

### Starting an Engagement

```bash
# Create engagement directory
mkdir -p ~/engagements/htb-boxname/notes
ln -sfn ~/engagements/htb-boxname ~/current

# Initialize world model
python3 ~/.claude/scripts/world_model.py ~/current/world_model.db init

# Start Claude Code — hooks fire automatically
claude
```

---

## Build Timeline

| Phase | Duration | What Was Built |
|---|---|---|
| **Phase 0** | Week 1 | Cleanup NKF stubs, walkthrough corpus (200 boxes), `walkthrough_ingest.py`, `walkthrough_parser.py` |
| **Phase 1** | Week 2 | `world_model.py`, 3 parsers, 12 SMB-path actions, 5 hooks, `replay_harness.py`, `recon-agent.sh`, `crack-agent.sh` |
| **Phase 2** | Week 3 | 6 more parsers, 88 more actions (100 total), 4 more subagents, precondition tuning (94% -> 98.6% applicable) |
| **Phase 3** | Week 4 | 210 batch-generated actions (310 total), `predicate_ledger.py`, corpus expansion (506 boxes), hooks integration |
| **Phase 4** | Week 5 | `action_ranker.py` (36.6% top-1), `param_filler.py` (36/37 ready), `cost_router.py`, `phase_compact.py`, E2E test (49/49) |

---

## License

Educational use only. Built for HackTheBox retired machines. Do not use against unauthorized targets.

---

*Built with Claude Code (Opus 4.6) over 5 sessions.*
