# The Intelligence & Reasoning Layer

How TAR's reasoning is constructed so the agent operates like an expert pentester rather than a pattern-matching chatbot.

This document is the answer to *"how do you make an LLM agent actually think like a red teamer?"* — and it is the most opinionated file in the repo. If you read one doc, read this one.

---

## The problem we're solving

An expert human pentester, dropped into a black-box target, goes through a loop that looks roughly like this:

```
1. Observe      → what services/versions/banners are there?
2. Hypothesise  → "given Apache 2.4.49, this is probably CVE-2021-41773"
3. Recall       → "CVE-2021-41773 is a path-traversal, exploitable via %2e, requires
                   mod_cgi enabled for RCE — confirm with GET /cgi-bin/... first"
4. Falsify      → craft a command whose *output pattern* will tell them whether the
                   hypothesis is true or false
5. Execute      → run exactly one attempt
6. Update       → if falsified, what did the silence/error actually teach us?
7. Repeat from step 2 with sharper hypothesis
```

Two properties are load-bearing:

- **Mechanism-level recall.** They don't remember a playbook. They remember *how the vulnerability works*, then derive the command. That's what makes them generalise — they can adapt the technique to a novel environment that isn't in any writeup.
- **Falsification discipline.** Every command is paired with a specific expectation. No expectation → no learning → retry-loop → context burn.

An LLM agent that doesn't replicate these two properties will look impressive in a demo and fail on novel targets. That is the gap TAR is designed to close.

---

## The single biggest design shift: knowledge-first scoring

TAR v1 ranked candidate actions with a scoring function dominated by walkthrough statistics. Given `last_action = nmap_scripts`, it computed `P(next | last_action, phase)` over a corpus of HackTheBox walkthroughs and picked the next action with the highest posterior.

This works until it doesn't. It works on boxes that look like the corpus. It fails on:

- Boxes where the vulnerable version is known but the specific CVE isn't in a writeup
- Boxes where the writeups solve it one way but a different path is easier given our current WM state
- Any variation the corpus doesn't cover (e.g., a rare CMS, a custom service, an unusual port assignment)

**v2 rewrites the scoring function to put knowledge first.**

| Signal | v1 weight | v2 weight | Source |
|---|---:|---:|---|
| Walkthrough transition `P(next\|last)` | 25 | **10** | corpus |
| Service specificity (port + product match) | 20 | 20 | WM + action YAML |
| Information gain (new predicates produced) | 15 | 15 | action effects |
| Precondition match (simple) | 15 | — | — |
| **Deep prerequisite validation (via TechniqueAdvisor)** | — | **25** | HackTricks |
| **Knowledge match (version-CVE, technique in HackTricks)** | — | **30** | KnowledgeIndex |

The shift is not just arithmetic. It means:

1. **An Apache 2.4.49 detection immediately surfaces CVE-2021-41773 as the top action**, even if no walkthrough in the corpus mentions it — because `knowledge_index.get_version_vulns("Apache", "2.4.49")` returns the CVE section and `ranker.knowledge_score()` assigns the full 30 points.
2. **Actions whose *deep* prerequisites are unmet are scored to zero, not merely penalised.** `certipy` without an ADCS CA in WM is not low-scored — it is blocked, because `TechniqueAdvisor.get_prerequisites("certipy")` returns `["adcs_ca_detected", "domain_credential"]` and the WM lacks the first.
3. **Walkthrough statistics become a tie-breaker, not a driver.** Two actions scoring 75 and 72 on knowledge/preconditions/service may be re-ordered by walkthrough-P, but no action with a low knowledge score can out-rank one with a high knowledge score on corpus frequency alone.

That single re-weighting is the most consequential line of code in the repo.

---

## The cognition loop — enforced in the hook output

The TAR planner-context hook reproduces the expert cognition loop on every user turn. It tells Claude, in order:

1. **State**: what do we know (WM)?
2. **Ranked hypotheses**: what should we try next, with per-action mechanism?
3. **Chain plan**: what's the multi-step path to the current phase goal?
4. **Failure analysis**: what recent failures teach us, with HackTricks interpretation?
5. **Alternatives**: if stuck, what else could we try from HackTricks/PAT?

Claude's system prompt (inherited from CLAUDE.md) then enforces that before each action cluster, it writes:

```
Hypothesis: [what I believe is true about the target right now]
Action:     [what I'm about to run and the mechanism it exploits]
Falsifier:  [what output would prove my hypothesis wrong]
```

Every YAML action carries a `falsifier` field — e.g., `kerberoast: "No entries|KDC_ERR_S_PRINCIPAL_UNKNOWN"`. When the post-action hook parses the output, if the falsifier matches, the action is marked failed and written to `failed_attempts`, and the *silence pattern* is extracted for the next turn's failure-analysis block.

This loop is designed to make retry-loops structurally impossible:

- A command run three times is a bug in the reasoning, not the target
- Each failure adds a predicate the ranker uses to suppress the same approach next time
- The cross-engagement predicate ledger (`predicate_ledger.py`) carries those predicates across engagements: if `smb_null_session → blocked` failed on the last three boxes with port 445 + Windows 2019, it is suppressed on this box too

---

## Knowledge injection: four points, four questions

Every injection point answers a specific question an expert would ask themselves.

### Injection 1 — Technique context for top-ranked actions

*"How does this technique actually work?"*

For the top-3 ranked actions on every turn, the hook queries `technique_advisor.get_mechanism_brief()` and injects a 2-3 line excerpt from HackTricks. Not the YAML's one-liner description — the actual HackTricks section body, trimmed to 150 chars.

```
 1. [READY] **kerberoast** (ad, score=72)
    Request TGS tickets for SPN users and extract crackable hashes
    `GetUserSPNs.py -request -dc-ip 10.10.10.100 HTB.LOCAL/lowpriv:P@ss...`
    Mechanism: Kerberos allows any authenticated principal to request a
    service ticket (TGS) for any SPN. The TGS is encrypted with the
    service account's NTLM hash, so offline cracking yields...
```

This is what lets Claude *reason about* the next step instead of just executing it. "Mechanism" is the difference between "run kerberoast" and "request TGS for spn_user because the service-account hash encrypts the reply — so the domain needs at least one SPN-bearing user, else we'll get KDC_ERR_S_PRINCIPAL_UNKNOWN and should pivot to asreproast instead."

### Injection 2 — Version-CVE matching

*"Is this version known-vulnerable?"*

When the WM contains a service with product+version, `knowledge_index.get_version_vulns(product, version)` scans the HackTricks index for sections that match `Component X.Y.Z`-style text and returns any CVE references.

```python
ki.get_version_vulns("Apache", "2.4.49")
# → [{"heading": "Apache 2.4.49 path traversal", "cve_desc": "CVE-2021-41773", "section": "..."}]
```

This is surfaced in two places:
- The World State block: `[!] Apache 2.4.49: see CVE-2021-41773 path traversal`
- The ranker's `knowledge_score` — which gets the full 30 points if a version CVE matches one of the action's aliases

A human pentester wouldn't need to look up "Apache 2.4.49 CVE" on first sight of that banner — they know it. TAR gets the same effect from the knowledge index.

### Injection 3 — Failure interpretation

*"What does this failure actually mean?"*

When an action fails (falsifier matched, or non-zero exit, or silence), the failure-analysis block injects a mapped HackTricks interpretation:

```
## Failure Analysis
- **kerberoast** failed: No entries found
  → No SPN-bearing users in this domain. Try asreproast (pre-auth
    disabled accounts) or rbcd (Resource-Based Constrained Delegation).
```

Interpretation comes from `technique_advisor.get_failure_interpretation(action_name, silence_pattern)`, which consults a curated `TECHNIQUE_RULES` map — entries hand-derived from the HackTricks section for each technique. For uncurated techniques it falls back to TF-IDF search on the knowledge index using the error string as the query.

This is the hook that kills retry loops. If kerberoast comes back with "No entries found", the very next turn Claude sees "no SPN users, try asreproast" — and it changes hypothesis rather than re-running the same command.

### Injection 4 — Alternatives when stuck

*"What else could I try?"*

When ≥2 consecutive actions fail, the hook detects "stuck" and calls `knowledge_index.get_alternatives(last_failed_action, services=[...])`. This returns HackTricks/PAT sections that mention the target services but aren't the same action.

```
## Alternative Approaches (from HackTricks/PAT)
- **Guest authentication with empty password** [HackTricks]: Some SMB shares
  allow `smbclient //host/share -N` when anonymous is disabled...
- **SNMP community string enumeration** [PAT]: If UDP 161 is open, snmpwalk
  with "public"/"private" often returns share names and mapped users...
```

This mimics how a human operator, after two failed SMB attempts, flips to a completely different angle rather than tuning parameters.

---

## The chain planner — multi-step reasoning

`attack_chain_planner.py` is STRIPS-style forward-chaining BFS over action preconditions and effects. It reproduces the expert's ability to answer *"how do I get from here to domain admin?"* with a concrete multi-step plan.

**Algorithm**:
```
frontier = [(initial_state, [])]
visited  = {initial_state}

while frontier:
    state, plan = frontier.popleft()
    if len(plan) >= max_depth: continue
    for action in actions:
        if not action.preconditions ⊆ state: continue
        new_state = state ∪ action.effects
        if new_state == state: continue        # no-op action
        if new_state in visited: continue
        if goal ⊆ new_state: return plan + [action]
        frontier.append((new_state, plan + [action]))
        visited.add(new_state)
return None   # unreachable within depth
```

**Goal catalogue** (17 named goals as of v2.1): `initial_foothold`, `credential_access`, `user_flag`, `root_access`, `system_access`, `domain_user`, `domain_admin`, `lateral_movement`, `persistence`, plus v2.1 additions `cross_forest_compromise`, `sccm_compromise`, `domain_persistence`, `hybrid_cloud_compromise`, `adcs_compromise`, `coerced_relay_chain`, `credential_extraction_onhost`. The new goals come directly from OCD mindmap branches, and the EFFECT_ALIASES table was extended so action effects like `trust_key_extracted → trust_key_used` or `sccm_site_db_sysadmin → sccm_admin` collapse cleanly during forward-chaining.

**Effect normalisation** (`EFFECT_ALIASES`) collapses synonyms across the action library so actions with differently-worded effects still chain. Without this, `tgs_hashes_obtained`, `ntlm_hashes_obtained`, and `hashes_dumped` would all fail to unify with a `has_hash` precondition, and the planner would collapse.

**Why BFS not A\***: at depth 4, the branching factor is tractable (on the order of 50-100 applicable actions per state after precondition filtering). A\* would need a good heuristic and we don't yet have one — shortest-action-count is itself a reasonable heuristic for "next tactical move", so BFS with explicit depth limit is the right tradeoff for v2. A\* with a learned heuristic is on the roadmap.

The planner output appears in the hook as:

```
## Suggested Chain → root_access (3 steps)
  1. [web] **apache_path_traversal** → rce_achieved, shell_obtained
  2. [privesc] **linux_suid_enum** → suid_found
  3. [privesc] **suid_exploit** → root_shell
```

Claude sees this alongside the single-action ranking. It can follow the chain, deviate intelligently (if a new finding suggests a shortcut), or reject it and propose a different plan — but it now has a *baseline trajectory* to reason against.

---

## Technique adaptation — the PAT layer

An expert doesn't just know "SSTI". They know *Jinja2 SSTI uses `{{...}}`, Mako uses `<%...%>`, Twig uses `{{...}}` but with different filters, ERB uses `<%=...%>`*. They pick the variant from evidence (response headers, framework fingerprint).

`technique_advisor.suggest_adaptation(action_name, target_profile)` implements this:

```python
adv.suggest_adaptation("ssti", target_profile={"tech": ["python", "flask"]})
# → {"engine": "Jinja2", "payloads": ["{{7*7}}", "{{config.items()}}",
#                                      "{{''.__class__.__mro__[1].__subclasses__()}}"]}

adv.suggest_adaptation("sqli", target_profile={"dbms": "mssql"})
# → {"injection": "UNION-based", "payloads": ["' UNION SELECT @@version--",
#                                               "'; EXEC xp_cmdshell('whoami')--"]}

adv.suggest_adaptation("deserialization", target_profile={"tech": ["java", "jackson"]})
# → {"gadget_chain": "CommonsBeanutils1", "tool": "ysoserial"}
```

Backed by PAT's per-technique directories, which are specifically organised by variant. TAR indexes the PAT README + top-level category files and maps target-profile attributes to variant selection.

---

## Prerequisite gating — hard blocks, not score penalties

An expert does not run `certipy find` against a domain when they haven't even enumerated whether ADCS exists. TAR enforces this structurally:

```
PreToolUse (Bash) fires → pre-action.sh reads the intended command
       ↓
Match command to action (fuzzy name match against YAML library)
       ↓
technique_advisor.get_prerequisites(action_name)
       ↓
For each prerequisite, check against WM predicates
       ↓
If any missing: block with explanation + what to do instead
```

Example block:
```
[pre-action] BLOCKED: certipy_find
  Missing prerequisite: adcs_ca_detected
  What this means: No AD Certificate Authority has been enumerated in WM.
  What to do first: Run `ldapsearch -x -H ldap://{dc_ip} -b {base_dn}
                     "(objectclass=pKIEnrollmentService)"` to find CAs,
                     OR run `certipy find -u {user}@{domain} -p {pw}
                     -dc-ip {dc_ip}` as the initial enumeration instead
                     of certipy_find (which expects CA already known).
```

This is how we eliminate a class of failure that bare-LLM agents make constantly: running a technique against a target that structurally can't be vulnerable to it.

---

## Example trace: how the pieces compose on a live box

Target: hypothetical Easy box, 10.10.10.100, Windows AD, Apache + SMB + Kerberos.

**Turn 1 — recon**:
```
[session-start hook] Subagent runs nmap → parser populates WM with 4 services
[planner-context]    Phase=recon, top actions: nmap_scripts, smb_enum, gobuster
                     No chain (no goal triggered yet)
Claude chooses: nmap_scripts (ranked #1, 85 pts)
```

**Turn 2 — after nmap_scripts**:
```
[post-action hook] Parser extracts Apache/2.4.49 banner
[planner-context]  Phase=recon→foothold
   World State:
     Apache 2.4.49  ← knowledge_index hit!
     [!] Apache 2.4.49: see CVE-2021-41773 path traversal
   Top actions:
     1. apache_path_traversal    score=95  (knowledge:30 + precond:25 + service:20 + gain:15 + trans:5)
        Mechanism: Apache 2.4.49 fails to normalise %2e in URL paths...
     2. kerberoast                score=62  (knowledge:20 + precond:0 — no domain_cred yet)
   Chain → root_access:
     1. apache_path_traversal → shell_obtained
     2. linux_suid_enum → suid_found
     3. suid_exploit → root_shell

Claude:
  Hypothesis: Apache 2.4.49 is CVE-2021-41773, mod_cgi probably enabled
              given it's an HTB easy
  Action:     apache_path_traversal, using %2e traversal to read /etc/passwd
              first (lower risk than RCE), then escalate to mod_cgi RCE
  Falsifier:  If /etc/passwd doesn't return, the CVE patch is applied
```

**Turn 3 — after apache_path_traversal**:
```
[post-action hook] web_response_parser matches "root:x:0:0:" → LFI confirmed
                   Writes finding {category: "lfi", severity: "high"}
                   WM adds predicate: lfi_confirmed
[planner-context]  Top actions include apache_path_traversal_rce
   Chain updates: now only 2 steps to root (LFI→rce was collapsed)

Claude:
  Hypothesis: LFI confirmed, mod_cgi likely reachable
  Action:     apache_path_traversal_rce via /cgi-bin/
  Falsifier:  If response doesn't contain `uid=` output, mod_cgi is
              disabled; pivot to LFI-to-log-poisoning
```

This is the loop. Every turn: WM updates → ranker re-scores → chain re-plans → mechanism context gets re-injected → Claude writes a fresh hypothesis.

---

## Why this is better than LLM-only agents

| Expert behaviour | Bare-LLM agent | TAR implementation |
|---|---|---|
| Remembers what's been tried | context window only | persistent WM + failed_attempts table |
| Knows CVEs for versions on sight | maybe (hallucinates) | knowledge_index.get_version_vulns |
| Picks technique variant from target fingerprint | inconsistent | technique_advisor.suggest_adaptation |
| Interprets silence as data | rarely | falsifier field + failure-analysis injection |
| Doesn't retry failed approach | often retries | retry-penalty + cross-engagement ledger |
| Plans 3 steps ahead | greedy | attack_chain_planner BFS |
| Knows when prerequisite is missing | learns after failing | pre-action prerequisite gate |

## Why this is better than walkthrough-replay agents

| Expert behaviour | Walkthrough-replay | TAR implementation |
|---|---|---|
| Handles boxes not in corpus | fails | mechanism-based reasoning |
| Picks the *easier* path, not the writeup path | locked to corpus | ranker evaluates all actions per turn |
| Reacts to unusual service/port configurations | doesn't | WM + knowledge index are config-agnostic |
| Adapts technique to stack fingerprint | no variants | PAT adaptation layer |
| Explains its choice | opaque | every score is decomposable |

---

## What this layer does *not* do

Being explicit about scope limits:

- **It does not write new exploits.** TAR composes known techniques. A zero-day in a custom service isn't something the ranker can surface — it would have to be handed an action YAML for that zero-day by an operator.
- **It does not plan beyond depth 4.** Planner cuts off at 4 action-steps; deeper plans are left to Claude to stitch turn-by-turn.
- **It does not learn online.** WM is per-engagement; the predicate ledger is cross-engagement but only tracks pass/fail, not new knowledge. Corpus updates are offline (re-run `enrich_actions.py` + re-build the knowledge index).
- **It does not reason about C2 / post-exploit stealth.** Falsifiers check whether a command worked, not whether it was quiet. Detection evasion is explicitly out of scope.

These are the next milestones in [`ROADMAP.md`](ROADMAP.md).

---

## The thesis, restated

> An autonomous pentest agent that operates outside its training distribution must reason from mechanism, not from pattern.
>
> Walkthroughs teach patterns. HackTricks teaches mechanisms. TAR puts HackTricks at the top of the scoring function, PAT in the adaptation layer, walkthroughs on the bench, and the LLM inside a runtime that *enforces* the hypothesis/action/falsifier loop.
>
> The result is not a better autocomplete. It's an agent whose decision trace a human operator can read, verify, and correct — because every step is grounded in an indexable, inspectable knowledge base.
