# Roadmap & Known Gaps

An honest enumeration of what TAR does *not* do yet, and how each gap will close.

This file is deliberately front-loaded with limitations. If you are evaluating TAR for adoption or investment, you should read this before the README.

> For the **present-tense** picture of what does not work today — destructive actions, rabbit holes, perception gaps, domain-specific weaknesses — see [../AUDIT.md](../AUDIT.md). ROADMAP.md is forward-looking; AUDIT.md is a brutal snapshot of the current state.

## Shipped in v2.1 (Apr 2026)

- Orange Cyberdefense 2025.03 AD mindmap integrated as a fourth canonical knowledge source (weight 1.1× on methodology queries).
- 46 new action YAMLs closing the mindmap-vs-library gap: full SCCM tree (8 actions), ADCS ESC9-15 + Certifried, Kerberos persistence (Skeleton Key, DCShadow, Custom SSP, DSRM, Saphire Ticket), noPac, PrivExchange, KeePass dump, Veeam CVE-2024-40711 / CVE-2023-27532, EternalBlue, Potato variants, UAC bypass, LSASS dump variants, trust key extraction + ticket forging, blind/targeted kerberoast, TimeRoasting, goldenPac MS14-068.
- BloodHound Cypher library (15 queries) indexed as first-class knowledge.
- 7 new attack-chain-planner goals + 15 effect aliases.
- 30+ new technique advisor rules (prereqs + failure-interp).
- Integration tests extended: 43/43 passing.

---

## Tier 0 — Blockers before real-world deployment

### 1. No live HTB run with published trace

**Gap**: The 35/35 integration tests validate that the reasoning layer produces credible plans over synthetic world-model state. They do *not* prove end-to-end efficacy on a live retired box.

**Impact**: We cannot yet claim a specific time-to-root number against a real target.

**Plan**:
- Week 1: pick 3 retired HTB Easy boxes (Lame, Legacy, Blue), run TAR end-to-end, publish the full conversation trace + WM snapshots + token cost
- Week 2: 3 Medium boxes (Forest, Active, Sauna), same methodology
- Week 3: 2 Hard boxes (Rebound, Hospital), surface failure modes for the roadmap

**Why we haven't yet**: the v2 reasoning layer completed this week. The bottleneck was not implementation, it was ensuring deterministic behaviour (35/35 tests) before burning HTB attempts.

### 2. Action library has uneven coverage

**Gap**: 310 actions across 12 categories, but distribution is skewed:

| Category | Actions | Density |
|---|---:|---|
| web | 68 | dense |
| ad | 65 | dense |
| services | 56 | adequate |
| privesc | 50 | adequate |
| crypto | 12 | **thin** |
| cms | 10 | thin |
| smb | 10 | adequate |
| binary | 10 | **thin** |
| shell | 10 | adequate |
| creds | 8 | thin |
| pivoting | 7 | **thin** |
| recon | 4 | **very thin** |

**Impact**: Boxes gated by a pivoting decision (e.g., need chisel forwarding), a binary exploitation step (buffer overflow with custom gadget chain), or unusual recon (masscan with custom rate tuning) will have fewer candidate actions to rank.

**Plan**: action-YAML expansion pass, priority order:
1. Pivoting (chisel variants, ligolo-ng, sshuttle, ssh tunneling patterns) — target +15 actions
2. Binary (ret2libc, ROP chain builders, format string primitives) — target +10
3. Recon (subdomain enum variants, cloud-asset enum) — target +10
4. Crypto (hashcat per-mode tuning, JWT, padding oracle, RSA attacks) — target +8

Open question: should recon stay thin (because most recon lives in the session-start subagent) or expand?

### 3. Parser coverage is breadth-first, not depth-first

**Gap**: 310/310 actions have a parser assigned, but many point at `generic_parser` as a fallback. `generic_parser` catches NTLM/SUID/uid=0/SUDO_NOPASSWD — coarse-grained. It misses service-specific structure.

**Impact**: Action outputs that go to generic parser don't always populate the world model with fine-grained findings, which hurts the ranker's info-gain signal on follow-up turns.

**Plan**: hand-written parsers needed for:
- `sqlmap_parser` — database/table/column enumeration structure
- `responder_parser` (full) — currently catches hashes, missing NetBIOS captures and HTTP-challenge patterns
- `hashcat_status_parser` — in-progress crack state, percent complete, eta
- `mimikatz_parser` — sekurlsa::logonpasswords block, lsadump::sam block
- `bloodhound_parser` — cypher query result → structured paths (currently raw JSON to findings)
- `certipy_parser` — vulnerable template enumeration → structured finding per template
- `enum4linux_parser` — SMB/LDAP user/group/policy sections

Priority: `sqlmap_parser`, `mimikatz_parser`, `bloodhound_parser` first (highest info-gain impact).

---

## Tier 1 — Quality improvements

### 4. Knowledge index is TF-IDF-only

**Gap**: Good on keyword queries (`"kerberoast"`, `"Apache 2.4.49"`), weak on conceptual queries (`"how do I escape this jail"`, `"what if the AV is blocking powershell"`).

**Impact**: Failure interpretation and alternatives generation sometimes return tangentially-related sections.

**Plan**:
- Add a sentence-transformer embedding layer (`all-MiniLM-L6-v2` or similar, ~22MB, CPU-friendly)
- Use as a re-ranker over the TF-IDF candidate shortlist (TF-IDF narrows 35k → 200, embeddings re-rank 200 → 5)
- Keep TF-IDF as the first-pass shortlist because it's fast and preserves the cache-warm flow
- Cost: +~200ms cold load, +~10ms per query after warm. Still well under the 3s hook budget.

### 5. Chain planner is depth-limited BFS

**Gap**: `max_depth=4` works for most tactical scenarios (foothold → privesc → root is usually 2-3 steps). Deeper plans (domain lateral movement into a multi-forest environment) exceed the depth budget.

**Impact**: For complex engagements, the planner returns `None` (unreachable) even when a plan exists at depth 5-6.

**Plan**:
- Implement heuristic-guided A* with admissible heuristic (action-distance-to-goal estimated via precondition-effect graph)
- Per-goal action subsetting (e.g., for `domain_admin`, shortlist AD-category actions first)
- Targeted memoisation of partial state → best-plan prefix
- Raise effective depth to 8 without blowing up search time

### 6. Technique advisor curated rules drift

**Gap**: `TECHNIQUE_RULES` is hand-written for 40+ techniques with specific failure patterns and adaptations. When HackTricks restructures or renames a section, the curated rules don't automatically notice.

**Impact**: Silent degradation — a curated rule pointing at "Kerberoast / common failures" section will return nothing if HackTricks renames it.

**Plan**:
- Lightweight CI: compute content hash per referenced section at enrichment time, fail the enrichment step if hashes diverge
- Migrate curated rules to track section by keyword-overlap rather than exact heading match
- Reduce curated-rule count by pushing most logic into on-demand TF-IDF + embedding retrieval (see #4)

### 7. No on-line learning from engagement outcomes

**Gap**: `predicate_ledger.py` tracks cross-engagement pass/fail per (technique, predicate-context) tuple — but only to suppress known-failing approaches. It does not surface positive signals (e.g., "on Windows 2019 + SMB + port 445 open, `petitpotam` succeeded 8/10 times").

**Impact**: The ranker can't reward techniques that have worked well on similar contexts.

**Plan**:
- Extend predicate ledger schema with success counts
- Add `ranker.contextual_prior_score()` signal (capped at 5 points, i.e., tiebreak only — we do not want corpus-like overfitting)
- Decay old observations (exponential, half-life ~30 days) so the signal stays fresh

### 8. No explicit exploit-writing loop

**Gap**: TAR composes known techniques. It cannot discover a zero-day in a custom service.

**Impact**: Limits applicability on real-world engagements where custom software is in-scope.

**Plan** (this is a big one, flagged for later):
- Add an `exploit_dev` subagent triggered by patterns like "custom protocol detected", "Ghidra found binary with obvious vulnerability class"
- Integrate with `ghidra_bridge` / `radare2` for automated binary analysis
- Add an ROP chain generator that consumes binary + gadget list → crafted payload
- Scope: weeks of work. This becomes TAR v3.

---

## Tier 2 — Operational gaps

### 9. Hooks are Bash-heavy and fragile

**Gap**: `planner-context.sh` is 200 lines of bash with inline Python. Hard to test, hard to refactor.

**Impact**: Regression risk when modifying hook logic.

**Plan**: Migrate hook logic into a single `tar_hook.py` called from a minimal wrapper `.sh`. Tests then live as Python unit tests.

### 10. No UI / observability dashboard

**Gap**: The only way to see what the ranker is doing is to read the hook output inline in Claude Code.

**Impact**: Hard to debug why a specific action was ranked high or low. Hard to present to stakeholders.

**Plan**:
- `tar inspect <engagement>` CLI that pretty-prints WM state, recent action scores (with decomposition), and chain plans
- Web dashboard (Flask + HTMX) showing live engagement state, action log, score histories
- Export hook traces to JSONL for post-engagement analysis

### 11. No benchmark suite

**Gap**: We validate against integration tests (35 synthetic scenarios) but have no standard benchmark like "time to root on top-20 retired HTB boxes".

**Impact**: Cannot compare TAR versions quantitatively over time.

**Plan**:
- Pick 20 retired HTB boxes covering the full category distribution
- Snapshot target state (nmap output captures) so benchmarks are reproducible without live targets
- Run each TAR version against the benchmark, track: turns-to-root, tokens consumed, ranker-agreement with ground-truth path
- Publish benchmarks with every release

### 12. Cost routing not fully wired

**Gap**: `cost_router.py` exists from v1 for tier-based cost control (cheap/balanced/premium → different model selections). Not yet fully integrated with v2 hooks.

**Impact**: Currently uses default Claude settings. No automatic escalation from Haiku to Opus when the ranker indicates "we're stuck, bring in the big model".

**Plan**: re-integrate `cost_router` into the hook stack, add auto-escalation triggers:
- `stuck_count >= 3` → escalate to Opus
- `phase == root && ranker_top_score < 40` → escalate (no strong candidate, need creativity)

---

## Tier 3 — Speculative / long-term

### 13. Cross-agent coordination

TAR currently runs as a single Claude instance. A multi-host engagement (Active Directory lateral movement across 10 boxes) should parallelise recon + exploit across agents.

**Plan**: Subagent orchestration — a "conductor" agent maintains the macro world model, spawns "worker" agents per host, aggregates their WMs back into the conductor's view.

### 14. Integration with real C2 infrastructure

TAR assumes Kali-local tool invocation. Real ops want C2 (Havoc, Sliver, Mythic).

**Plan**: Add a C2 abstraction layer — action YAMLs reference abstract tasks (`beacon_exec`, `beacon_upload`) that map to C2-specific commands at runtime.

### 15. LLM-native action authoring

Today, new action YAMLs are hand-written (or enriched from HackTricks). An LLM should be able to generate new YAMLs from a HackTricks section automatically, with human review.

**Plan**: `tar action-from-hacktricks <section_path>` CLI that drafts a new action YAML, which a human then reviews/edits/commits.

---

## Upgrade path summary

| Milestone | What ships | ETA |
|---|---|---|
| **v2.1** | Live HTB traces (3 Easy boxes), benchmark suite scaffolding | 2 weeks |
| **v2.2** | Missing deep parsers (sqlmap, mimikatz, bloodhound), pivoting actions | 4 weeks |
| **v2.3** | Embedding re-ranker, chain planner A*, cost routing | 6 weeks |
| **v2.4** | On-line learning signals, TAR CLI inspect tool | 8 weeks |
| **v3.0** | Exploit-dev subagent, multi-agent orchestration | 3-6 months |

These are targets, not promises. The principle is: ship small, inspectable improvements behind the existing test harness, preserve the 35-test baseline through every change.

---

## What's explicitly *out* of scope

- Stealthy post-exploitation (detection evasion, C2 beacon design)
- Windows binary exploitation (cribbed from existing frameworks — PwnDbg, PwnTools)
- Malware authoring / obfuscation
- Social engineering agents (phishing crafting, OSINT-to-attack)

These are interesting problems. They belong to different tools.
