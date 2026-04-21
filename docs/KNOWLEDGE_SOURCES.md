# Knowledge Sources — HackTricks, PAT, OCD Mindmap, and Cypher Library

This document explains in full detail how the four canonical offensive-security knowledge bases are integrated into TAR's reasoning pipeline.

If you only remember one sentence from this doc: **TAR does not send HackTricks or PAT to Claude. It sends Claude answers derived from them, per-decision, in tokens measured in hundreds — not tens of thousands.**

---

## The four sources

### HackTricks (`/home/kali/hacktricks/`)

Carlos Polop's mechanism-first reference. ~1,938 markdown files organised by attack surface (AD, Linux privesc, web, Windows hardening, etc.). Characterised by:

- Prose-heavy. Every technique section explains *what the vulnerability is*, *how the mechanism works*, and *why the specific command flags matter* — not just copy-paste commands.
- Flat, grep-friendly structure. Each file covers one focused topic.
- Coverage of failure modes. Most sections include a "why this might not work" paragraph — critical for TAR's failure-interpretation feature.

HackTricks is what TAR uses for **mechanism understanding** and **failure interpretation**. When Claude needs to reason about *why* a technique works or *what* a silent failure means, HackTricks is the source.

### PayloadsAllTheThings (`/home/kali/PayloadsAllTheThings/`)

Swissky's payload catalogue. ~483 files, structured as per-technique directories each containing dozens of payload variants for different environments, engines, and bypass requirements.

Characterised by:

- Payload-first organisation. A technique like SSTI has sub-sections for Jinja2, Mako, Twig, Smarty, ERB, Freemarker, Thymeleaf, etc.
- Clear environmental parameters. Each payload variant specifies *when* to use it (engine, filter state, sandbox type).
- Less prose, more examples. Complements HackTricks rather than duplicates it.

PAT is what TAR uses for **adaptation** — picking the right payload variant given the target's detected stack. When Claude needs to pick Jinja2 over Mako, PAT is the source.

### The third source: OCD AD Red Teaming Mindmap (`/home/kali/knowledge/mindmaps/`)

Orange Cyberdefense's operator mindmap (2025.03 release), transcribed into `ocd_ad_2025.md` as a structured `## Branch` / `### Technique` markdown. It encodes the exact decision tree a senior internal-pentest operator uses — zero-access → poisoning → credential capture → relay → coercion → privesc → trust crossing → forest DA.

Differs from HackTricks in two important ways:
- **Topology, not prose.** The mindmap's value is the *branching order* — which technique you try next given what you just learned.
- **Per-branch CVE & tool mapping.** Each leaf lists the specific CVE/tool, saving the advisor from having to grep HackTricks by keyword.

TAR weights mindmap sections slightly higher (1.1×) than HackTricks on methodology queries because it answers *"what do I try next"* rather than *"how does technique X work"*.

### The fourth source: BloodHound Cypher library (`/home/kali/knowledge/cypher/`)

15 canonical Cypher queries in individual `.cypher` files, each with a header comment describing *when* to run it and *what predicate* it produces (`kerberoastable.cypher`, `rbcd_candidates.cypher`, `shadow_cred_candidates.cypher`, `readlaps.cypher`, `readgmsa.cypher`, `gpo_controllers.cypher`, `ou_genericall.cypher`, `trust_map.cypher`, `high_value_paths.cypher`, `foreign_group_members.cypher`, `dcsync_rights.cypher`, `esc1_vulnerable_templates.cypher`, `unconstrained_delegation.cypher`, `constrained_delegation.cypher`, `asreproastable.cypher`).

Indexed as first-class knowledge sections so the planner/advisor can reference them directly, and individual action YAMLs can quote them in their `mechanism:` field.

### The fifth source: local knowledge (`/home/kali/knowledge/`)

Hand-curated operational notes: tool usage recipes, commonly-missed flag combinations, HTB-specific gotchas. Indexed alongside the others but weighted lower (operator-local, not canonical).

---

## The index — `scripts/knowledge_index.py`

### Build pipeline

```
For each source root in SOURCES:
  For each .md file under root:
    Split on heading regex (^#{1,4}\s+)
    For each section:
      section_id  = hash(file_path + heading + first_100_chars)
      tokens      = lowercase, strip md syntax, split on non-alnum
      tf          = Counter(tokens)
      doc_len     = len(tokens)
      store (section_id, heading, body, source, path, tf, doc_len)

# Second pass — corpus statistics
df[token] = number of sections containing token
N         = total section count
idf[token] = log(N / df[token])

# Third pass — inverted index
token_index[token] = [section_ids that contain token]
```

Result: **35,752 sections** indexed from the three sources (as of current build). Cold build: 2.4s. Cached build from pickle: 0.4s.

Pickle cache at `/tmp/tar_knowledge_index.pkl` is version-tagged and invalidated on source-file mtime change. Schema version bump also invalidates (current: v3, which added the inverted token index).

### Query path

The naive `search("kerberoast")` is O(N × |query tokens|) — scanning all 35k sections. Unacceptable when the planner-context hook fires every turn.

The inverted token index shortlist fixes this:

```python
def search(self, query, top_n=5):
    query_tokens = self._tokenise(query)
    # Step 1: candidate shortlist via inverted index
    candidate_ids = set()
    for tok in query_tokens:
        candidate_ids.update(self.token_index.get(tok, []))
    # Step 2: TF-IDF score only the candidates (typically <200 of 35k)
    scored = []
    for sid in candidate_ids:
        section = self.sections[sid]
        score = sum(
            section.tf.get(tok, 0) * self.idf[tok]
            for tok in query_tokens
        ) / section.doc_len
        scored.append((score, section))
    return sorted(scored, reverse=True)[:top_n]
```

This collapses the hot path from ~4.9s to ~40ms per query.

### Source weighting

```python
SOURCE_WEIGHTS = {
    "hacktricks":  1.0,    # canonical mechanism source
    "pat":         0.9,    # canonical payload source
    "knowledge":   0.7,    # operator notes, less authoritative
    "walkthroughs": 0.3,   # observation, not explanation
}
```

When a query overlaps multiple sources, HackTricks wins tie-breakers. This implements "mechanism > pattern" at the retrieval layer.

---

## The four injection points

Each injection point answers one question an expert would ask. The knowledge base provides one of four outputs.

### ① `get_technique_context(action_name, max_chars=1500)`

**Question**: *What is the HackTricks section for this technique?*

**Used by**: top-3 ranked actions in planner-context hook (for `mechanism_brief`), the technique advisor for failure interpretation lookups.

**Behaviour**: Maps the action name (from YAML) to a keyword set (from the action's `references.hacktricks` field if set, otherwise the action name itself), searches the index, returns the highest-scoring HackTricks section trimmed to `max_chars`. Cached per `(action_name, max_chars)` tuple.

```python
ki.get_technique_context("kerberoast", max_chars=300)
# → "[HACKTRICKS] Kerberoast
#    Kerberoasting exploits the fact that any authenticated domain user can
#    request a TGS (Ticket Granting Service) ticket for any SPN. The TGS is
#    partially encrypted with the service account's NTLM hash. By requesting
#    TGS tickets for SPNs tied to user accounts (not machine accounts), an
#    attacker obtains crackable material..."
```

Why this matters: Claude sees the *reasoning* for the technique, not just "run GetUserSPNs.py". When the box turns out to have no SPN-user, Claude can say "oh, no SPN-user exists, so kerberoast is structurally unavailable — asreproast next" — because the mechanism section explained the SPN-user requirement.

### ② `get_version_vulns(product, version)`

**Question**: *Is this specific version known-vulnerable, according to HackTricks?*

**Used by**: the ranker's `knowledge_score()`, and directly surfaced in the World State block of the planner-context hook.

**Behaviour**: searches the index for sections matching `{product}.*{version}` regex patterns, filters to those containing `CVE-\d{4}-\d+`, returns the top matches with structured fields.

```python
ki.get_version_vulns("Apache", "2.4.49")
# → [{
#     "heading": "Apache 2.4.49 path traversal",
#     "cve_desc": "CVE-2021-41773",
#     "product": "Apache",
#     "version_pattern": "2.4.49",
#     "excerpt": "Apache 2.4.49 fails to normalise %2e sequences...",
#     "source": "hacktricks"
#   }]
```

Cached per `(product, version)` tuple.

Why this matters: the moment a service banner like `Apache/2.4.49` lands in the WM, the ranker scores the matching action (e.g., `apache_path_traversal`) with the full 30-point knowledge bonus. That single injection is why TAR can solve novel-ish boxes that contain a known-vulnerable version not covered in any walkthrough in the corpus.

### ③ `get_failure_guidance(action_name, error_pattern)` / `advisor.get_failure_interpretation(...)`

**Question**: *What does this specific error mean for this specific technique?*

**Used by**: the Failure Analysis block of the planner-context hook.

**Behaviour**: two-layer lookup.

1. **Curated first** — `technique_advisor.TECHNIQUE_RULES[action_name]["failure_patterns"][error_match]` returns a hand-written interpretation tuned from the HackTricks section. Covers the 40+ most common techniques.
2. **Index fallback** — if uncurated, searches the index with `"{error_string} {action_name}"` and returns the top matching section.

```python
advisor.get_failure_interpretation("kerberoast", "No entries found")
# Curated hit:
# → "No SPN-bearing users exist in this domain. Kerberoast is structurally
#    unavailable. Try asreproast (pre-auth disabled accounts) or rbcd
#    (Resource-Based Constrained Delegation) if you have write on a
#    computer object."
```

Why this matters: this is the mechanism that prevents retry-loops. The hook shows the interpretation to Claude, and the hypothesis-falsifier discipline in the system prompt forces Claude to *update* rather than retry.

### ④ `get_alternatives(action_name, services=[...])` / adaptation layer

**Question**: *If this approach isn't working, what else could I try on this target surface?*

**Used by**: Alternatives block of the planner-context hook (triggered on ≥2 consecutive failures), and `technique_advisor.suggest_adaptation()` for per-technique variant selection.

**Behaviour (alternatives)**: given the failed action and the services present, builds a query like `"{service_products} alternatives to {action} techniques"` and returns HackTricks/PAT sections — excluding sections that describe the failed action itself.

**Behaviour (adaptation)**: given a technique and a target profile (tech stack, DBMS, framework), queries PAT's per-variant sub-sections and returns the variant that best matches the profile.

```python
# Stuck on an SMB target
ki.get_alternatives("smb_null_session", services=[(445,"Samba"),(161,"SNMP")])
# → [
#     {"source": "hacktricks", "heading": "SNMP enumeration", "excerpt": "..."},
#     {"source": "pat",        "heading": "SMB guest authentication", "excerpt": "..."},
#     {"source": "hacktricks", "heading": "SMB anonymous via null-username", "excerpt": "..."},
#   ]

# Adaptation: SSTI on Python/Flask stack
advisor.suggest_adaptation("ssti", target_profile={"tech": ["python","flask"]})
# → {"engine": "Jinja2",
#    "payloads": ["{{7*7}}", "{{config.items()}}", "{{''.__class__.__mro__[1]...}}"],
#    "source": "pat"}
```

Why this matters: an expert operator who's failed SMB null-session twice doesn't keep tuning SMB flags — they pivot to SNMP, HTTP, WinRM. The alternatives block mimics that pivot.

---

## Where each source is weighted most heavily

Different injection points lean on different sources:

| Injection | Primary source | Why |
|---|---|---|
| Mechanism brief (top-3 actions) | HackTricks | Mechanism-first prose, explains *why* |
| Version-CVE matching | HackTricks | CVE coverage is exhaustive; PAT rarely includes CVE IDs |
| Failure interpretation | HackTricks | HackTricks includes "why this might not work" commentary |
| Technique adaptation (payload variants) | PAT | PAT is organised by variant; HackTricks usually shows one variant |
| Alternatives (stuck pivot) | HackTricks + PAT | Blended — HackTricks for technique candidates, PAT for variant hints |

---

## How enrichment bakes knowledge into the action library

`enrich_actions.py` and `enrich_effects.py` use the knowledge index *at build time* to enrich the YAML action library. This is a one-way flow (knowledge → actions) that makes the actions themselves "smarter" without paying query cost at runtime.

For each YAML action:

1. Query HackTricks for the technique
2. Extract the best-matching section
3. **Upgrade the `mechanism:` field** from the shallow one-liner to a 2-3 sentence HackTricks excerpt
4. **Extract failure patterns** from the section's "troubleshooting / common issues" paragraphs and update the `falsifier:` regex
5. **Assign a parser** via pattern-match rules (`enrich_actions.PARSER_RULES` holds ~200 rules mapping name patterns to parsers)
6. **Assign meaningful effects** (`enrich_effects.EFFECT_RULES` holds ~200 rules mapping action patterns to predicate sets like `["tgs_hashes_obtained","has_hash"]`)
7. Store the HackTricks path in `references.hacktricks` so runtime queries can target the exact section

Numbers from the current repo (post-enrichment):
- 310/310 actions have a parser assigned (was 68/310 pre-enrichment — i.e., 78% were `null`)
- 271/310 have meaningful effect predicates (was 100/310 — the rest were generic `action_completed` which breaks chain planning)
- 310/310 have mechanism fields of ≥40 chars (was mostly one-liners)
- 267/310 got meaningful falsifier upgrades

This is why the intelligence layer and the action library reinforce each other — the ranker queries knowledge at runtime, and the actions themselves carry pre-digested knowledge that the ranker can reason over without a fresh query.

---

## Example: full query trace for one action rank

Walkthrough of what happens when `action_ranker.score_action(action=kerberoast, wm_state=...)` runs:

```
1. precondition_score — checks wm.predicates against action.preconditions
   + deep call to advisor.get_prerequisites("kerberoast")
   deep prereqs return: ["valid domain credential", "SPN users in domain", "port 88"]
   wm has: has_domain_credential=True, service.port==88=True, but not spn_users_enumerated
   → partial match: 20/25 (missing one soft prereq)

2. service_score — action YAML expects port 88 present
   wm has port 88 → 20/20

3. info_gain_score — action produces effects ["tgs_hashes_obtained","has_hash"]
   wm does not yet have has_hash → +15

4. transition_score — walkthrough corpus P(kerberoast | last=bloodhound_analysis, phase=foothold)
   corpus says 0.4 → 4/10

5. knowledge_score — THIS IS THE KEY CALL
   ki.get_technique_context("kerberoast") → HackTricks "Kerberoast" section
   section found with match score 0.87 → 26/30

   PLUS: ki.get_version_vulns() for all services — none match (no CVE for kerberoast itself)
   PLUS: advisor.get_prerequisites() used for the 25-point precondition check above

TOTAL: 85 points
```

That score is deterministic (re-runnable) and decomposable (every component attributable to a source).

---

## Failure modes of the knowledge layer (honest)

- **TF-IDF is bag-of-words.** Conceptual queries like "how do I escape a sandbox" match sections about "sandbox escape" but also about "escaping URLs in a sandbox" — sometimes poorly. Roadmap item: sentence-transformer re-ranker on top of TF-IDF shortlist.
- **CVE regex is pattern-matched.** `get_version_vulns("Apache","2.4.49")` depends on HackTricks having a section whose body contains text matching `Apache.*2\.4\.49.*CVE-\d{4}-\d+`. If HackTricks worded it differently (e.g., "Apache 2.4.49-2.4.50 are vulnerable to CVE-...") the match could miss. Mitigation: curated `TECHNIQUE_RULES` covers the top 40 CVEs explicitly.
- **Curated rules drift.** The 40 curated technique entries in `technique_advisor.TECHNIQUE_RULES` need manual maintenance when HackTricks restructures a section. Planned mitigation: lightweight CI that diffs HackTricks content hashes and warns on drift.
- **PAT variant detection is heuristic.** `suggest_adaptation("ssti", target_profile={"tech":["python","flask"]})` works because `python|flask` → Jinja2 mapping is in the rule table. Novel frameworks may fall through to a generic "try these payloads" response. Good enough for the top 15 stacks; not exhaustive.

None of these break the system, and each has a clear upgrade path listed in [`ROADMAP.md`](ROADMAP.md).
