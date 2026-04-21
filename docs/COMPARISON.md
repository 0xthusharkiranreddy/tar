# Comparison with existing approaches

An honest look at how TAR relates to the existing landscape of AI-driven offensive-security tools.

TL;DR: The existing tools either don't ground their reasoning at all (bare LLM), ground it in the wrong thing (walkthrough corpora), or ground it in a narrow slice (single-tool wrappers). TAR grounds it in the same canonical references a human expert uses — HackTricks for mechanism, PAT for adaptation — with a deterministic runtime to enforce hypothesis discipline.

---

## The landscape

### 1. PentestGPT (Gelei Deng et al., 2023)

- **What it is**: paper + open-source implementation. Uses GPT-4 as the reasoning engine with a three-module architecture: Reasoning, Generation, Parsing.
- **How it reasons**: maintains a "Pentest Task Tree" — a hierarchical decomposition of the engagement. The LLM expands, prunes, and executes tree nodes.
- **Grounding**: none beyond GPT-4's training data. No external knowledge base.
- **Where it wins**: strong decomposition, readable task trees, reasonable performance on boxes that match GPT-4's memorised patterns.
- **Where it loses**: hallucinates tool flags, has no persistent world model between sessions, retries failing approaches (task-tree doesn't encode "this approach is structurally blocked"), no version-specific CVE reasoning.

**How TAR differs**: TAR's task structure is flat per-turn (the ranked action list), but the ranker is knowledge-grounded and the world model persists. Where PentestGPT has a tree and a model, TAR has a flat action library and a heavyweight retrieval + scoring runtime.

### 2. HackingBuddyGPT (Happe et al., 2024)

- **What it is**: Linux privesc agent. LLM-in-loop that runs SSH commands and reads output.
- **How it reasons**: plain LLM prompt engineering with tool-call loop. Some history tracking.
- **Grounding**: uses `lse.sh` / `linpeas.sh` output and feeds results to the LLM.
- **Where it wins**: focused scope (Linux privesc), measurable results on benchmark boxes.
- **Where it loses**: Linux-only, no lateral movement, no AD, no web, no structured retrieval of mechanism knowledge, no multi-step planning.

**How TAR differs**: TAR is general (web/AD/privesc/services/binary/…). TAR separates perception (parsers) from reasoning (ranker/planner) — HackingBuddyGPT conflates the two inside the LLM prompt.

### 3. AutoGPT / BabyAGI-style pentest agents

- **What they are**: general-purpose LLM agent frameworks repurposed for pentesting by prompting.
- **How they reason**: goal decomposition, step-by-step plan generation, reflection.
- **Grounding**: none. The LLM is expected to already know how to pentest.
- **Where they win**: quick to set up, flexible.
- **Where they lose**: everything that matters — no persistent state, no falsification, no retry suppression, no mechanism grounding, no prerequisite gating.

**How TAR differs**: TAR uses Claude Code's tool loop but replaces the "LLM decides everything" paradigm with a knowledge-first ranker and a typed world model. Claude is the *reasoner*, not the *planner*.

### 4. Walkthrough-replay / corpus-mimic agents (academic)

- **What they are**: models trained on (or retrieving from) scraped HackTheBox writeups that predict `P(action | history, phase)`.
- **How they reason**: statistical next-step prediction.
- **Grounding**: corpus-only.
- **Where they win**: boxes within distribution of training data.
- **Where they lose**: anything novel, and any deviation requires re-training.

**How TAR differs**: TAR *has* a walkthrough corpus and uses it — but demoted to 10 of the 100-point scoring budget, and only as a tie-breaker. v1 of TAR was walkthrough-dominant (25 points); the v2 rewrite that pushed walkthroughs down and knowledge up is the single biggest intellectual shift in the codebase.

### 5. Individual tool wrappers (e.g., LLM-powered sqlmap, LLM-powered nmap parsers)

- **What they are**: narrow tools that use an LLM to interpret or drive one specific tool.
- **How they reason**: domain-restricted LLM prompts.
- **Grounding**: limited to the tool's output semantics.
- **Where they win**: quality on the specific tool's task.
- **Where they lose**: no cross-tool reasoning, no state, no planning.

**How TAR differs**: these are useful components, not agents. TAR incorporates the same kind of specialised parsing (13 parsers) but under a unifying world model and reasoning engine.

---

## Axis-by-axis comparison

| Axis | Bare LLM | PentestGPT | HackingBuddyGPT | Walkthrough-replay | **TAR** |
|---|:---:|:---:|:---:|:---:|:---:|
| **Grounding in canonical knowledge** | ✗ | ✗ | partial (shell output) | corpus only | **HackTricks + PAT + walkthroughs** |
| **Persistent world model** | ✗ (context only) | partial (task tree) | partial | ~ | **SQLite, 10 tables** |
| **Multi-step planning** | ✗ | task-tree | ✗ | one-step | **STRIPS forward-chain BFS** |
| **Prerequisite gating** | ✗ | ✗ | ✗ | ✗ | **pre-action.sh + advisor** |
| **Failure interpretation** | ✗ | manual reflection | ✗ | ✗ | **HackTricks-grounded** |
| **Retry suppression** | ✗ | weak | ✗ | ✗ | **failed_attempts + predicate ledger** |
| **Falsifier per action** | ✗ | ✗ | ✗ | ✗ | **YAML `falsifier:` field** |
| **Adapts payload to stack fingerprint** | maybe | manual | ✗ | ✗ | **PAT adaptation layer** |
| **Explainable scoring** | ✗ (opaque LLM) | partial | ✗ | "highest P" | **5-signal decomposable** |
| **Deterministic replay** | ✗ | ✗ | ✗ | partial | **action YAMLs + WM snapshot** |
| **Hook-driven runtime** | no | no | custom loop | no | **Claude Code hooks** |
| **Coverage** | general | general | Linux privesc only | HTB only | **general (12 categories, 310 actions)** |

---

## Concrete example: how each approach would handle one situation

**Scenario**: target has Apache 2.4.49 detected by `nmap -sV`. Your agent sees this banner for the first time. What happens next?

### Bare LLM (GPT-4 in a shell)
```
LLM: "I'll run gobuster to enumerate directories."
→ gobuster finds /cgi-bin
LLM: "I'll try running exploits for Apache."
→ runs wpscan (wrong tool, Apache isn't WordPress)
→ runs searchsploit apache (returns 400 results)
→ picks one that doesn't match the version
→ fails, retries with a different random exploit
[Burns 15 tool calls on hallucinated approaches]
```

### Walkthrough-replay agent
```
Next-action prediction P(x | last=nmap, phase=foothold)
→ Top 3: [gobuster (0.4), hydra (0.2), nikto (0.15)]
(None of these specifically target CVE-2021-41773 because the
 walkthrough corpus may or may not have that exact box)
→ If lucky, a writeup covered this CVE, it's in the top 3
→ If not, wastes turns on generic enum
```

### TAR
```
post-action.sh parses nmap output:
  → tech_detect_parser identifies "Apache/2.4.49"
  → knowledge_index.get_version_vulns("Apache","2.4.49") returns
      [{"heading": "CVE-2021-41773 path traversal", ...}]
  → writes finding {category: "cve_version_match", severity: "critical",
                     description: "Apache 2.4.49 → CVE-2021-41773"}

planner-context.sh fires on next turn:
  → ranker computes scores:
      apache_path_traversal: knowledge=30 + precond=25 + service=20 = 95
      kerberoast:             knowledge=0  + precond=0  + service=0  = ~15
      gobuster_web:           knowledge=0  + precond=20 + service=20 = ~55
  → Top action: apache_path_traversal
  → Mechanism excerpt from HackTricks injected

Claude sees:
  1. **apache_path_traversal** (score=95)
     Mechanism: Apache 2.4.49 fails to normalise %2e in URL paths...
     Command: curl --path-as-is http://.../cgi-bin/.%2e/.%2e/...

Claude writes:
  Hypothesis: Apache 2.4.49 vulnerable to CVE-2021-41773
  Action: test LFI with %2e traversal first, then escalate to mod_cgi RCE
  Falsifier: if /etc/passwd doesn't return, patch is applied

Executes, parses, updates WM, moves on.
```

Three different agents. TAR gets to exploit in 2 turns; bare LLM never reliably gets there; walkthrough-replay gets there *if and only if* the corpus happens to cover that specific box.

---

## Cost comparison (illustrative, not measured)

Rough per-box token usage for an Easy HTB machine, based on architectural characteristics:

| Approach | Tokens per box | Mechanism |
|---|---:|---|
| Bare LLM-in-loop | 150k-400k | Re-reads full output, hallucinated detours |
| PentestGPT | 80k-200k | Task tree reduces re-reads, still verbose reasoning |
| Walkthrough-replay | 30k-80k | Compact action selection, low per-turn context |
| **TAR** | **20k-50k** | Compacted WM, cached knowledge prefix, ranked actions |

TAR's cost efficiency comes from three places:
1. **Knowledge injection is curated** — top-3 mechanism excerpts, not full HackTricks sections
2. **World model compresses history** — Claude doesn't re-read previous tool outputs; it reads the typed state summary
3. **Prompt prefix is cache-friendly** — the hook output is structurally stable across turns, allowing prompt caching to amortise the context injection cost

---

## When NOT to use TAR

Being honest about scope:

- **If you want zero-day discovery**: TAR composes known techniques. It cannot find a bug in a custom service unless you hand it an action YAML for that bug.
- **If you want stealthy red-team ops**: Falsifiers check whether a command worked, not whether it was silent to defenders. TAR is loud.
- **If your target is not in Claude's training window**: The LLM still needs some general-world-knowledge competence. TAR makes Claude 3-5x more effective, not infinitely effective.
- **If you need continuous online learning**: TAR's knowledge base updates are offline (re-run enrichment scripts). It does not learn from engagement outcomes automatically.
- **If you want a turnkey SaaS**: TAR is a research codebase that lives alongside Claude Code CLI. It expects Kali, the knowledge bases cloned locally, and an operator in the loop.

---

## What TAR is, stated plainly

TAR is **Claude + a deterministic offensive-security runtime**. The runtime gives Claude what a senior operator has internalised:

- A persistent memory of the engagement (world model)
- A structured vocabulary of actions with falsifiers (action library)
- A ranking function that prefers knowledge-grounded techniques
- A multi-step planner for goal-directed chains
- A prerequisite gate that blocks structurally-unavailable techniques
- Per-decision knowledge injection from HackTricks and PAT

The LLM does the creative work. The runtime does the bookkeeping, retrieval, and verification. That division of labour is what makes TAR more capable than bare LLM agents and more adaptable than walkthrough-replay agents.
