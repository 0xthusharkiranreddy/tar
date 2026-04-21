# AUDIT — brutal-honest gap analysis (v2.1)

## 1. What this document is

This is not a roadmap. `docs/ROADMAP.md` lists what we plan to build. This file lists what is **wrong or absent right now**, in language an experienced pentester can verify by opening the code.

If you are evaluating TAR for adoption, investment, or live use, read this **before** the README. Every claim below is anchored to a file path and line number in this repository at commit `8e7e4d3`.

TAR today is a defensible reasoning layer over a deterministic runtime. It is **not** a senior operator in a box. The gap between those two things is real — 6–12 months of focused work, not a tuning pass — and the rest of this document enumerates the gap concretely.

---

## 2. The core mismatch — what TAR ranks vs. what a human ranks

`scripts/action_ranker.py:244-250` declares five ranking signals:

```
1. Phase relevance    (0-25 pts) — Phase-appropriate via walkthrough + category
2. Knowledge match    (0-30 pts) — HackTricks prerequisite depth + product-version
3. Service specificity (0-20 pts) — Precondition coverage
4. Information gain    (0-15 pts) — Enum before exploit
5. Transition hint     (0-10 pts) — Walkthrough P(next|last) as tiebreaker
```

A senior pentester ranks a candidate action by at least six dimensions:

1. Technique applicability — *modelled*
2. Detection cost (how loud is this in SOC/EDR/CloudTrail terms) — **not modelled**
3. Reversibility (can I undo it if it misfires) — **not modelled**
4. Scope fit (is the target in the rules-of-engagement) — **not modelled**
5. Engagement-phase fit (is it day 1 of a recon window, or day 13 with a deliverable due) — **not modelled**
6. Target fragility (will this BSoD a production Windows box) — **not modelled**

Four of six dimensions are absent from the ranker. TAR is technique-aware; it is not operator-aware. That mismatch is the root of almost everything else in this document.

---

## 3. Destructive actions TAR can fire without a safety net

A grep of the action library for first-class safety keys produced nothing:

```
$ grep -rE "^(opsec|noise|detection|destructive|lockout|reversible|stealth):" actions/
(no matches)
```

No YAML in the 356-action library carries `destructive: true`, `reversible: false`, `noise: high`, or any equivalent. Safety hints exist only as free-text in the `mechanism:` field, which the ranker never reads.

The following eleven actions are present and will fire the moment their YAML preconditions evaluate true. Preconditions listed are the real ones in the file, verbatim.

| Action | File | Preconditions | Real-world consequence if misfired |
|---|---|---|---|
| `skeleton_key` | `actions/ad/skeleton_key.yml` | `domain_joined`, `has_cred` | Universal backdoor password injected into lsass on every DC; persists until DC reboot or EDR catches it |
| `dc_shadow` | `actions/ad/dc_shadow.yml` | `domain_joined`, `has_cred`, `domain_admin` | Injects arbitrary AD replication changes; reversal requires forensic AD audit |
| `dsrm_password` | `actions/ad/dsrm_password.yml` | `local_system`, `os==windows`, `is_dc` | If re-run with wrong SYSKEY, DSRM recovery path is destroyed |
| `zerologon` | `actions/ad/zerologon.yml` | `domain_joined` | Resets DC machine-account password to empty; if TAR does not restore it, AD replication breaks domain-wide |
| `krbtgt_reset` | `actions/ad/krbtgt_reset.yml` | `domain_joined`, `has_cred` | If dual-rotation is done without the 10-hour gap, invalidates every TGT in the domain simultaneously |
| `eternalblue` | `actions/services/eternalblue.yml` | `service.port==445`, `smbv1_enabled` | ~50% BSoD rate on real unpatched targets; takes production hosts offline |
| `smbghost` | `actions/privesc/smbghost.yml` | `service.port==445`, `smbv3_compression_enabled` | BSoD on misaligned offsets; same as above |
| `wsus_attack` | `actions/ad/wsus_attack.yml` | `os==windows` | Modifies WSUS server; breaks patching for the tenant until reverted |
| `custom_ssp` | `actions/ad/custom_ssp.yml` | `domain_joined`, `local_system`, `os==windows` | Persistent DLL injected into lsass; crash-dump reveals the tool on next reboot |
| `kerbrute_spray` | `actions/ad/kerbrute_spray.yml` | `service.port==88`, `domain_joined` | Lockout storm if spray-rate exceeds domain lockout threshold; can take a whole OU offline |
| `hydra` | `actions/creds/hydra.yml` | `has_target` | Same lockout risk; runs on any target with zero safety input |

**TAR does not check "is this host likely production?" before recommending any of these.** There is no production-environment predicate, no destructive-action confirmation prompt in the hook stack, no dry-run mode, no `engagement.allow_destructive` gate. The chain `responder → ntlmrelayx → certipy → skeleton_key → dc_shadow` is a valid plan under the current planner; nothing stops it mid-way.

The worst-case composition: `skeleton_key` + `dc_shadow` chained — creates audit-log invisibility that only CA-level forensics catches, and TAR will happily plan that chain if both predicates hold.

---

## 4. Rabbit holes TAR will fall into

Concrete scenarios, with the code path that enables each.

- **Web enum loop.** `gobuster`, `ffuf`, `feroxbuster`, `dirb` are all in the same `ENUM_ACTIONS` bucket (`action_ranker.py:202-214`). They produce equivalent output on port 80/443 with identical knowledge-match and service-specificity scores. No tool-class redundancy down-rank exists. On successive turns, TAR will pick a different fuzzer each time and believe it is making progress.

- **Kerberoast on machine-account-only SPNs.** If the only SPNs in the domain belong to machine accounts, kerberoast returns zero crackable hashes. The ranker has no rule that says "this technique has exhausted its search space"; TAR will retry kerberoast with different `-usersfile` arguments because `has_spns` is still true.

- **DC$ hash crack.** responder often captures the DC machine account's NetNTLMv2 hash. Machine-account passwords are 120-character random and uncrackable. TAR's ranker has no "machine accounts are uncrackable" filter; the `hashcat` action will score high because `has_hash` is true, and Opus will happily reason about wordlist tuning on an uncrackable hash for entire turns.

- **Password-spray lockout storm.** The spray actions have no input-time rate limiter. The feedback loop is "credential acquired?" not "did we just lock 200 users?". TAR will escalate the spray intensity if turn-one fails, because from the ranker's perspective the signal is "no credential, try again".

- **BFS silent dead-end.** `scripts/attack_chain_planner.py:235` returns `None` when `max_depth` (default 6) is exceeded. There is no partial plan, no warning, no recursive depth bump. A legitimate 7-step cross-forest plan becomes "goal unreachable" with no remediation hint. The operator sees a blank planner output and has to guess why.

- **Tier-bump, same wrong plan.** `scripts/cost_router.py:126-169` escalates Haiku → Sonnet → Opus after three consecutive failures, but keeps the same goal and the same action subset. Result: a bigger, more expensive model reasoning about the same dead goal. There is no phase-pivot trigger, no goal-abandonment rule, no "try a different attack vector" escape.

- **Responder long-sit.** responder captures hashes passively. TAR has no time-budget predicate — it will keep responder running across turns while also ranking noisy active attacks, producing both high-noise and low-noise activity simultaneously.

---

## 5. Perception gaps — what TAR literally cannot see

- **No visual input.** Cannot read a rendered webapp UI, cannot see a login flow, cannot interpret a Burp screenshot or a BloodHound graph image. All inference is from tool text output.

- **No client-side execution.** Misses DOM-XSS, runtime prototype pollution, `postMessage` handlers, SPA routing-based auth bypass, any vulnerability that requires rendering JavaScript.

- **No timing intuition.** A human notices "this response takes 800ms authenticated and 50ms unauthenticated — it hits a DB index only for logged-in users". TAR has no response-time differential tracker.

- **No smell test.** Cannot tell a honeypot from a real target. Cannot feel "this box is too easy, this is staged". Cannot detect a canary file designed to trigger on read.

- **No phased engagement model.** TAR ranks for immediate-next-best-move. On turn 1 of a 2-week engagement, it will go for DA in one chain if the preconditions hold. A human operator would spend days 1–3 on recon-only, days 4–9 on exploitation, days 10–14 on reporting.

- **No threat-model awareness.** "This is a bank's production domain" vs "this is a CTF" is indistinguishable to the ranker. The only signal the ranker receives is the WM predicate set.

---

## 6. Domain-specific gaps

### AD / red team

- No opsec scoring on lateral movement. `wmiexec`, `smbexec`, `winrm_exec`, `dcomexec`, `atexec`, `psexec` all score equal for the same predicate set. Their noise footprints differ by roughly an order of magnitude and TAR does not know.
- No BloodHound Enterprise awareness (certificate-services paths, tier-model violations, ACL path audit).
- No kerberoast pacing. Bulk-roasting 300 SPNs in one request triggers most SIEM rules. No per-request delay predicate.
- No ADCS template-discovery-then-wait-then-abuse sequence. `actions/ad/certipy.yml` enumerates; chain planning then jumps straight to abuse. A human would wait to see if the template was a honeytoken.
- Trust enumeration only 1 hop. `trusts_enum.yml` lists direct trusts; no recursive two-way → forest → external chain reasoning.
- No machine-account-quota reasoning. `maq_abuse.yml` exists; the ranker has no rule "if MAQ == 0, skip this entire subtree".
- Password-quality predicates are absent. TAR has no sense of "the first spray hit a 4-character password — this domain is weak" vs "8 sprays, no hits — skip to hash-based moves".

### Web / API

- **No session-state object.** Every web action is stateless HTTP. TAR cannot express "log in, capture cookie, hit authenticated endpoint, then refresh token" in one reasoning sequence.
- No OpenAPI / Swagger ingestion → endpoint enumeration. Modern APIs publish their full surface; TAR cannot consume it.
- JWT coverage is 2 of 65 web actions. Missing: RS256→HS256 algorithm confusion, JWK injection, `kid` SSRF, embedded JWK abuse, signature stripping, `none` alg downgrade, `jku` header exploitation, JWE content-encryption attacks.
- No GraphQL introspection → field-map → type-abuse chain. `graphql_enum.yml` mentions batching in prose; no action exploits it.
- No BFLA matrix across roles. `idor.yml` tests sequential IDs; `mass_assignment.yml` tests parameter tampering; neither tests privilege escalation across admin/user/guest triples.
- No WebSocket stateful testing. The YAML exists; session handling does not.
- No race-condition helper. `race_condition.yml` mentions millisecond windows; there is no actual single-packet-multi-request or H2 concurrent-stream helper wired in.
- No business-logic testing. Price tampering, coupon stacking, cart manipulation, workflow-step skipping — all absent.
- No CORS preflight hijack, no SameSite / cookie-scope confusion, no cookie-rewrite via subdomain.
- No cache-poisoning chain beyond the base YAML — no Web Cache Deception primitive, no HTTP/2 request smuggling beyond CL.TE/TE.CL.

### Cloud

**There is no `actions/cloud/` directory.** The audit states this flatly.

Cloud-adjacent actions found in the library:

- `ad/msol_password.yml` — Azure AD / Microsoft Online password dump
- `services/docker_api.yml` — Docker socket exposure
- `services/kubernetes_enum.yml` — K8s API enumeration (read-only)
- `privesc/docker_privesc.yml` — Docker privilege escalation
- `web/ssrf_cloud.yml` — SSRF to AWS/GCP/Azure metadata

Absent:
- No AWS IAM enum → privesc chain. No `iam:PassRole`, `sts:AssumeRole`, `lambda:UpdateFunctionConfiguration` escalation paths. No Pacu-style IAM abuse graph.
- No Azure beyond `msol_password`. No Azure AD role hunt, no Graph API abuse, no Managed Identity exfil, no Key Vault enum.
- No GCP. No service-account impersonation, no Cloud IAM role abuse, no metadata enum beyond `ssrf_cloud`.
- No CloudTrail / Azure-Activity-Log awareness. Every cloud API call leaves an audit entry; TAR has no "this is loud in CloudTrail" signal.
- No serverless attack surface. Lambda event-injection, Cloud Functions triggers, EventBridge abuse — absent.
- No container-escape chain post-exploitation beyond the base YAMLs. `CAP_SYS_ADMIN`, privileged pods, `hostPath` volumes, `/proc/self/exe` container-breakout — not wired as a chain.
- No Kubernetes RBAC abuse or etcd exploitation. Enum-only.

### Binary / reverse engineering

- 10 binary actions total. `actions/binary/` covers buffer overflow detection, canary leak, format string, Ghidra decompile, heap exploit, ret2libc, ROP chain, shellcode, SROP, checksec.
- No actual exploit development loop. TAR cannot fuse a CVE description with a loaded target and generate a working exploit.
- No Ghidra-bridge integration for automatic vulnerability-class detection.
- No ROP chain generator that consumes binary + gadget list → crafted payload.
- Cannot write a custom exploit for an 0-day in in-scope custom software.
- Canary/PIE bypass beyond basic enumeration is absent.

---

## 7. Judgment and scope gaps

- **No scope enforcement.** No `scope.yml`, no allow-list, no deny-list, no session-state scope section, no ranker scope filter. If a target appears in the world model, TAR will plan against it regardless of rules-of-engagement. A typo in a WM host entry and TAR will plan against 8.8.8.8 if preconditions match.

- **No engagement-goal awareness.** "Compromise the PII database" vs "get DA" produce the same plan, because goal granularity is only at the chain-planner level (17 canonical goals). There is no engagement-level goal slot that the ranker consults.

- **No stop-and-report mode.** TAR runs until context limit. It does not know when sufficient evidence exists to write the deliverable, or when to stop enumerating and start documenting.

- **No report writer.** TAR cannot produce a pentest deliverable. No CVSS scoring grounded in business context. No MITRE ATT&CK step mapping (mentioned in ROADMAP, not shipped). No executive-summary generator.

- **Cannot learn new techniques.** Anything outside HackTricks / PAT / OCD mindmap is invisible. A fresh CVE published today is unreachable until someone enriches the knowledge base manually.

- **No engagement memory.** `scripts/predicate_ledger.py` tracks cross-run failures narrowly. It does not record "on Windows 2019 + SMB + this patch level, petitpotam worked 8/10 times" positive signals. The ranker cannot reward techniques that have succeeded on similar contexts.

---

## 8. Environmental blindness

- Assumes impacket and other tool versions match. No version-compatibility pre-check on an action before dispatching its command.
- Clock skew is a heuristic in the operator's `CLAUDE.md` prompt, not a first-class precondition on Kerberos actions.
- VPN routing check is pre-attack advice to the human, not a predicate the ranker consults.
- SOCKS5-via-pivot target access — no action knows "this target is only reachable via pivot; prepend proxychains".
- IPv6 path — `mitm6.yml` exists; no reasoning rule "is IPv6 SLAAC applicable on this subnet".
- Process and port conflicts (responder, ntlmrelayx, ADIDNS listener all want overlapping ports) — no pre-flight check.
- AV/EDR presence is never predicated. TAR will drop `procdump lsass.exe` on a host with Defender running and generate an EICAR-class alert every time.

---

## 9. What would close each gap — prioritised

This section is deliberately pragmatic. The items are implementable sprint work, not research dreams.

### Priority 1 — safety (must precede any production-like use)

- First-class YAML schema fields: `destructive: bool`, `reversible: bool`, `noise: low|med|high`, `lockout_risk: bool`, `requires_explicit_auth: bool`. `scripts/action_ranker.py` penalises `destructive: true` unless session state contains `engagement.allow_destructive: true`.
- `scope.yml` schema with CIDR allow-list and deny-list; ranker filters candidate targets through scope before scoring.
- Lockout throttle — `kerbrute_spray` and `hydra` refuse to run without an explicit `rate_limit` parameter.
- Stuck-count phase pivot — after N consecutive failures in a phase, force a goal change, not just a model tier bump.

### Priority 2 — reasoning quality

- Embedding re-ranker over the TF-IDF shortlist (sentence-transformer, ~22 MB, CPU-friendly). Ship the ROADMAP item.
- Redundancy down-rank on tool class — gobuster, ffuf, feroxbuster, dirb share a `web_content_enum` class; second attempt within the same phase loses 15 points.
- Chain planner A* with admissible heuristic; raise effective depth to 8.
- Per-goal action subsetting so the planner does not BFS the full 356-action space.

### Priority 3 — domain coverage

- Spawn `actions/cloud/` with three subtrees: `aws/` (iam_enum, sts_abuse, s3_enum, ec2_metadata, lambda_exec, ssm_exec), `azure/` (aad_enum, graph_abuse, managed_identity, key_vault_enum), `gcp/` (sa_impersonate, metadata_abuse, iam_policy_dump).
- Web session-state object; re-use cookies, headers, and CSRF tokens across chained actions.
- JWT deep library — algorithm-confusion, JWK injection, `kid` SSRF, signature stripping, `jku` abuse, embedded JWK.
- GraphQL introspection → typed abuse chain: introspection → field map → type-based BOLA.
- API-specific recon from OpenAPI / Swagger ingestion.

### Priority 4 — judgement

- Engagement-goal slot in session state; ranker weights actions by goal fit (not just phase).
- Stop-and-report trigger when WM predicates indicate the stated objective is achieved.
- LLM-native action authoring — draft a new YAML from a HackTricks section automatically, with human review (ROADMAP item).
- Report writer subagent that consumes WM + evidence pointers + engagement goal → draft deliverable.

---

## 10. Honest "fit for" statement

**TAR v2.1 is fit for:** CTFs, lab work, HackTheBox and similar retired-box exercises, internal methodology drill for junior operators, rapid enumeration of known-scope targets, and as a reasoning augmenter for a *human-in-the-loop* senior engagement where the operator is the final authority on every destructive action.

**TAR v2.1 is not fit for:** hands-off real-world engagements, production environments, stealthy red-team ops, cloud-primary targets, or any scenario where a destructive action firing without human approval would cause measurable harm.

The path from the first list to the second is the rest of this document. It is real work, in a known order, on a well-defined codebase. It is not a marketing gap.

If you are evaluating TAR, the correct mental model is: *this is a very strong junior teammate who has memorised three textbooks and can reason about them, but who will absolutely run zerologon on a production DC if you don't stop them.* Staff accordingly.
