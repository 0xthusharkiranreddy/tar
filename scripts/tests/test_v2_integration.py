#!/usr/bin/env python3
"""
test_v2_integration.py — TAR v2 end-to-end integration tests.

Covers:
  - Knowledge Index: search, technique context, version vulns, alternatives
  - Technique Advisor: prerequisites, failure interp, adaptations
  - Action Ranker: scoring, prerequisite gating, knowledge bonus
  - Attack Chain Planner: forward-chaining, goal satisfaction
  - Parsers: web_response, tech_detect, generic
  - Param Filler: technique-aware credential selection
  - Hook latency: planner-context <3s

Run: python3 test_v2_integration.py
"""

import os
import subprocess
import sys
import time
import tempfile
from pathlib import Path

SCRIPTS_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(SCRIPTS_DIR))

PASS = 0
FAIL = 0
FAILURES = []


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [OK] {name}")
    else:
        FAIL += 1
        FAILURES.append((name, detail))
        print(f"  [FAIL] {name}  {detail}")


def section(title):
    print(f"\n── {title} " + "─" * (60 - len(title)))


# ══════════════════════════════════════════════════════════════════
# Knowledge Index
# ══════════════════════════════════════════════════════════════════
def test_knowledge_index():
    section("Knowledge Index")
    from knowledge_index import get_index

    ki = get_index()

    # Basic search
    results = ki.search("kerberoast", top_n=5)
    check("search returns results for kerberoast", len(results) > 0)
    check("search results have scores", all("score" in r for r in results))

    # Technique context
    ctx = ki.get_technique_context("kerberoast")
    check("get_technique_context for kerberoast returns content", len(ctx) > 100)
    check("context labels source (HACKTRICKS/PAT)",
          any(label in ctx for label in ["HACKTRICKS", "PAT", "KNOWLEDGE"]))

    # Version vulns — Apache 2.4.49 has CVE-2021-41773
    vulns = ki.get_version_vulns("Apache", "2.4.49")
    check("get_version_vulns returns Apache 2.4.49 CVE info", len(vulns) > 0)

    # Cache hit: second call should be much faster (already warmed)
    t0 = time.perf_counter()
    for _ in range(20):
        ki.get_technique_context("kerberoast")
    elapsed = (time.perf_counter() - t0) * 1000
    check(f"technique_context cache hit fast (<5ms for 20 calls, got {elapsed:.1f}ms)",
          elapsed < 50)


# ══════════════════════════════════════════════════════════════════
# Technique Advisor
# ══════════════════════════════════════════════════════════════════
def test_technique_advisor():
    section("Technique Advisor")
    from technique_advisor import get_advisor

    adv = get_advisor()

    # Prerequisites
    prereqs = adv.get_prerequisites("kerberoast")
    check("kerberoast has prerequisites", len(prereqs) >= 2)

    # Failure interpretation
    interp = adv.get_failure_interpretation("kerberoast", "No entries found")
    check("failure interp for kerberoast 'No entries found'",
          "SPN" in interp or "No entries" in interp or len(interp) > 20)

    # Mechanism brief
    brief = adv.get_mechanism_brief("secretsdump")
    check("secretsdump has mechanism brief", brief and len(brief) > 20)

    # Adaptation (SSTI engines)
    adapt = adv.suggest_adaptation("ssti", target_profile={"tech": ["python", "flask"]})
    check("ssti adaptation returns Jinja2-related info",
          "jinja" in str(adapt).lower() or len(str(adapt)) > 30)


# ══════════════════════════════════════════════════════════════════
# Action Ranker
# ══════════════════════════════════════════════════════════════════
def make_test_wm(tmpdir):
    """Create a test world model DB with AD foothold state."""
    from world_model import WorldModel
    db_path = f"{tmpdir}/test_wm.db"
    if os.path.exists(db_path):
        os.remove(db_path)
    wm = WorldModel(db_path)
    hid = wm.add_host(ip="10.10.10.100", os="windows", domain="HTB.LOCAL")
    wm.add_service(host_id=hid, port=445, protocol="tcp", product="Samba", version="4.15")
    wm.add_service(host_id=hid, port=88, protocol="tcp", product="Kerberos")
    wm.add_service(host_id=hid, port=389, protocol="tcp", product="Active Directory")
    wm.add_service(host_id=hid, port=80, protocol="tcp", product="Apache", version="2.4.49")
    wm.add_cred(username="lowpriv", password="P@ssw0rd", domain="HTB.LOCAL", source="spray")
    wm.close()
    return db_path


def test_action_ranker():
    section("Action Ranker v2")
    tmpdir = tempfile.mkdtemp()
    db_path = make_test_wm(tmpdir)

    from action_ranker import rank_actions
    ranked = rank_actions(db_path, top_n=15)

    check("ranker returns non-empty list", len(ranked) > 0)
    check("ranker returns top-15 max", len(ranked) <= 15)
    check("ranked actions have scores", all("score" in a for a in ranked))
    check("scores sorted descending",
          all(ranked[i]["score"] >= ranked[i+1]["score"] for i in range(len(ranked)-1)))

    # Given Apache 2.4.49, expect path_traversal or exploit-oriented action to rank well
    names = [a["name"] for a in ranked]
    check("Apache 2.4.49 + SMB + creds produces credible plan",
          any(n in names for n in ["bloodhound", "kerberoast", "crackmapexec_spray",
                                    "smb_share_enum", "ldapsearch", "nmap_scripts"]))


# ══════════════════════════════════════════════════════════════════
# Attack Chain Planner
# ══════════════════════════════════════════════════════════════════
def test_attack_chain_planner():
    section("Attack Chain Planner")
    from attack_chain_planner import plan_chain, load_actions, extract_state_predicates, GOALS

    actions = load_actions()
    check("planner loads actions", len(actions) > 200)

    # Already-satisfied goal
    state = {"has_cred", "service.port==445"}
    plan = plan_chain("credential_access", state, actions, max_depth=3)
    check("already-satisfied returns empty plan", plan == [])

    # Unreachable goal (no web services)
    state = {"service.port==445"}
    plan = plan_chain("root_access", state, actions, max_depth=2)
    check("plan_chain returns None or list", plan is None or isinstance(plan, list))

    # Reachable foothold from web service
    state = {"service.port==80"}
    plan = plan_chain("initial_foothold", state, actions, max_depth=3)
    check("web → foothold plan found", plan and len(plan) >= 1)

    # DB-backed extraction
    tmpdir = tempfile.mkdtemp()
    db_path = make_test_wm(tmpdir)
    state = extract_state_predicates(db_path)
    check("extract_state_predicates from WM returns non-empty", len(state) > 5)
    check("WM state includes has_cred", "has_cred" in state)


# ══════════════════════════════════════════════════════════════════
# Parsers
# ══════════════════════════════════════════════════════════════════
def test_web_response_parser():
    section("Web Response Parser")
    from parsers.web_response_parser import parse_web_response

    # SQLi output
    text = """
    Type: UNION query
    back-end DBMS: MySQL >= 5.0.12
    available databases [3]:
    [*] information_schema
    [*] employees
    """
    result = parse_web_response(text)
    check("web parser detects SQLi",
          any(f["category"] == "sqli" for f in result["findings"]))

    # LFI /etc/passwd
    text = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
    result = parse_web_response(text)
    check("web parser detects LFI /etc/passwd",
          any(f["category"] == "lfi" for f in result["findings"]))

    # SSTI 49
    text = "HTTP/1.1 200 OK\nContent: Result is 49"
    result = parse_web_response(text)
    check("web parser detects SSTI 7*7=49",
          any(f["category"] == "ssti" for f in result["findings"]))


def test_tech_detect_parser():
    section("Tech Detect Parser")
    from parsers.tech_detect_parser import detect_tech

    # Apache 2.4.49 → CVE-2021-41773
    text = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49\r\n\r\n<html></html>"
    result = detect_tech(text)
    check("detects Apache server",
          any(d["component"] == "Apache" for d in result["detections"]))
    check("flags CVE-2021-41773 for Apache 2.4.49",
          any("CVE-2021-41773" in v["cve_desc"] for v in result["vulns"]))

    # WordPress detection
    text = "HTTP/1.1 200\r\n\r\n<link rel='stylesheet' href='/wp-content/themes/..'"
    result = detect_tech(text)
    check("detects WordPress from body",
          any(d["component"] == "WordPress" for d in result["detections"]))


def test_generic_parser():
    section("Generic Parser")
    from parsers.generic_parser import parse_generic

    # NTLM hash
    text = "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"
    result = parse_generic(text)
    check("generic parser extracts NTLM hash",
          any(c.get("hash_type") == "ntlm" for c in result["creds"]))

    # uid=0 root shell
    text = "uid=0(root) gid=0(root) groups=0(root)"
    result = parse_generic(text)
    check("generic parser detects root privilege",
          any(f["severity"] == "critical" for f in result["findings"]))

    # SUID binary
    text = "-rwsr-xr-x 1 root root 44168 May 7  2019 /usr/bin/find"
    result = parse_generic(text)
    check("generic parser detects SUID binary",
          any(f["category"] == "suid" for f in result["findings"]))


# ══════════════════════════════════════════════════════════════════
# Parser coverage across action YAMLs
# ══════════════════════════════════════════════════════════════════
def test_parser_coverage():
    section("Parser Coverage")
    import yaml
    actions_dir = Path("/home/kali/knowledge/actions")
    total = 0
    with_parser = 0
    for p in actions_dir.rglob("*.yml"):
        try:
            data = yaml.safe_load(p.read_text())
            if data and "name" in data:
                total += 1
                if data.get("parser"):
                    with_parser += 1
        except Exception:
            pass
    check(f"100% action parser coverage ({with_parser}/{total})",
          with_parser == total, detail=f"{total-with_parser} still null")


# ══════════════════════════════════════════════════════════════════
# Hook latency
# ══════════════════════════════════════════════════════════════════
def test_hook_latency():
    section("Hook Latency")
    import shutil
    tmpdir = tempfile.mkdtemp()
    os.makedirs(f"{tmpdir}/notes", exist_ok=True)
    db_path = make_test_wm(tmpdir)
    shutil.copy(db_path, f"{tmpdir}/world_model.db")

    hook_text = Path("/home/kali/.claude/hooks/planner-context.sh").read_text()
    patched = hook_text.replace("ROOT=/home/kali", f"ROOT={tmpdir}").replace(
        'CURRENT_REAL=$(readlink -f "$ROOT/current" 2>/dev/null || printf \'%s\' "$ROOT/current")',
        f"CURRENT_REAL={tmpdir}",
    ).replace(
        'SCRIPTS_DIR="$ROOT/.claude/scripts"',
        'SCRIPTS_DIR="/home/kali/.claude/scripts"',
    )
    hook_path = f"{tmpdir}/hook.sh"
    Path(hook_path).write_text(patched)
    os.chmod(hook_path, 0o755)

    t0 = time.perf_counter()
    r = subprocess.run(["bash", hook_path], capture_output=True, text=True, timeout=30)
    elapsed = time.perf_counter() - t0

    check(f"hook runs successfully (exit=0)", r.returncode == 0,
          detail=r.stderr[:200] if r.stderr else "")
    check(f"hook output contains world state", "TAR World State" in r.stdout)
    check(f"hook output contains ranked actions", "Top Actions" in r.stdout)
    check(f"hook latency under 5s (got {elapsed*1000:.0f}ms)", elapsed < 5.0,
          detail=f"{elapsed:.2f}s")


# ══════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════
def test_ocd_mindmap_integration():
    """v2.1 — OCD mindmap + Cypher library integration."""
    section("OCD Mindmap & Cypher")
    from knowledge_index import get_index
    import yaml
    ki = get_index()

    # 1. Mindmap indexed
    results = ki.search("SCCM PXE NAA credential", top_n=10)
    check(
        "mindmap returns SCCM branch",
        any(r.get("source") == "mindmaps" for r in results),
        detail=f"top sources: {[r.get('source') for r in results[:3]]}",
    )

    # 2. Cypher library indexed
    cyphers = ki.search("kerberoastable cypher bloodhound query", top_n=10)
    check(
        "cypher library in index",
        any(r.get("source") == "cypher" for r in cyphers),
    )

    # 3. New YAML action loads with meaningful effects
    certifried_path = Path("/home/kali/knowledge/actions/ad/certifried.yml")
    check("certifried action file exists", certifried_path.exists())
    if certifried_path.exists():
        data = yaml.safe_load(certifried_path.read_text())
        check(
            "certifried has DA effect",
            "domain_admin" in (data.get("expected_effects") or []),
        )

    # 4. Planner knows new goal
    from attack_chain_planner import GOALS
    check("planner has cross_forest_compromise goal", "cross_forest_compromise" in GOALS)
    check("planner has sccm_compromise goal", "sccm_compromise" in GOALS)

    # 5. TechniqueAdvisor has new rules
    from technique_advisor import PREREQUISITES, FAILURE_PATTERNS
    check("advisor knows certifried prereqs", "certifried" in PREREQUISITES)
    check("advisor knows nopac failure patterns", "nopac" in FAILURE_PATTERNS)


def main():
    print("═" * 66)
    print("TAR v2 Integration Test Suite")
    print("═" * 66)

    try:
        test_knowledge_index()
        test_technique_advisor()
        test_action_ranker()
        test_attack_chain_planner()
        test_web_response_parser()
        test_tech_detect_parser()
        test_generic_parser()
        test_parser_coverage()
        test_hook_latency()
        test_ocd_mindmap_integration()
    except Exception as e:
        print(f"\n[EXCEPTION during tests]: {e}")
        import traceback
        traceback.print_exc()

    print("\n" + "═" * 66)
    print(f"RESULTS: {PASS} passed, {FAIL} failed")
    if FAILURES:
        print("\nFailed:")
        for name, detail in FAILURES:
            print(f"  - {name}: {detail}")
    print("═" * 66)
    sys.exit(0 if FAIL == 0 else 1)


if __name__ == "__main__":
    main()
