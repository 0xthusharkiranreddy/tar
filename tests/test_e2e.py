#!/usr/bin/env python3
"""
TAR End-to-End Integration Test

Simulates a full engagement cycle without hitting a real target:
1. Init engagement + world_model
2. Simulate nmap output → parse into world_model
3. Run planner: rank actions + fill params
4. Simulate action execution + post-action parsing
5. Phase advancement detection
6. Phase compaction
7. Failure recording + reasoning injection
8. Cost escalation trigger
9. Session-end compaction

Each step asserts expected state changes.
"""

import json
import os
import sys
import subprocess
import tempfile
from pathlib import Path

sys.path.insert(0, "/home/kali/.claude/scripts")

PASS = 0
FAIL = 0


def check(label, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {label}")
    else:
        FAIL += 1
        print(f"  [FAIL] {label} — {detail}")


# ═══════════════════════════════════════════════════════════════
# SETUP
# ═══════════════════════════════════════════════════════════════
print("=" * 70)
print("TAR End-to-End Integration Test")
print("=" * 70)

TEST_DIR = tempfile.mkdtemp(prefix="tar_e2e_")
DB_PATH = os.path.join(TEST_DIR, "world_model.db")
NOTES_DIR = os.path.join(TEST_DIR, "notes")
os.makedirs(NOTES_DIR, exist_ok=True)

print(f"\nTest dir: {TEST_DIR}")

# ═══════════════════════════════════════════════════════════════
# STEP 1: Initialize engagement
# ═══════════════════════════════════════════════════════════════
print("\n── Step 1: Initialize engagement ──")
from world_model import WorldModel

wm = WorldModel(DB_PATH)
eid = wm.init_engagement("htb-testbox", "10.10.11.200", "balanced")
hid = wm.add_host("10.10.11.200")

check("Engagement created", eid > 0, f"eid={eid}")
check("Host added", hid > 0)
check("Phase is recon", wm.current_phase() == "recon")
check("Predicates has has_target", "has_target" in wm.get_state_predicates())
wm.close()

# ═══════════════════════════════════════════════════════════════
# STEP 2: Simulate nmap scan → parse into world_model
# ═══════════════════════════════════════════════════════════════
print("\n── Step 2: Simulate nmap scan + parse ──")

# Write fake nmap XML
nmap_xml = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
<host><address addr="10.10.11.200" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9p1"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.4.52"/></port>
<port protocol="tcp" portid="3306"><state state="open"/><service name="mysql" product="MySQL" version="8.0"/></port>
</ports>
</host>
</nmaprun>"""

nmap_file = os.path.join(TEST_DIR, "nmap_full.xml")
Path(nmap_file).write_text(nmap_xml)

# Parse via nmap_parser
result = subprocess.run(
    ["python3", "/home/kali/.claude/scripts/parsers/nmap_parser.py",
     nmap_file, "--db", DB_PATH],
    capture_output=True, text=True
)
check("Nmap parser ran", result.returncode == 0, result.stderr[:100] if result.stderr else "")

wm = WorldModel(DB_PATH)
services = wm.get_services()
check("Services parsed", len(services) >= 3, f"got {len(services)}")
check("SSH detected", any(s["port"] == 22 for s in services))
check("HTTP service detected", any(s["port"] == 80 for s in services))
check("MySQL detected", any(s["port"] == 3306 for s in services))

preds = wm.get_state_predicates()
check("service.port==22 in predicates", "service.port==22" in preds)
check("service.port==80 in predicates", "service.port==80" in preds)
wm.close()

# ═══════════════════════════════════════════════════════════════
# STEP 3: Action ranking
# ═══════════════════════════════════════════════════════════════
print("\n── Step 3: Action ranking ──")
from action_ranker import rank_actions, get_current_phase

# Clear cache
import action_ranker
action_ranker._transition_cache = None
action_ranker._phase_freq_cache = None

phase = get_current_phase(DB_PATH)
check("Phase is recon", phase == "recon")

# After nmap_full, nmap_scripts should be top ranked
ranked = rank_actions(DB_PATH, last_action="nmap_full", top_n=10)
check("Ranked actions returned", len(ranked) > 0, f"got {len(ranked)}")
check("nmap_scripts is #1 after nmap_full", ranked[0]["name"] == "nmap_scripts",
      f"got {ranked[0]['name']}" if ranked else "empty")

# Without last_action, recon actions should dominate
ranked2 = rank_actions(DB_PATH, top_n=5)
recon_in_top3 = sum(1 for r in ranked2[:3] if r["category"] in ("recon", "web", "smb"))
check("Recon/web/smb dominate top-3", recon_in_top3 >= 2, f"got {recon_in_top3}")

# ═══════════════════════════════════════════════════════════════
# STEP 4: Parameter filling
# ═══════════════════════════════════════════════════════════════
print("\n── Step 4: Parameter filling ──")
from param_filler import fill_action, fill_multiple

result = fill_action(DB_PATH, "nmap_scripts")
check("nmap_scripts filled", result.get("ready", False), f"unfilled: {result.get('unfilled')}")
check("Command has target IP", "10.10.11.200" in result.get("command", ""))
check("Command has ports", "22" in result.get("command", "") and "80" in result.get("command", ""))

result2 = fill_action(DB_PATH, "ssh")
check("ssh action filled", result2.get("ready", False) or "username" in result2.get("unfilled", []),
      f"unfilled: {result2.get('unfilled')}")

# Add a credential and test again
wm = WorldModel(DB_PATH)
wm.add_cred(username="webadmin", password="Passw0rd!", source="config_file", verified=True)
wm.close()

result3 = fill_action(DB_PATH, "ssh")
check("ssh fills after cred added", result3.get("ready", False), f"unfilled: {result3.get('unfilled')}")
check("ssh command has username", "webadmin" in result3.get("command", ""))

# Batch fill
batch = fill_multiple(DB_PATH, ["nmap_scripts", "feroxbuster", "ssh", "hydra"])
ready_count = sum(1 for b in batch if b.get("ready"))
check("Batch fill: ≥3 ready", ready_count >= 3, f"got {ready_count}/{len(batch)}")

# ═══════════════════════════════════════════════════════════════
# STEP 5: Phase advancement
# ═══════════════════════════════════════════════════════════════
print("\n── Step 5: Phase advancement ──")
wm = WorldModel(DB_PATH)

# With 3 version-scanned services, should advance from recon → foothold
check("Phase still recon", wm.current_phase() == "recon")
new_phase = wm.maybe_advance_phase()
check("Advanced to foothold", new_phase == "foothold", f"got {new_phase}")
check("Phase is now foothold", wm.current_phase() == "foothold")

# With a password cred, should advance foothold → user
new_phase2 = wm.maybe_advance_phase()
check("Advanced to user", new_phase2 == "user", f"got {new_phase2}")
wm.close()

# ═══════════════════════════════════════════════════════════════
# STEP 6: Phase compaction
# ═══════════════════════════════════════════════════════════════
print("\n── Step 6: Phase compaction ──")
from phase_compact import phase_boundary, session_end

delta = phase_boundary(DB_PATH)
check("Phase delta generated", len(delta) > 100, f"length={len(delta)}")
check("Delta mentions services", "10.10.11.200:22" in delta)
check("Delta mentions creds", "webadmin" in delta)
check("Delta mentions phase", "user" in delta.lower())

compact = session_end(DB_PATH)
check("Session compact generated", len(compact) > 50)
check("Compact has engagement name", "htb-testbox" in compact)

# Write to file
compact_path = os.path.join(NOTES_DIR, "compaction_state.md")
Path(compact_path).write_text(delta)
check("Compaction file written", Path(compact_path).exists())

# ═══════════════════════════════════════════════════════════════
# STEP 7: Failure recording + reasoning
# ═══════════════════════════════════════════════════════════════
print("\n── Step 7: Failure recording ──")
wm = WorldModel(DB_PATH)
wm.record_failure("sqli_union", {"url": "http://10.10.11.200/login"},
                  silence_pattern="no UNION columns found", error_output="error in SQL syntax")
wm.record_failure("lfi", {"url": "http://10.10.11.200/page?file="},
                  silence_pattern="empty response", error_output="")

failed = wm.get_failed_attempts()
check("Failures recorded", len(failed) >= 2, f"got {len(failed)}")
check("sqli_union in failures", any(f["action_name"] == "sqli_union" for f in failed))

# Check that failed actions are excluded from ranking
wm.close()
ranked = rank_actions(DB_PATH, top_n=50)
ranked_names = {r["name"] for r in ranked}
check("sqli_union excluded from rankings", "sqli_union" not in ranked_names)
check("lfi excluded from rankings", "lfi" not in ranked_names)

# ═══════════════════════════════════════════════════════════════
# STEP 8: Cost routing + auto-escalation
# ═══════════════════════════════════════════════════════════════
print("\n── Step 8: Cost routing ──")
from cost_router import get_model, record_critic_failure, record_success, get_status

model = get_model(DB_PATH, "planner")
check("Balanced planner = sonnet", model == "sonnet", f"got {model}")

model2 = get_model(DB_PATH, "executor")
check("Balanced executor = haiku", model2 == "haiku", f"got {model2}")

# Trigger escalation
record_critic_failure(DB_PATH)
record_critic_failure(DB_PATH)
result = record_critic_failure(DB_PATH)
check("Escalation triggered", "ESCALATED" in result, result)

model3 = get_model(DB_PATH, "planner")
check("Escalated planner = opus", model3 == "opus", f"got {model3}")

# Success resets counter
record_success(DB_PATH)
status = get_status(DB_PATH)
phase_rec = next((p for p in status["phases"] if p["phase"] == "user"), None)
check("Success resets failure counter", phase_rec and phase_rec["failures"] == 0,
      f"failures={phase_rec['failures'] if phase_rec else '?'}")

# ═══════════════════════════════════════════════════════════════
# STEP 9: Predicate ledger (cross-engagement)
# ═══════════════════════════════════════════════════════════════
print("\n── Step 9: Cross-engagement predicate ledger ──")
from predicate_ledger import PredicateLedger

pl = PredicateLedger()
fp = pl.compute_fingerprint(os_name="linux", services=[(22, "OpenSSH"), (80, "Apache")])
check("Fingerprint generated", fp != "unknown", f"fp={fp}")

pl.record_failure("sqli_union", fp, "no UNION columns", "e2e-test")
pl.record_failure("sqli_union", fp, "no UNION columns", "e2e-test")
pl.record_failure("sqli_union", fp, "no UNION columns", "e2e-test")

blocked = pl.should_block("sqli_union", fp)
check("Action blocked after 3 failures", blocked)

not_blocked = pl.should_block("lfi", fp)
check("Other actions not blocked", not not_blocked)

pl.close()

# ═══════════════════════════════════════════════════════════════
# STEP 10: Full planner context output
# ═══════════════════════════════════════════════════════════════
print("\n── Step 10: Full planner context output ──")
from action_ranker import rank_actions as ra2
from param_filler import fill_multiple as fm2
from world_model import WorldModel as WM2

wm = WM2(DB_PATH)
summary = wm.get_state_summary()
phase = wm.current_phase()
wm.close()

ranked = ra2(DB_PATH, last_action="feroxbuster", top_n=5)
filled = fm2(DB_PATH, [r["name"] for r in ranked])

check("Planner output has ranked actions", len(ranked) >= 5)
check("All top-5 have scores > 0", all(r["score"] > 0 for r in ranked))

ready_in_top5 = sum(1 for f in filled if f.get("ready"))
check("≥3 of top-5 are ready (filled)", ready_in_top5 >= 3, f"got {ready_in_top5}")

# Check that the output includes mechanism info
has_mechanism = sum(1 for r in ranked if r.get("mechanism"))
check("All ranked actions have mechanisms", has_mechanism == len(ranked))

# ═══════════════════════════════════════════════════════════════
# RESULTS
# ═══════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print(f"RESULTS: {PASS} passed, {FAIL} failed out of {PASS + FAIL} checks")
print("=" * 70)

if FAIL > 0:
    sys.exit(1)
else:
    print("\nAll integration checks passed.")
    sys.exit(0)
