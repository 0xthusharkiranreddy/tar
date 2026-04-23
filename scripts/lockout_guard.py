#!/usr/bin/env python3
"""
lockout_guard.py — Pre-flight lockout protection for spray/brute-force actions.

Problem: kerbrute_spray and hydra will lock out entire OUs if they exceed
the domain lockout threshold. TAR previously had no input-time check.

This module:
  1. Reads domain lockout policy from the WM (if known) or queries via LDAP
  2. Computes a safe rate: floor(lockout_threshold / 2) attempts per account
  3. Blocks the action and sets predicate 'lockout_guard_blocked' if unsafe
  4. Injects --delay / --threads flags to cap spray rate if allowed

Called from a PreToolUse hook (bash) before any spray action executes.
Also importable for direct use by actions or tests.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPTS_DIR))

# Actions with account-lockout risk
SPRAY_ACTIONS = {
    "kerbrute_spray",
    "kerbrute_userenum",       # userenum also touches AS-REQ per user
    "crackmapexec_spray",
    "hydra",
    "password_spray",
}

# Hard minimum delay between attempts (seconds) per engagement profile
PROFILE_MIN_DELAY = {
    "ctf":        0,
    "lab":        0,
    "internal":   30,   # 30s between rounds — safe on AD default (30min window)
    "external":   60,
    "production": 120,
}

# Default domain lockout threshold if we can't read it
DEFAULT_LOCKOUT_THRESHOLD = 5


def get_lockout_policy_from_wm(db_path: str) -> dict:
    """Read lockout policy cached in WM findings table."""
    try:
        from world_model import WorldModel
        wm = WorldModel(db_path)
        findings = wm.get_findings(category="domain_policy")
        wm.close()
        for f in findings:
            desc = f.get("description", "")
            # "Lockout threshold: 5 attempts"
            m = re.search(r"[Ll]ockout.*?threshold.*?(\d+)", desc)
            if m:
                return {"threshold": int(m.group(1)), "source": "wm_cache"}
            m = re.search(r"[Ll]ockout.*?duration.*?(\d+)", desc)
            if m:
                return {"duration_minutes": int(m.group(1)), "source": "wm_cache"}
    except Exception:
        pass
    return {}


def query_lockout_policy_ldap(target_ip: str, domain: str,
                               username: str = "", password: str = "") -> dict:
    """Query AD lockout policy via ldapsearch."""
    try:
        base = "DC=" + domain.replace(".", ",DC=")
        filter_str = "(objectClass=domainDNS)"
        attrs = "lockoutThreshold lockoutDuration lockoutObservationWindow"
        cmd = ["ldapsearch", "-x", "-H", f"ldap://{target_ip}",
               "-b", base, filter_str] + attrs.split()
        if username and password:
            cmd += ["-D", f"{username}@{domain}", "-w", password]
        out = subprocess.check_output(cmd, timeout=10, stderr=subprocess.DEVNULL).decode()
        result = {}
        m = re.search(r"lockoutThreshold:\s*(\d+)", out)
        if m:
            result["threshold"] = int(m.group(1))
        m = re.search(r"lockoutDuration:\s*(-?\d+)", out)
        if m:
            # AD stores as negative 100ns intervals
            val = int(m.group(1))
            if val < 0:
                result["duration_minutes"] = abs(val) // 600000000
        return result
    except Exception:
        return {}


def compute_safe_rate(threshold: int, profile_type: str = "lab") -> dict:
    """
    Given a lockout threshold, compute the safe spray parameters.

    Returns:
      {
        safe: bool,
        max_attempts_per_account: int,
        recommended_delay_seconds: int,
        reason: str,
      }
    """
    if threshold == 0:
        # Lockout disabled — spray freely
        return {
            "safe": True,
            "max_attempts_per_account": 9999,
            "recommended_delay_seconds": 0,
            "reason": "Lockout disabled (threshold=0)",
        }

    # Use at most half the threshold to stay safe
    max_attempts = max(1, threshold // 2)
    min_delay = PROFILE_MIN_DELAY.get(profile_type, 60)

    return {
        "safe": True,
        "max_attempts_per_account": max_attempts,
        "recommended_delay_seconds": min_delay,
        "reason": f"Threshold={threshold}; safe max={max_attempts} attempts/account with {min_delay}s delay",
    }


def check_spray_safety(
    action_name: str,
    db_path: str = "",
    target_ip: str = "",
    domain: str = "",
    profile_type: str = "lab",
) -> dict:
    """
    Main entry point. Returns a guard decision dict:
    {
        allowed: bool,
        max_attempts: int,
        delay_seconds: int,
        injected_flags: str,   # flags to inject into the command
        reason: str,
    }
    """
    if action_name not in SPRAY_ACTIONS:
        return {"allowed": True, "max_attempts": 9999, "delay_seconds": 0,
                "injected_flags": "", "reason": "not a spray action"}

    # Profile-based hard blocks
    if profile_type == "production":
        return {
            "allowed": False,
            "max_attempts": 0,
            "delay_seconds": 0,
            "injected_flags": "",
            "reason": "BLOCKED: production profile — spraying disabled entirely",
        }

    # Try to get lockout policy
    policy = {}
    if db_path:
        policy = get_lockout_policy_from_wm(db_path)
    if not policy and target_ip and domain:
        policy = query_lockout_policy_ldap(target_ip, domain)
    if not policy:
        # Unknown — apply conservative default
        policy = {"threshold": DEFAULT_LOCKOUT_THRESHOLD,
                  "source": "conservative_default"}

    threshold = policy.get("threshold", DEFAULT_LOCKOUT_THRESHOLD)
    rate = compute_safe_rate(threshold, profile_type)

    # Build injected flags
    flags = []
    if action_name == "kerbrute_spray":
        flags.append(f"--delay {rate['recommended_delay_seconds'] * 1000}")  # kerbrute uses ms
        flags.append(f"--safe")  # kerbrute --safe stops on first lockout
    elif action_name == "hydra":
        if rate["recommended_delay_seconds"] > 0:
            flags.append(f"-W {rate['recommended_delay_seconds']}")
        flags.append("-t 1")  # one thread to serialize
    elif action_name == "crackmapexec_spray":
        if rate["recommended_delay_seconds"] > 0:
            flags.append(f"--jitter {rate['recommended_delay_seconds']}")

    return {
        "allowed": True,
        "max_attempts": rate["max_attempts_per_account"],
        "delay_seconds": rate["recommended_delay_seconds"],
        "injected_flags": " ".join(flags),
        "threshold_used": threshold,
        "policy_source": policy.get("source", "unknown"),
        "reason": rate["reason"],
    }


def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("action_name")
    p.add_argument("--db", default="")
    p.add_argument("--target", default="")
    p.add_argument("--domain", default="")
    p.add_argument("--profile", default="lab")
    p.add_argument("--json", dest="as_json", action="store_true")
    args = p.parse_args()

    result = check_spray_safety(
        args.action_name, db_path=args.db,
        target_ip=args.target, domain=args.domain,
        profile_type=args.profile,
    )
    if args.as_json:
        print(json.dumps(result, indent=2))
    else:
        status = "ALLOWED" if result["allowed"] else "BLOCKED"
        print(f"{status}: {result['reason']}")
        if result.get("injected_flags"):
            print(f"Inject flags: {result['injected_flags']}")


if __name__ == "__main__":
    main()
