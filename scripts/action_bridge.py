"""
action_bridge.py — Translate TAR YAML actions into workstation-executable
command blocks for the internal red team agent.

The agent runs commands in one of four modes. The bridge picks the right
mode per action and assembles the command body + parameters:

  powershell_native  — in-process PowerShell using an agent/actions/*.ps1 file
  sharpcollection    — .NET binary (Rubeus, Seatbelt, SharpHound, Certify);
                       agent downloads from server-hosted .b64 blob, reflect-loads
  impacket_via_kali  — impacket-only; agent emits `need_kali` predicate so the
                       operator runs it on Kali and pipes output back
  native_exec        — cmd.exe built-ins (whoami, tasklist, nltest)

MVP maps 15 canonical actions covering OCD mindmap branches 1–3.

Usage:
    python3 action_bridge.py translate <action_name> [--params k=v ...]
    python3 action_bridge.py list
    python3 action_bridge.py status
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# ── Constants ─────────────────────────────────────────────────────────
REPO = Path(__file__).resolve().parent.parent
PS_ACTIONS_DIR = REPO / "agent" / "actions"
SHARP_BLOBS_DIR = REPO / "agent" / "sharp_blobs"  # base64-encoded .NET DLLs


# ── Action → exec_mode mapping ────────────────────────────────────────
# Keys are TAR YAML action names (from actions/ad/*.yml).
# For MVP we ship 15 — covering mindmap branches 1, 2, 3 (Scan/DC/LDAP enum,
# user list, spray+discovery, credential capture).

ACTION_MAP: dict[str, dict] = {
    # ── Branch 1: local network & domain recon ────────────────────────
    "net_recon_local": {
        "exec_mode": "powershell_native",
        "ps_file": "net_recon_local.ps1",
        "description": "Enumerate local network interfaces, ARP cache, routes",
    },
    "domain_enum": {
        "exec_mode": "powershell_native",
        "ps_file": "domain_enum.ps1",
        "description": "Current domain info via Get-ADDomain + nltest fallback",
    },
    "user_enum": {
        "exec_mode": "powershell_native",
        "ps_file": "user_enum.ps1",
        "description": "Enumerate domain users with Get-ADUser",
        "required_params": [],
    },
    "group_enum": {
        "exec_mode": "powershell_native",
        "ps_file": "group_enum.ps1",
        "description": "Privileged AD groups and membership",
    },
    "computer_enum": {
        "exec_mode": "powershell_native",
        "ps_file": "computer_enum.ps1",
        "description": "All domain computers + OS version",
    },
    "spn_enum": {
        "exec_mode": "powershell_native",
        "ps_file": "spn_enum.ps1",
        "description": "Accounts with SPNs (kerberoast candidates)",
    },

    # ── Branch 2: Kerberos attacks via .NET ───────────────────────────
    "kerberoast": {
        "exec_mode": "sharpcollection",
        "ps_file": "kerberoast.ps1",
        "tool": "Rubeus.exe",
        "description": "Kerberoast all SPNs visible to the current user",
    },
    "asreproast": {
        "exec_mode": "sharpcollection",
        "ps_file": "asreproast.ps1",
        "tool": "Rubeus.exe",
        "description": "AS-REP roast users with pre-auth disabled",
    },
    "bloodhound_sharphound": {
        "exec_mode": "sharpcollection",
        "ps_file": "bloodhound_sharphound.ps1",
        "tool": "SharpHound.exe",
        "description": "Collect BloodHound data (DCOnly by default)",
    },

    # ── Branch 3: local privilege + discovery ─────────────────────────
    "local_admin_enum": {
        "exec_mode": "powershell_native",
        "ps_file": "local_admin_enum.ps1",
        "description": "Local admins on this box + token privileges",
    },
    "gpp_password": {
        "exec_mode": "powershell_native",
        "ps_file": "gpp_password.ps1",
        "description": "Hunt cpassword in SYSVOL Group Policy Preferences",
    },
    "laps_read": {
        "exec_mode": "powershell_native",
        "ps_file": "laps_read.ps1",
        "description": "Read ms-Mcs-AdmPwd attribute where readable",
    },
    "adcs_enum_certify": {
        "exec_mode": "sharpcollection",
        "ps_file": "adcs_enum_certify.ps1",
        "tool": "Certify.exe",
        "description": "Enumerate ADCS templates (find vulnerable ESC1-15)",
    },

    # ── Spray & detection ─────────────────────────────────────────────
    "password_spray_local": {
        "exec_mode": "powershell_native",
        "ps_file": "password_spray_local.ps1",
        "description": "Spray a single password against discovered users",
        "requires_lockout_guard": True,
    },
    "responder_detect": {
        "exec_mode": "native_exec",
        "ps_file": "responder_detect.ps1",
        "description": "Check segment for rogue Responder-style NBNS/LLMNR poisoners",
    },
}


# Actions the agent doesn't run — operator executes on Kali and pipes back.
NEEDS_KALI = {
    "ntlmrelayx",
    "getTGT",
    "getST",
    "secretsdump",
    "psexec",
    "wmiexec",
    "atexec",
    "dcomexec",
    "petitpotam",
    "printerbug",
}


# ── Parameter interpolation ──────────────────────────────────────────
def _resolve_params(template: str, params: dict[str, str]) -> str:
    """Substitute {key} tokens in the PowerShell template with values.

    Unfilled params stay as literal {key} so the agent can reject the
    command server-side before executing.
    """
    out = template
    for k, v in params.items():
        out = out.replace("{" + k + "}", str(v))
    return out


def _lockout_flags(params: dict) -> str:
    """Insert lockout-guard flags into the command body for spray actions."""
    delay = int(params.get("delay_seconds", 30))
    attempts = int(params.get("max_attempts", 3))
    return f"-DelaySeconds {delay} -MaxAttempts {attempts}"


# ── Translation ───────────────────────────────────────────────────────
def translate(action_name: str, params: dict) -> dict:
    """Produce a queue-ready command dict for the /api/v1/command endpoint.

    Returns:
        {
            "action_name": str,
            "exec_mode": str,
            "command_body": str,
            "parameters": dict,
            "need_kali": bool,
            "error": Optional[str],
        }
    """
    params = dict(params or {})

    if action_name in NEEDS_KALI:
        return {
            "action_name": action_name,
            "exec_mode": "impacket_via_kali",
            "command_body": "",
            "parameters": params,
            "need_kali": True,
            "error": None,
            "note": f"Action {action_name} requires impacket — run on Kali",
        }

    spec = ACTION_MAP.get(action_name)
    if not spec:
        return {
            "action_name": action_name,
            "exec_mode": "",
            "command_body": "",
            "parameters": params,
            "need_kali": False,
            "error": f"action_not_mapped:{action_name}",
        }

    ps_path = PS_ACTIONS_DIR / spec["ps_file"]
    if not ps_path.is_file():
        return {
            "action_name": action_name,
            "exec_mode": spec["exec_mode"],
            "command_body": "",
            "parameters": params,
            "need_kali": False,
            "error": f"ps_file_missing:{spec['ps_file']}",
        }

    template = ps_path.read_text()
    body = _resolve_params(template, params)

    if spec.get("requires_lockout_guard"):
        params.setdefault("lockout_flags", _lockout_flags(params))
        body = body.replace("{lockout_flags}", params["lockout_flags"])

    params["_exec_mode_hint"] = spec["exec_mode"]
    if spec.get("tool"):
        params["_sharp_tool"] = spec["tool"]

    return {
        "action_name": action_name,
        "exec_mode": spec["exec_mode"],
        "command_body": body,
        "parameters": params,
        "need_kali": False,
        "error": None,
    }


def list_actions() -> list[dict]:
    return [{"name": k, **v} for k, v in ACTION_MAP.items()]


def status() -> dict:
    missing = []
    present = []
    for name, spec in ACTION_MAP.items():
        ps = PS_ACTIONS_DIR / spec["ps_file"]
        if ps.is_file():
            present.append(name)
        else:
            missing.append(f"{name} (needs {spec['ps_file']})")
    return {
        "total_mapped": len(ACTION_MAP),
        "present": len(present),
        "missing_ps_files": missing,
        "kali_only_actions": sorted(NEEDS_KALI),
    }


def main() -> int:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    tp = sub.add_parser("translate")
    tp.add_argument("action")
    tp.add_argument("--params", nargs="*", default=[],
                    help="key=value pairs")

    sub.add_parser("list")
    sub.add_parser("status")

    args = p.parse_args()
    if args.cmd == "translate":
        params = dict(kv.split("=", 1) for kv in args.params if "=" in kv)
        out = translate(args.action, params)
        print(json.dumps(out, indent=2))
    elif args.cmd == "list":
        for item in list_actions():
            print(f"{item['name']:<28} {item['exec_mode']:<20} {item.get('description','')}")
    elif args.cmd == "status":
        print(json.dumps(status(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
