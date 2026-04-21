#!/usr/bin/env python3
"""
engagement_profile.py — Load and validate TAR engagement profile.

The profile lives at $ENGAGEMENT_DIR/engagement_profile.yml (or .json).
It controls: noise tolerance, destructive-action gating, lockout thresholds,
and engagement phase restrictions.

Schema:
  profile: ctf | lab | internal | external | production
  allow_destructive: true | false        # default false for internal/external/production
  lockout_threshold: int                 # max spray attempts before abort (default 3)
  noise_tolerance: low | medium | high   # maps to ranker penalty
  engagement_goal: str                   # free-text primary objective
  scope_cidrs: [str]                     # CIDR allow-list for targets
  scope_domains: [str]                   # domain allow-list
  out_of_scope: [str]                    # CIDRs or IPs to never touch
"""

import ipaddress
import json
import os
import sys
from pathlib import Path

try:
    import yaml
    _YAML = True
except ImportError:
    _YAML = False


# ── Defaults by profile type ─────────────────────────────────────────────────

PROFILE_DEFAULTS = {
    "ctf": {
        "allow_destructive": True,
        "lockout_threshold": 999,
        "noise_tolerance": "high",
        "destructive_penalty": 0,
        "noise_penalty": 0,
    },
    "lab": {
        "allow_destructive": True,
        "lockout_threshold": 50,
        "noise_tolerance": "high",
        "destructive_penalty": 0,
        "noise_penalty": 0,
    },
    "internal": {
        "allow_destructive": False,
        "lockout_threshold": 5,
        "noise_tolerance": "medium",
        "destructive_penalty": -50,   # ranker penalty for destructive actions
        "noise_penalty": -15,
    },
    "external": {
        "allow_destructive": False,
        "lockout_threshold": 3,
        "noise_tolerance": "low",
        "destructive_penalty": -100,  # effectively blocks destructive
        "noise_penalty": -25,
    },
    "production": {
        "allow_destructive": False,
        "lockout_threshold": 2,
        "noise_tolerance": "low",
        "destructive_penalty": -100,
        "noise_penalty": -30,
    },
}

# Actions that must be blocked unless allow_destructive is explicitly true
DESTRUCTIVE_ACTIONS = {
    "skeleton_key", "dc_shadow", "dsrm_password", "zerologon", "krbtgt_reset",
    "eternalblue", "smbghost", "wsus_attack", "custom_ssp",
    # account lockout risk
    "kerbrute_spray", "hydra",
}

# Actions that are noisy and get penalised on low noise_tolerance
HIGH_NOISE_ACTIONS = {
    "eternalblue", "smbghost", "printnightmare", "zerologon", "petitpotam_relay",
    "ntlmrelayx", "hydra", "kerbrute_spray",
    # exploit frameworks that spawn listeners
    "metasploit",
}


class EngagementProfile:
    def __init__(self, profile_path: str | Path = None, engagement_dir: str = None):
        self.raw = {}
        self.profile_type = "lab"

        # Try to load from path
        path = None
        if profile_path:
            path = Path(profile_path)
        elif engagement_dir:
            for name in ("engagement_profile.yml", "engagement_profile.yaml",
                         "engagement_profile.json", "scope.yml", "scope.yaml"):
                candidate = Path(engagement_dir) / name
                if candidate.exists():
                    path = candidate
                    break

        # Fallback: env var
        if not path:
            env_dir = os.environ.get("TAR_ENGAGEMENT_DIR", "")
            if env_dir:
                for name in ("engagement_profile.yml", "engagement_profile.yaml",
                             "engagement_profile.json", "scope.yml", "scope.yaml"):
                    candidate = Path(env_dir) / name
                    if candidate.exists():
                        path = candidate
                        break

        if path and path.exists():
            self._load(path)
        else:
            # No profile file — default to lab
            self.raw = {"profile": "lab"}
            self.profile_type = "lab"

        self._apply_defaults()

    def _load(self, path: Path):
        try:
            text = path.read_text()
            if path.suffix in (".yml", ".yaml") and _YAML:
                self.raw = yaml.safe_load(text) or {}
            else:
                self.raw = json.loads(text)
        except Exception:
            self.raw = {}
        self.profile_type = self.raw.get("profile", "lab")
        if self.profile_type not in PROFILE_DEFAULTS:
            self.profile_type = "lab"

    def _apply_defaults(self):
        defaults = PROFILE_DEFAULTS.get(self.profile_type, PROFILE_DEFAULTS["lab"])
        for k, v in defaults.items():
            if k not in self.raw:
                self.raw[k] = v

    # ── Query methods ────────────────────────────────────────────────────────

    @property
    def allow_destructive(self) -> bool:
        return bool(self.raw.get("allow_destructive", False))

    @property
    def lockout_threshold(self) -> int:
        return int(self.raw.get("lockout_threshold", 3))

    @property
    def noise_tolerance(self) -> str:
        return str(self.raw.get("noise_tolerance", "medium"))

    @property
    def engagement_goal(self) -> str:
        return str(self.raw.get("engagement_goal", ""))

    @property
    def destructive_penalty(self) -> float:
        return float(self.raw.get("destructive_penalty", -50))

    @property
    def noise_penalty(self) -> float:
        return float(self.raw.get("noise_penalty", -15))

    def action_score_modifier(self, action_name: str) -> float:
        """Return score modifier to apply to action_name based on profile."""
        penalty = 0.0

        if action_name in DESTRUCTIVE_ACTIONS:
            if not self.allow_destructive:
                penalty += self.destructive_penalty  # will be large negative

        if action_name in HIGH_NOISE_ACTIONS:
            if self.noise_tolerance == "low":
                penalty += self.noise_penalty
            elif self.noise_tolerance == "medium":
                penalty += self.noise_penalty / 2

        return penalty

    def is_in_scope(self, target: str) -> bool:
        """Return True if target IP/host is within scope_cidrs or scope_domains."""
        scope_cidrs = self.raw.get("scope_cidrs", [])
        scope_domains = self.raw.get("scope_domains", [])
        out_of_scope = self.raw.get("out_of_scope", [])

        # Always block out-of-scope
        if out_of_scope:
            for entry in out_of_scope:
                try:
                    if ipaddress.ip_address(target) in ipaddress.ip_network(entry, strict=False):
                        return False
                except ValueError:
                    if target == entry or target.endswith("." + entry):
                        return False

        # If no scope defined, allow everything (don't block)
        if not scope_cidrs and not scope_domains:
            return True

        # Check CIDR allow-list
        for cidr in scope_cidrs:
            try:
                if ipaddress.ip_address(target) in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                pass

        # Check domain allow-list
        for domain in scope_domains:
            if target == domain or target.endswith("." + domain):
                return True

        return False

    def summary(self) -> str:
        """One-line profile summary for hook injection."""
        return (
            f"Profile: {self.profile_type} | "
            f"DestructiveOK: {self.allow_destructive} | "
            f"Noise: {self.noise_tolerance} | "
            f"LockoutThreshold: {self.lockout_threshold} | "
            f"Goal: {self.engagement_goal or 'unset'}"
        )


# ── Template ─────────────────────────────────────────────────────────────────

TEMPLATE = """\
# TAR Engagement Profile
# Copy to your engagement directory as engagement_profile.yml
# Profile controls: noise, destructive-action gating, scope, lockout thresholds

profile: lab          # ctf | lab | internal | external | production
allow_destructive: true   # set false for internal/external/production
lockout_threshold: 20     # max spray attempts before abort
noise_tolerance: high     # low | medium | high
engagement_goal: "Obtain domain admin and exfiltrate proof.txt"

# Scope (leave empty to allow all — NOT recommended for real engagements)
scope_cidrs:
  # - "10.0.0.0/8"
scope_domains:
  # - "lab.internal"
out_of_scope:
  # - "10.0.0.1"   # gateway — do not touch
"""


def write_template(dest: Path):
    dest.write_text(TEMPLATE)
    print(f"Template written to {dest}", file=sys.stderr)


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--dir", default=".")
    p.add_argument("--write-template", action="store_true")
    p.add_argument("--summary", action="store_true")
    args = p.parse_args()

    if args.write_template:
        write_template(Path(args.dir) / "engagement_profile.yml")
    elif args.summary:
        profile = EngagementProfile(engagement_dir=args.dir)
        print(profile.summary())
