"""
auth.py — HMAC signing, cert pinning helpers, and API key validation for the
TAR internal-agent server.

Design goals:
  - Agents never ship secrets in the binary. The HMAC key is per-agent and
    issued at /register time. Stolen agent binaries cannot impersonate
    another agent.
  - All signed tokens include a nonce + issued_at + expiry. No replay window
    longer than 10 minutes for command tokens; kill tokens are single-use.
  - The engagement letter SHA-256 is baked into the dropper at build time;
    the server also records it so post-hoc audit can prove what was authorised.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time


HMAC_ALGO = "sha256"
COMMAND_TOKEN_TTL_SEC = 600     # 10 min — operator queues, agent must fetch within
KILL_TOKEN_TTL_SEC = 300        # 5 min
AGENT_KEY_BYTES = 32            # 256-bit HMAC key per agent


def new_agent_id() -> str:
    """Fresh UUID-like agent id. Printed to operator + baked into first heartbeat."""
    return secrets.token_hex(16)


def new_agent_key() -> bytes:
    """Per-agent HMAC key, issued at registration time."""
    return secrets.token_bytes(AGENT_KEY_BYTES)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)


def sign(payload: bytes, key: bytes) -> str:
    """HMAC-SHA256, return base64url-encoded digest."""
    mac = hmac.new(key, payload, hashlib.sha256).digest()
    return _b64(mac)


def verify(payload: bytes, signature: str, key: bytes) -> bool:
    """Constant-time signature verification."""
    try:
        expected = _b64(hmac.new(key, payload, hashlib.sha256).digest())
    except Exception:
        return False
    return hmac.compare_digest(expected, signature)


def issue_command_token(agent_id: str, command_id: str, key: bytes,
                        ttl: int = COMMAND_TOKEN_TTL_SEC) -> str:
    """Token bound to a specific agent + command_id; expires after ttl seconds."""
    iat = int(time.time())
    exp = iat + ttl
    body = f"{agent_id}:{command_id}:{iat}:{exp}".encode()
    sig = sign(body, key)
    return f"{_b64(body)}.{sig}"


def verify_command_token(token: str, agent_id: str, command_id: str,
                         key: bytes) -> bool:
    try:
        body_b64, sig = token.split(".", 1)
        body = _unb64(body_b64)
        parts = body.decode().split(":")
        if len(parts) != 4:
            return False
        tok_agent, tok_cmd, iat, exp = parts
        if tok_agent != agent_id or tok_cmd != command_id:
            return False
        if int(exp) < int(time.time()):
            return False
        return verify(body, sig, key)
    except Exception:
        return False


def issue_kill_token(agent_id: str, key: bytes) -> str:
    """Kill-switch token. One-time use tracked by server."""
    nonce = secrets.token_hex(8)
    iat = int(time.time())
    exp = iat + KILL_TOKEN_TTL_SEC
    body = f"KILL:{agent_id}:{nonce}:{iat}:{exp}".encode()
    sig = sign(body, key)
    return f"{_b64(body)}.{sig}"


def verify_kill_token(token: str, agent_id: str, key: bytes) -> bool:
    try:
        body_b64, sig = token.split(".", 1)
        body = _unb64(body_b64)
        parts = body.decode().split(":")
        if len(parts) != 5 or parts[0] != "KILL" or parts[1] != agent_id:
            return False
        if int(parts[4]) < int(time.time()):
            return False
        return verify(body, sig, key)
    except Exception:
        return False


# ── Operator API key ────────────────────────────────────────────────────
# MVP: single static operator key from env / config file. v2: per-operator
# mTLS. The key is compared in constant time to avoid timing attacks.

def check_operator_key(provided: str) -> bool:
    expected = os.environ.get("TAR_OPERATOR_API_KEY", "")
    if not expected:
        return False
    return hmac.compare_digest(provided.encode(), expected.encode())


# ── Engagement letter hash ──────────────────────────────────────────────

def sha256_file(path: str) -> str:
    """SHA-256 hex digest of a file on disk."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()
