"""
tar_server.py — FastAPI backend for the TAR internal-agent MVP.

Routes (all under /api/v1/...):
  POST /register           → dropper registers an agent; server returns agent_id + HMAC key
  GET  /agent              → returns the agent.ps1 body (HMAC-signed)
  POST /heartbeat          → agent polls; server returns pending commands
  POST /result             → agent returns command output; server parses into WM
  POST /command            → operator queues a command for an agent
  POST /engagement         → operator creates a new engagement
  GET  /audit/{eng_id}     → full audit log for an engagement
  POST /kill/{agent_id}    → operator triggers signed kill-switch

Persistence: one SQLite DB per engagement at
/home/kali/engagements/<engagement_id>/world_model.db plus engagement-scoped
auxiliary tables (agents, commands, audit_log).

TAR's existing `world_model.py` schema is reused unchanged. This server
simply writes to the same DB the planner-context hook reads from, so the
operator's Claude Code session sees agent results on the next turn.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import sys
import time
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

# Hook into TAR's existing world model + parsers
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, "/home/kali/.claude/scripts")

from world_model import WorldModel          # reuse schema
from engagement_profile import EngagementProfile

from server.auth import (
    new_agent_id, new_agent_key, sign, verify,
    issue_command_token, verify_command_token,
    issue_kill_token, verify_kill_token,
    check_operator_key, sha256_file,
)

# ── Configuration ────────────────────────────────────────────────────
ENGAGEMENTS_ROOT = Path(os.environ.get("TAR_ENGAGEMENTS_ROOT", "/home/kali/engagements"))
AGENT_BODY_PATH = Path(os.environ.get("TAR_AGENT_BODY", str(ROOT / "agent" / "agent.ps1")))

app = FastAPI(title="TAR Internal Agent Server", version="0.1.0")


# ── Auxiliary DB schema (per engagement) ─────────────────────────────

AUX_SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    hostname TEXT,
    domain TEXT,
    username TEXT,
    os_version TEXT,
    hmac_key BLOB NOT NULL,
    registered_at INTEGER NOT NULL,
    last_heartbeat_at INTEGER,
    status TEXT DEFAULT 'active',   -- active | killed | expired
    expiry_at INTEGER
);

CREATE TABLE IF NOT EXISTS commands (
    command_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    action_name TEXT NOT NULL,
    exec_mode TEXT NOT NULL,        -- powershell_native | sharpcollection | native_exec
    command_body TEXT NOT NULL,
    parameters_json TEXT,
    timeout_sec INTEGER DEFAULT 120,
    state TEXT NOT NULL DEFAULT 'pending',  -- pending | delivered | done | failed | rejected
    queued_at INTEGER NOT NULL,
    delivered_at INTEGER,
    completed_at INTEGER,
    exit_code INTEGER,
    stdout TEXT,
    stderr TEXT,
    rejection_reason TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    event TEXT NOT NULL,            -- REGISTER | QUEUE | DELIVER | RESULT | REJECT | KILL
    agent_id TEXT,
    command_id TEXT,
    operator TEXT,
    details TEXT                    -- JSON details blob
);

CREATE TABLE IF NOT EXISTS engagement_meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


def _engagement_dir(engagement_id: str) -> Path:
    if not re.match(r"^[a-z0-9][a-z0-9_\-]{2,63}$", engagement_id):
        raise HTTPException(400, "Invalid engagement_id format")
    d = ENGAGEMENTS_ROOT / engagement_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def _engagement_db(engagement_id: str) -> sqlite3.Connection:
    """Open (and migrate) the engagement DB."""
    d = _engagement_dir(engagement_id)
    db = d / "world_model.db"
    # Ensure TAR WM schema exists
    _ = WorldModel(db)   # __init__ runs schema migration
    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row
    conn.executescript(AUX_SCHEMA)
    conn.commit()
    return conn


def _audit(conn: sqlite3.Connection, event: str, *,
           agent_id: str = "", command_id: str = "",
           operator: str = "", details: Optional[dict] = None) -> None:
    conn.execute(
        "INSERT INTO audit_log (ts, event, agent_id, command_id, operator, details) "
        "VALUES (?,?,?,?,?,?)",
        (int(time.time()), event, agent_id, command_id, operator,
         json.dumps(details or {}))
    )
    conn.commit()


def _load_profile(engagement_id: str) -> EngagementProfile:
    return EngagementProfile(engagement_dir=str(_engagement_dir(engagement_id)))


# ── Pydantic models ─────────────────────────────────────────────────

class RegisterReq(BaseModel):
    engagement_id: str
    hostname: str
    domain: Optional[str] = ""
    username: Optional[str] = ""
    os_version: Optional[str] = ""
    engagement_letter_sha256: Optional[str] = ""


class RegisterResp(BaseModel):
    agent_id: str
    hmac_key_b64: str       # urlsafe base64 of the 32-byte key
    heartbeat_seconds: int
    heartbeat_jitter: int
    expiry_epoch: int       # absolute UTC seconds; agent exits past this
    allowed_exec_modes: list[str]


class HeartbeatReq(BaseModel):
    agent_id: str
    engagement_id: str
    status: str = "idle"
    system_info: Optional[dict] = None


class Command(BaseModel):
    command_id: str
    action_name: str
    exec_mode: str
    command_body: str
    parameters: dict
    timeout_sec: int = 120
    token: str              # HMAC token bound to this agent+command


class HeartbeatResp(BaseModel):
    sleep_seconds: int
    commands: list[Command]
    kill: bool = False


class ResultReq(BaseModel):
    agent_id: str
    command_id: str
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    token: str              # command token returned so server can verify


class ResultResp(BaseModel):
    accepted: bool
    reason: str = ""


class QueueCommandReq(BaseModel):
    engagement_id: str
    agent_id: str
    action_name: str
    exec_mode: str
    command_body: str
    parameters: dict = Field(default_factory=dict)
    timeout_sec: int = 120


class QueueCommandResp(BaseModel):
    command_id: str
    queued: bool
    reason: str = ""


class NewEngagementReq(BaseModel):
    engagement_id: str
    profile_yml_body: str   # raw scope.yml content


# ── Helpers ──────────────────────────────────────────────────────────

def _agent_key(conn: sqlite3.Connection, agent_id: str) -> Optional[bytes]:
    row = conn.execute("SELECT hmac_key, status, expiry_at FROM agents WHERE agent_id=?",
                       (agent_id,)).fetchone()
    if not row:
        return None
    if row["status"] != "active":
        return None
    if row["expiry_at"] and int(time.time()) > row["expiry_at"]:
        conn.execute("UPDATE agents SET status='expired' WHERE agent_id=?", (agent_id,))
        conn.commit()
        return None
    return row["hmac_key"]


def _check_scope_on_command(profile: EngagementProfile, action_name: str,
                             parameters: dict) -> tuple[bool, str]:
    """Server-side scope check before queueing.

    Returns (ok, reason).
    """
    # Destructive gate
    from engagement_profile import DESTRUCTIVE_ACTIONS
    if action_name in DESTRUCTIVE_ACTIONS and not profile.allow_destructive:
        return False, f"destructive_action_blocked:{action_name}"

    # Exec-mode restriction
    if profile.allowed_exec_modes:
        em = parameters.get("_exec_mode_hint", "")
        if em and em not in profile.allowed_exec_modes:
            return False, f"exec_mode_not_allowed:{em}"

    # Target scope check
    target_ip = parameters.get("target_ip") or parameters.get("dc_ip", "")
    target_domain = parameters.get("target_domain") or parameters.get("domain", "")
    if target_ip and not profile.is_in_scope(target_ip):
        return False, f"target_out_of_scope:{target_ip}"
    if target_domain:
        scope_block = profile.raw.get("scope", {}) or {}
        allowed_domain = scope_block.get("domain") or ""
        if allowed_domain and target_domain != allowed_domain:
            return False, f"domain_mismatch:{target_domain}"

    return True, ""


# ── Routes ────────────────────────────────────────────────────────────

@app.post("/api/v1/register", response_model=RegisterResp)
def register(req: RegisterReq):
    profile = _load_profile(req.engagement_id)
    if profile.profile_type != "internal-agent":
        raise HTTPException(400, "Engagement is not of type internal-agent")

    # Engagement letter hash check
    expected_hash = profile.engagement_letter_sha256
    if expected_hash and req.engagement_letter_sha256 != expected_hash:
        conn = _engagement_db(req.engagement_id)
        _audit(conn, "REGISTER_REJECTED",
               details={"hostname": req.hostname, "reason": "letter_hash_mismatch"})
        conn.close()
        raise HTTPException(403, "Engagement letter hash mismatch")

    # Hostname pattern check
    if profile.hostname_pattern:
        if not re.match(profile.hostname_pattern, req.hostname):
            conn = _engagement_db(req.engagement_id)
            _audit(conn, "REGISTER_REJECTED",
                   details={"hostname": req.hostname, "reason": "hostname_pattern_mismatch"})
            conn.close()
            raise HTTPException(403, f"Hostname {req.hostname} outside scope pattern")

    # Issue agent credentials
    agent_id = new_agent_id()
    hmac_key = new_agent_key()

    # Compute expiry: profile.expiry_iso → epoch, else 7 days from now
    expiry_epoch = 0
    expiry_iso = profile.expiry_iso
    if expiry_iso:
        try:
            from datetime import datetime
            expiry_epoch = int(datetime.fromisoformat(str(expiry_iso).replace("Z", "+00:00")).timestamp())
        except Exception:
            expiry_epoch = int(time.time()) + 7 * 86400
    else:
        expiry_epoch = int(time.time()) + 7 * 86400

    conn = _engagement_db(req.engagement_id)
    conn.execute(
        "INSERT INTO agents (agent_id, engagement_id, hostname, domain, username, "
        " os_version, hmac_key, registered_at, status, expiry_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (agent_id, req.engagement_id, req.hostname, req.domain, req.username,
         req.os_version, hmac_key, int(time.time()), "active", expiry_epoch)
    )
    _audit(conn, "REGISTER", agent_id=agent_id,
           details={"hostname": req.hostname, "domain": req.domain,
                    "username": req.username})
    conn.commit()
    conn.close()

    # Seed the world model with a host entry so the planner sees the foothold.
    # Done after closing the aux conn to avoid SQLite write-lock contention.
    wm = WorldModel(_engagement_dir(req.engagement_id) / "world_model.db")
    try:
        wm.add_host(ip="127.0.0.1", hostname=req.hostname, os=req.os_version,
                    domain=req.domain)
        wm.add_finding(category="agent_foothold",
                       description=f"Internal agent {agent_id} landed on {req.hostname} "
                                   f"as {req.username}@{req.domain}",
                       severity="info")
    finally:
        wm.close()

    import base64
    return RegisterResp(
        agent_id=agent_id,
        hmac_key_b64=base64.urlsafe_b64encode(hmac_key).rstrip(b"=").decode("ascii"),
        heartbeat_seconds=int(profile.raw.get("server", {}).get("heartbeat_seconds", 45)),
        heartbeat_jitter=int(profile.raw.get("server", {}).get("heartbeat_jitter_seconds", 15)),
        expiry_epoch=expiry_epoch,
        allowed_exec_modes=profile.allowed_exec_modes,
    )


@app.get("/api/v1/agent", response_class=PlainTextResponse)
def get_agent_body():
    """Return the agent.ps1 body (plain text for iex consumption)."""
    if not AGENT_BODY_PATH.is_file():
        raise HTTPException(500, f"Agent body missing at {AGENT_BODY_PATH}")
    return AGENT_BODY_PATH.read_text()


@app.post("/api/v1/heartbeat", response_model=HeartbeatResp)
def heartbeat(req: HeartbeatReq):
    conn = _engagement_db(req.engagement_id)
    key = _agent_key(conn, req.agent_id)
    if not key:
        conn.close()
        raise HTTPException(403, "Unknown or inactive agent")

    conn.execute("UPDATE agents SET last_heartbeat_at=? WHERE agent_id=?",
                 (int(time.time()), req.agent_id))

    # Fetch pending commands — mark them delivered in the same transaction
    rows = conn.execute(
        "SELECT command_id, action_name, exec_mode, command_body, parameters_json, "
        "timeout_sec FROM commands WHERE agent_id=? AND state='pending' ORDER BY queued_at",
        (req.agent_id,)
    ).fetchall()

    cmds: list[Command] = []
    for r in rows:
        token = issue_command_token(req.agent_id, r["command_id"], key)
        cmds.append(Command(
            command_id=r["command_id"],
            action_name=r["action_name"],
            exec_mode=r["exec_mode"],
            command_body=r["command_body"],
            parameters=json.loads(r["parameters_json"] or "{}"),
            timeout_sec=r["timeout_sec"],
            token=token,
        ))
        conn.execute("UPDATE commands SET state='delivered', delivered_at=? WHERE command_id=?",
                     (int(time.time()), r["command_id"]))
        _audit(conn, "DELIVER", agent_id=req.agent_id, command_id=r["command_id"])

    # Kill-switch check
    killed_row = conn.execute("SELECT status FROM agents WHERE agent_id=?",
                              (req.agent_id,)).fetchone()
    killed = killed_row and killed_row["status"] in ("killed", "expired")

    conn.commit()
    conn.close()

    profile = _load_profile(req.engagement_id)
    return HeartbeatResp(
        sleep_seconds=int(profile.raw.get("server", {}).get("heartbeat_seconds", 45)),
        commands=cmds,
        kill=bool(killed),
    )


@app.post("/api/v1/result", response_model=ResultResp)
def result(req: ResultReq):
    # Need the engagement_id to open the DB. Find it by scanning engagements
    # for a matching agent_id.
    engagement_id = _find_engagement_for_agent(req.agent_id)
    if not engagement_id:
        raise HTTPException(404, "Unknown agent")

    conn = _engagement_db(engagement_id)
    key = _agent_key(conn, req.agent_id)
    if not key:
        conn.close()
        raise HTTPException(403, "Inactive agent")

    if not verify_command_token(req.token, req.agent_id, req.command_id, key):
        _audit(conn, "REJECT", agent_id=req.agent_id, command_id=req.command_id,
               details={"reason": "bad_token"})
        conn.commit()
        conn.close()
        return ResultResp(accepted=False, reason="bad_token")

    # Persist the result
    conn.execute(
        "UPDATE commands SET state=?, completed_at=?, exit_code=?, stdout=?, stderr=? "
        "WHERE command_id=?",
        ("done" if req.exit_code == 0 else "failed",
         int(time.time()), req.exit_code, req.stdout, req.stderr, req.command_id)
    )
    cmd_row = conn.execute(
        "SELECT action_name FROM commands WHERE command_id=?",
        (req.command_id,)
    ).fetchone()
    action_name = cmd_row["action_name"] if cmd_row else ""

    _audit(conn, "RESULT", agent_id=req.agent_id, command_id=req.command_id,
           details={"exit_code": req.exit_code, "duration_ms": req.duration_ms,
                    "stdout_sha": _short_sha(req.stdout)})
    conn.commit()
    conn.close()

    # Parse the stdout into world-model predicates (best-effort). Done after
    # the aux conn is closed so WorldModel can take its own write lock.
    if action_name:
        _ingest_result(engagement_id, action_name, req.stdout, req.stderr,
                       req.exit_code)

    return ResultResp(accepted=True)


def _short_sha(s: str) -> str:
    import hashlib
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()[:16]


def _ingest_result(engagement_id: str, action_name: str, stdout: str,
                   stderr: str, exit_code: int) -> None:
    """Feed command output into the TAR world model via existing parsers."""
    db = _engagement_dir(engagement_id) / "world_model.db"
    try:
        sys.path.insert(0, "/home/kali/.claude/scripts/parsers")
        from generic_parser import parse as generic_parse  # type: ignore
    except Exception:
        generic_parse = None

    wm = WorldModel(db)
    try:
        # Record the action in attack_paths (used by the ranker for redundancy)
        wm.add_attack_path(
            from_state="agent_command",
            to_state="result_delivered",
            action_name=action_name,
            verified=(exit_code == 0),
            notes=stdout[:500],
        )
        if exit_code != 0:
            wm.add_finding(
                category="agent_failure",
                description=f"{action_name} failed (exit={exit_code}): "
                            f"{(stderr or stdout)[:120]}",
                severity="warn",
            )
            return
        if generic_parse:
            findings = generic_parse(stdout, action_name=action_name) or {}
            for pred in findings.get("predicates", []) or []:
                wm.add_finding(category="agent_predicate",
                               description=pred, severity="info")
    finally:
        wm.close()


def _find_engagement_for_agent(agent_id: str) -> str:
    if not ENGAGEMENTS_ROOT.is_dir():
        return ""
    for d in ENGAGEMENTS_ROOT.iterdir():
        if not d.is_dir():
            continue
        db = d / "world_model.db"
        if not db.is_file():
            continue
        try:
            c = sqlite3.connect(str(db))
            c.row_factory = sqlite3.Row
            row = c.execute("SELECT agent_id FROM agents WHERE agent_id=?",
                            (agent_id,)).fetchone()
            c.close()
            if row:
                return d.name
        except sqlite3.Error:
            continue
    return ""


@app.post("/api/v1/command", response_model=QueueCommandResp)
def queue_command(req: QueueCommandReq, x_tar_api_key: str = Header(default="")):
    if not check_operator_key(x_tar_api_key):
        raise HTTPException(401, "Unauthorized operator")

    profile = _load_profile(req.engagement_id)
    if profile.profile_type != "internal-agent":
        raise HTTPException(400, "Engagement is not internal-agent")

    ok, reason = _check_scope_on_command(profile, req.action_name, req.parameters)
    conn = _engagement_db(req.engagement_id)
    if not ok:
        _audit(conn, "REJECT", agent_id=req.agent_id,
               details={"action": req.action_name, "reason": reason,
                        "params": req.parameters})
        conn.commit()
        conn.close()
        return QueueCommandResp(command_id="", queued=False, reason=reason)

    if req.exec_mode not in (profile.allowed_exec_modes or [req.exec_mode]):
        _audit(conn, "REJECT", agent_id=req.agent_id,
               details={"action": req.action_name,
                        "reason": f"exec_mode_not_allowed:{req.exec_mode}"})
        conn.commit()
        conn.close()
        return QueueCommandResp(command_id="", queued=False,
                                reason=f"exec_mode_not_allowed:{req.exec_mode}")

    command_id = uuid.uuid4().hex
    conn.execute(
        "INSERT INTO commands (command_id, agent_id, action_name, exec_mode, "
        "command_body, parameters_json, timeout_sec, state, queued_at) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (command_id, req.agent_id, req.action_name, req.exec_mode,
         req.command_body, json.dumps(req.parameters),
         req.timeout_sec, "pending", int(time.time()))
    )
    _audit(conn, "QUEUE", agent_id=req.agent_id, command_id=command_id,
           operator="operator",
           details={"action": req.action_name, "exec_mode": req.exec_mode})
    conn.commit()
    conn.close()
    return QueueCommandResp(command_id=command_id, queued=True)


@app.post("/api/v1/engagement")
def create_engagement(req: NewEngagementReq,
                      x_tar_api_key: str = Header(default="")):
    if not check_operator_key(x_tar_api_key):
        raise HTTPException(401, "Unauthorized operator")
    d = _engagement_dir(req.engagement_id)
    (d / "engagement_profile.yml").write_text(req.profile_yml_body)
    # Trigger DB creation + schema
    _engagement_db(req.engagement_id).close()
    return {"engagement_id": req.engagement_id, "dir": str(d)}


@app.get("/api/v1/audit/{engagement_id}")
def audit(engagement_id: str, x_tar_api_key: str = Header(default="")):
    if not check_operator_key(x_tar_api_key):
        raise HTTPException(401, "Unauthorized operator")
    conn = _engagement_db(engagement_id)
    rows = conn.execute(
        "SELECT ts, event, agent_id, command_id, operator, details "
        "FROM audit_log ORDER BY id"
    ).fetchall()
    conn.close()
    return JSONResponse([dict(r) for r in rows])


@app.post("/api/v1/kill/{agent_id}")
def kill(agent_id: str, x_tar_api_key: str = Header(default="")):
    if not check_operator_key(x_tar_api_key):
        raise HTTPException(401, "Unauthorized operator")
    engagement_id = _find_engagement_for_agent(agent_id)
    if not engagement_id:
        raise HTTPException(404, "Unknown agent")
    conn = _engagement_db(engagement_id)
    conn.execute("UPDATE agents SET status='killed' WHERE agent_id=?", (agent_id,))
    _audit(conn, "KILL", agent_id=agent_id, operator="operator")
    conn.commit()
    conn.close()
    return {"agent_id": agent_id, "status": "killed"}


# ── Dev runner ──────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=os.environ.get("TAR_BIND", "127.0.0.1"),
                port=int(os.environ.get("TAR_PORT", "8443")))
