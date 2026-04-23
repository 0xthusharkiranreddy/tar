"""
test_endpoints.py — End-to-end smoke test for the TAR internal-agent server.

Covers the full register → heartbeat → command → result loop, plus the
destructive-action block and kill-switch paths.

Run: pytest server/tests/test_endpoints.py   (from repo root)
"""

from __future__ import annotations

import base64
import os
import sys
import tempfile
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO))


OPERATOR_KEY = "test-operator-key-12345"

ENGAGEMENT_YML = """\
profile: internal-agent
engagement_goal: "test"
allow_destructive: false
lockout_threshold: 3
scope:
  domain: corp.local
  subnets: [10.1.0.0/16]
  hostname_pattern: 'CORP-WKS-\\d+'
  excluded_hosts: []
  expiry: 2099-01-01T00:00:00+00:00
engagement_letter:
  path: /tmp/letter.pdf
  sha256: ""
server:
  url: http://127.0.0.1
  cert_fingerprint: ""
  heartbeat_seconds: 5
  heartbeat_jitter_seconds: 1
allowed_exec_modes:
  - powershell_native
  - sharpcollection
  - native_exec
"""


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("TAR_OPERATOR_API_KEY", OPERATOR_KEY)
    monkeypatch.setenv("TAR_ENGAGEMENTS_ROOT", str(tmp_path))

    # Agent body is required for /agent endpoint tests; point at a stub
    stub = tmp_path / "stub_agent.ps1"
    stub.write_text("# stub agent\nWrite-Host 'hello'\n")
    monkeypatch.setenv("TAR_AGENT_BODY", str(stub))

    # Import server after env is set
    from server import tar_server
    # Reload to pick up new env
    import importlib
    importlib.reload(tar_server)
    return TestClient(tar_server.app)


def _mk_engagement(client, eng_id="test-eng") -> None:
    r = client.post(
        "/api/v1/engagement",
        headers={"x-tar-api-key": OPERATOR_KEY},
        json={"engagement_id": eng_id, "profile_yml_body": ENGAGEMENT_YML},
    )
    assert r.status_code == 200, r.text


def test_register_happy_path(client):
    _mk_engagement(client)
    r = client.post("/api/v1/register", json={
        "engagement_id": "test-eng",
        "hostname": "CORP-WKS-042",
        "domain": "corp.local",
        "username": "alice",
        "os_version": "Windows 10",
    })
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["agent_id"]
    assert d["hmac_key_b64"]
    assert d["allowed_exec_modes"] == ["powershell_native", "sharpcollection", "native_exec"]


def test_register_out_of_scope_hostname(client):
    _mk_engagement(client)
    r = client.post("/api/v1/register", json={
        "engagement_id": "test-eng",
        "hostname": "PERSONAL-LAPTOP",     # doesn't match CORP-WKS-\d+
        "domain": "corp.local",
        "username": "bob",
        "os_version": "Windows 11",
    })
    assert r.status_code == 403, r.text


def test_heartbeat_and_command_loop(client):
    _mk_engagement(client)
    reg = client.post("/api/v1/register", json={
        "engagement_id": "test-eng",
        "hostname": "CORP-WKS-001",
        "domain": "corp.local",
        "username": "alice",
        "os_version": "Windows 10",
    }).json()
    agent_id = reg["agent_id"]

    # Queue a command
    q = client.post(
        "/api/v1/command",
        headers={"x-tar-api-key": OPERATOR_KEY},
        json={
            "engagement_id": "test-eng",
            "agent_id": agent_id,
            "action_name": "domain_enum",
            "exec_mode": "powershell_native",
            "command_body": "Get-ADDomain | Select-Object -Property Name,NetBIOSName",
            "parameters": {"target_domain": "corp.local"},
            "timeout_sec": 60,
        },
    )
    assert q.status_code == 200, q.text
    command_id = q.json()["command_id"]
    assert q.json()["queued"]

    # Heartbeat → agent receives the command
    hb = client.post("/api/v1/heartbeat", json={
        "agent_id": agent_id,
        "engagement_id": "test-eng",
        "status": "idle",
    })
    assert hb.status_code == 200, hb.text
    commands = hb.json()["commands"]
    assert len(commands) == 1
    assert commands[0]["command_id"] == command_id
    token = commands[0]["token"]

    # Result submitted with valid token
    res = client.post("/api/v1/result", json={
        "agent_id": agent_id,
        "command_id": command_id,
        "exit_code": 0,
        "stdout": "Name: CORP\nNetBIOSName: CORP\n",
        "stderr": "",
        "duration_ms": 120,
        "token": token,
    })
    assert res.status_code == 200, res.text
    assert res.json()["accepted"] is True

    # Second heartbeat → no pending commands
    hb2 = client.post("/api/v1/heartbeat", json={
        "agent_id": agent_id,
        "engagement_id": "test-eng",
        "status": "idle",
    })
    assert hb2.json()["commands"] == []


def test_destructive_action_blocked(client):
    _mk_engagement(client)
    reg = client.post("/api/v1/register", json={
        "engagement_id": "test-eng",
        "hostname": "CORP-WKS-099",
        "domain": "corp.local",
        "username": "alice",
        "os_version": "Windows 10",
    }).json()

    q = client.post(
        "/api/v1/command",
        headers={"x-tar-api-key": OPERATOR_KEY},
        json={
            "engagement_id": "test-eng",
            "agent_id": reg["agent_id"],
            "action_name": "skeleton_key",
            "exec_mode": "powershell_native",
            "command_body": "# destructive",
            "parameters": {},
        },
    )
    assert q.status_code == 200
    body = q.json()
    assert body["queued"] is False
    assert "destructive_action_blocked" in body["reason"]


def test_out_of_scope_target_blocked(client):
    _mk_engagement(client)
    reg = client.post("/api/v1/register", json={
        "engagement_id": "test-eng",
        "hostname": "CORP-WKS-123",
        "domain": "corp.local",
        "username": "alice",
        "os_version": "Windows 10",
    }).json()

    q = client.post(
        "/api/v1/command",
        headers={"x-tar-api-key": OPERATOR_KEY},
        json={
            "engagement_id": "test-eng",
            "agent_id": reg["agent_id"],
            "action_name": "user_enum",
            "exec_mode": "powershell_native",
            "command_body": "Get-ADUser -Server 8.8.8.8",
            "parameters": {"target_ip": "8.8.8.8"},
        },
    )
    body = q.json()
    assert body["queued"] is False
    assert "target_out_of_scope" in body["reason"]


def test_kill_switch(client):
    _mk_engagement(client)
    reg = client.post("/api/v1/register", json={
        "engagement_id": "test-eng",
        "hostname": "CORP-WKS-777",
        "domain": "corp.local",
        "username": "alice",
        "os_version": "Windows 10",
    }).json()
    agent_id = reg["agent_id"]

    k = client.post(f"/api/v1/kill/{agent_id}",
                     headers={"x-tar-api-key": OPERATOR_KEY})
    assert k.status_code == 200
    assert k.json()["status"] == "killed"

    # Heartbeat after kill → 403
    hb = client.post("/api/v1/heartbeat", json={
        "agent_id": agent_id,
        "engagement_id": "test-eng",
        "status": "idle",
    })
    assert hb.status_code == 403


def test_operator_auth_required(client):
    _mk_engagement(client)
    # No x-tar-api-key header
    q = client.post("/api/v1/command", json={
        "engagement_id": "test-eng",
        "agent_id": "abc",
        "action_name": "domain_enum",
        "exec_mode": "powershell_native",
        "command_body": "",
        "parameters": {},
    })
    assert q.status_code == 401


def test_audit_log_records_events(client):
    _mk_engagement(client)
    reg = client.post("/api/v1/register", json={
        "engagement_id": "test-eng",
        "hostname": "CORP-WKS-555",
        "domain": "corp.local",
        "username": "alice",
        "os_version": "Windows 10",
    }).json()
    client.post(
        "/api/v1/command",
        headers={"x-tar-api-key": OPERATOR_KEY},
        json={
            "engagement_id": "test-eng",
            "agent_id": reg["agent_id"],
            "action_name": "user_enum",
            "exec_mode": "powershell_native",
            "command_body": "Get-ADUser -Filter *",
            "parameters": {"target_domain": "corp.local"},
        },
    )
    log = client.get("/api/v1/audit/test-eng",
                     headers={"x-tar-api-key": OPERATOR_KEY}).json()
    events = [e["event"] for e in log]
    assert "REGISTER" in events
    assert "QUEUE" in events
