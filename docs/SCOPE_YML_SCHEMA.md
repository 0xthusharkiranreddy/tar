# scope.yml — Engagement Scope Reference

The `scope.yml` (or `engagement_profile.yml`) file lives in the engagement
directory and is read by:

1. The TAR operator hooks (`action_ranker.py`, `planner-context.sh`) — to bias
   ranking, block destructive actions, and refuse to plan against out-of-scope
   targets.
2. The internal red team agent (`agent/agent.ps1`) — to enforce scope **per
   command** on the workstation side, independently of the server.

Both sides fail closed: if the file is missing or malformed, no command runs.

## Minimal example

```yaml
profile: internal-agent
engagement_goal: "Validate AD exposure from a standard employee workstation"
allow_destructive: false
lockout_threshold: 3

scope:
  domain: corp.local
  subnets:
    - 10.1.0.0/16
  hostname_pattern: 'CORP-(WKS|LT)-\d+'
  excluded_hosts: []
  expiry: 2026-05-22T23:59:59Z

engagement_letter:
  path: /home/kali/engagements/<id>/letter.pdf
  sha256: <hex>

server:
  url: https://tar-server.local:8443
  cert_fingerprint: <hex>
  heartbeat_seconds: 45
  heartbeat_jitter_seconds: 15

allowed_exec_modes:
  - powershell_native
  - sharpcollection
  - native_exec
```

## Field reference

### `profile` (required)

One of: `ctf`, `lab`, `internal`, `external`, `production`, `internal-agent`.

The profile sets the defaults for everything below. Explicit values in the
file override the defaults from `PROFILE_DEFAULTS`.

### `scope.domain` (required for internal-agent)

The Active Directory domain the agent may interact with. Commands whose
`target_domain` differs are rejected agent-side with reason `domain_mismatch`.

### `scope.subnets` (required for internal-agent)

List of CIDR blocks the agent may reach. The agent resolves every command's
`target_ip` (including hostnames, which are resolved against DNS first) and
requires the resolved IP to fall inside one of these blocks.

Scope-via-DNS bypass: the agent resolves hostname **and** requires the IP to
be in scope, so an attacker-controlled DNS record pointing an in-scope
hostname at an external IP will not escape scope.

### `scope.hostname_pattern` (required for internal-agent)

Regex that the workstation's own `%COMPUTERNAME%` must match. If the dropper
lands on a machine whose name doesn't match, it exits `OUT_OF_SCOPE` without
registering with the server. Catches cases like a user pasting the one-liner
on their personal laptop instead of the engagement target.

### `scope.excluded_hosts`

Specific hostnames or IPs that must never be targeted even if they fall
inside the subnet list — e.g., honeypots, the client's own SOC tooling.

### `scope.expiry`

ISO 8601 timestamp. After this, the agent refuses further commands and
exits, even if the server is unreachable. Enforced by the agent (time
check on `[DateTime]::UtcNow`), not the server.

### `engagement_letter.path` and `.sha256`

Absolute path to the signed engagement letter PDF. The SHA-256 is baked
into the dropper at build time. On first run the dropper recomputes the
hash of the delivered letter and refuses to continue on mismatch.

### `server.url` / `server.cert_fingerprint`

HTTPS URL and the SHA-256 thumbprint of the server's TLS certificate.
The agent's HTTP client pins the cert — an MITM with a different cert
(even from a valid CA) is rejected.

### `allowed_exec_modes`

Subset of: `powershell_native`, `sharpcollection`, `native_exec`,
`dotnet_reflect`. Commands requesting an exec_mode not in this list are
rejected agent-side. `impacket_via_kali` is handled specially — those
commands are marked `need_kali` and executed by the operator on Kali,
with output piped back into the engagement's world_model.db.

### `allow_destructive`

If `false`, commands referencing any action in the `DESTRUCTIVE_ACTIONS`
set (`skeleton_key`, `dc_shadow`, `dsrm_password`, `zerologon`,
`krbtgt_reset`, `eternalblue`, `smbghost`, `wsus_attack`, `custom_ssp`,
`kerbrute_spray`, `hydra`) are blocked by both the server ranker and the
agent. Setting to `true` requires an explicit client sign-off that should
be recorded in the engagement letter.

### `lockout_threshold`

Maximum spray / brute-force attempts per account before the `lockout_guard`
inserts a hard stop. The internal-agent default is 3 (half of AD's typical
default of 5), leaving headroom for legitimate user typos.

## Validation

```
python3 /home/kali/.claude/scripts/engagement_profile.py \
    --dir /home/kali/engagements/<engagement-id> --summary
```

Prints a one-line summary. Exits non-zero if the file is missing required
fields for the declared profile.

## Fail-closed behaviour

1. File missing → profile defaults to `lab` → internal-agent features disabled.
2. `profile: internal-agent` but `engagement_letter.sha256` missing → dropper exit.
3. `target_ip` outside `scope.subnets` → agent rejects command, logs
   `out_of_scope_ip` finding.
4. `$env:COMPUTERNAME` doesn't match `hostname_pattern` → dropper exit
   `OUT_OF_SCOPE_HOSTNAME`.
5. `[DateTime]::UtcNow > scope.expiry` → agent exit `EXPIRED`.
