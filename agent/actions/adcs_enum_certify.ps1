# adcs_enum_certify — enumerate ADCS templates to find ESC1-15
# OCD mindmap: ADCS weak configuration branch
$ErrorActionPreference = 'Continue'

if (-not $global:SharpBlobs -or -not $global:SharpBlobs['Certify.exe']) {
    throw "Certify binary not pre-loaded"
}
$asm = [System.Reflection.Assembly]::Load($global:SharpBlobs['Certify.exe'])

$sw = New-Object System.IO.StringWriter
[Console]::SetOut($sw)
try {
    # find /vulnerable surfaces ESC1/2/3/4/6/9/10/11/13/15 candidates
    $asm.EntryPoint.Invoke($null, @([string[]]@('find', '/vulnerable')))
} catch {
    Write-Host "Certify failed: $_"
}
$std = New-Object System.IO.StreamWriter([System.Console]::OpenStandardOutput())
$std.AutoFlush = $true
[Console]::SetOut($std)
Write-Output $sw.ToString()

# Also dump all CAs for context
$sw2 = New-Object System.IO.StringWriter
[Console]::SetOut($sw2)
try {
    $asm.EntryPoint.Invoke($null, @([string[]]@('cas')))
} catch {}
$std2 = New-Object System.IO.StreamWriter([System.Console]::OpenStandardOutput())
$std2.AutoFlush = $true
[Console]::SetOut($std2)
Write-Output $sw2.ToString()
