# spn_enum — accounts with ServicePrincipalNames (kerberoast targets)
# OCD mindmap: Kerberoast branch
$ErrorActionPreference = 'SilentlyContinue'

Write-Host "=== SPN-bearing user accounts ==="
try {
    Get-ADUser -Filter 'ServicePrincipalName -like "*"' -Properties ServicePrincipalName, AdminCount |
        Select-Object SamAccountName, AdminCount,
                      @{N='SPN';E={$_.ServicePrincipalName -join ', '}} |
        Format-Table -AutoSize -Wrap
} catch {
    setspn -T $env:USERDNSDOMAIN -Q */ 2>&1
}

Write-Host "`n=== Computer SPNs (informational, not kerberoastable as user) ==="
try {
    Get-ADComputer -Filter 'ServicePrincipalName -like "*"' -Properties ServicePrincipalName |
        Select-Object Name,
                      @{N='SPN';E={$_.ServicePrincipalName -join ', '}} |
        Format-Table -AutoSize -Wrap
} catch {}
