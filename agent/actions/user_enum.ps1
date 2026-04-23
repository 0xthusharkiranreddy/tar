# user_enum — enumerate domain users with metadata useful for follow-on attacks
# OCD mindmap: Find user list / Got valid username
$ErrorActionPreference = 'SilentlyContinue'

Write-Host "=== Domain Users (Get-ADUser) ==="
try {
    Get-ADUser -Filter * -Properties LastLogonDate, PasswordLastSet, Enabled,
                                      DoesNotRequirePreAuth, ServicePrincipalName,
                                      AdminCount, MemberOf |
        Select-Object SamAccountName, Enabled, LastLogonDate, PasswordLastSet,
                      @{N='PreAuthDisabled';E={$_.DoesNotRequirePreAuth}},
                      @{N='HasSPN';E={$_.ServicePrincipalName.Count -gt 0}},
                      @{N='Protected';E={$_.AdminCount -eq 1}} |
        Format-Table -AutoSize
} catch {
    Write-Host "Get-ADUser failed: $_`nFalling back to 'net user /domain'"
    net user /domain
}

Write-Host "`n=== Users with AS-REP roastable flag (preauth disabled) ==="
try {
    Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' -Properties DoesNotRequirePreAuth |
        Select-Object SamAccountName, Enabled | Format-Table -AutoSize
} catch {}
