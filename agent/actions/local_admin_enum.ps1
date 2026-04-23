# local_admin_enum — local administrators on this box + token privileges
# OCD mindmap: Low access → local privesc
$ErrorActionPreference = 'SilentlyContinue'

Write-Host "=== Current Token Privileges ==="
whoami /priv

Write-Host "`n=== Current Integrity Level ==="
whoami /groups | Select-String "Mandatory Label"

Write-Host "`n=== Local Administrators group ==="
try {
    Get-LocalGroupMember -Name Administrators |
        Select-Object Name, ObjectClass, PrincipalSource | Format-Table -AutoSize
} catch {
    net localgroup Administrators
}

Write-Host "`n=== Local Remote Desktop Users ==="
try {
    Get-LocalGroupMember -Name "Remote Desktop Users" -ErrorAction Stop |
        Select-Object Name | Format-Table -AutoSize
} catch {}

Write-Host "`n=== UAC state ==="
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA).EnableLUA
