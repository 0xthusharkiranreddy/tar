# group_enum — privileged groups + membership (AD Tier 0 visibility)
# OCD mindmap: Enterprise Admin / Domain admin / Administrator access
$ErrorActionPreference = 'SilentlyContinue'

$PrivGroups = @(
    'Domain Admins', 'Enterprise Admins', 'Schema Admins',
    'Administrators', 'Account Operators', 'Backup Operators',
    'Server Operators', 'Print Operators',
    'DnsAdmins', 'Exchange Trusted Subsystem',
    'Protected Users', 'Cert Publishers',
    'Group Policy Creator Owners'
)

foreach ($g in $PrivGroups) {
    Write-Host "`n=== $g ==="
    try {
        Get-ADGroupMember -Identity $g -Recursive |
            Select-Object Name, SamAccountName, ObjectClass | Format-Table -AutoSize
    } catch {
        net group "$g" /domain 2>&1 | Out-String
    }
}
