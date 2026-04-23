# computer_enum — domain computers with OS version + last logon
# Identifies legacy Windows boxes (SMBv1, EternalBlue candidates)
$ErrorActionPreference = 'SilentlyContinue'
try {
    Get-ADComputer -Filter * -Properties OperatingSystem, OperatingSystemVersion,
                                          LastLogonDate, ServicePrincipalName,
                                          TrustedForDelegation, TrustedToAuthForDelegation |
        Select-Object Name, OperatingSystem, OperatingSystemVersion, LastLogonDate,
                      @{N='UnconstrDeleg';E={$_.TrustedForDelegation}},
                      @{N='ConstrDeleg';E={$_.TrustedToAuthForDelegation}} |
        Sort-Object OperatingSystem | Format-Table -AutoSize
} catch {
    net view /domain 2>&1
}
