# domain_enum — current domain context, DC list, forest info
# OCD mindmap: Find DC IP / Got Account on the domain
$ErrorActionPreference = 'SilentlyContinue'

Write-Host "=== Current Identity ==="
whoami /all

Write-Host "`n=== Domain (Get-ADDomain) ==="
try { Get-ADDomain | Format-List Forest, Name, NetBIOSName, DomainMode, DomainControllersContainer, DNSRoot }
catch { Write-Host "Get-ADDomain unavailable: $_" }

Write-Host "`n=== Domain Controllers (nltest) ==="
nltest /dclist:$env:USERDNSDOMAIN

Write-Host "`n=== Trusts ==="
nltest /trusted_domains

Write-Host "`n=== Forest ==="
try { Get-ADForest | Format-List Name, ForestMode, Domains, GlobalCatalogs, Sites } catch {}
