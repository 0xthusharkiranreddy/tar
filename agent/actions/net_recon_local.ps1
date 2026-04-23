# net_recon_local — interfaces, routes, ARP cache, DNS servers
# OCD mindmap: Scan Network / Entry point
Write-Host "=== Network Interfaces ==="
Get-NetIPConfiguration | Format-List InterfaceAlias, IPv4Address, IPv4DefaultGateway, DNSServer
Write-Host "`n=== Routes ==="
Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.NextHop -ne '0.0.0.0' } |
    Select-Object DestinationPrefix, NextHop, InterfaceAlias, RouteMetric |
    Format-Table -AutoSize
Write-Host "`n=== ARP Cache ==="
Get-NetNeighbor -AddressFamily IPv4 -State Reachable, Stale -ErrorAction SilentlyContinue |
    Select-Object IPAddress, LinkLayerAddress, InterfaceAlias |
    Format-Table -AutoSize
Write-Host "`n=== DNS ==="
nslookup -type=SRV "_ldap._tcp.dc._msdcs.$env:USERDNSDOMAIN" 2>&1
