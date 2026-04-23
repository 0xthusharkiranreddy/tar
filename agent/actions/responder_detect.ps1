# responder_detect — detect rogue LLMNR/NBNS responders on the local segment
# Sends a bogus name lookup and checks if *anyone* answers (real DNS won't)
# OCD mindmap: (MITM) Listen and Relay — defensive visibility check
$ErrorActionPreference = 'SilentlyContinue'

$bogus = "wpad-nonexistent-$(Get-Random -Maximum 99999)"
Write-Host "Resolving bogus hostname: $bogus"
$result = Resolve-DnsName -Name $bogus -Type A -DnsOnly -ErrorAction SilentlyContinue -LlmnrNetbiosOnly

if ($result) {
    Write-Host "[!] ROGUE_RESPONDER_DETECTED — segment is poisoned:"
    $result | Select-Object Name, IPAddress, Type | Format-List
} else {
    Write-Host "no rogue responder detected on this segment"
}

# Also sample WPAD detection
Write-Host "`n=== WPAD auto-discovery ==="
try {
    $w = Resolve-DnsName -Name "wpad.$env:USERDNSDOMAIN" -ErrorAction Stop
    Write-Host "WPAD configured: $($w.IPAddress)"
} catch {
    Write-Host "WPAD not configured via DNS"
}
