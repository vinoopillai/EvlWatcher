# Downloads the five internet registries' "delegated" statistics files into .\geo\ for the installer
# (the service refreshes them weekly by itself; this copy is the fallback for servers without internet access).
# Run from the folder you compile make.nsi in:  powershell -ExecutionPolicy Bypass -File fetch-geo.ps1
param([string]$Target = (Join-Path (Get-Location) 'geo'))

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$sources = [ordered]@{
    'apnic'   = 'https://ftp.apnic.net/stats/apnic/delegated-apnic-latest'
    'ripencc' = 'https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest'
    'arin'    = 'https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest'
    'lacnic'  = 'https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest'
    'afrinic' = 'https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest'
}

New-Item -ItemType Directory -Force -Path $Target | Out-Null
foreach ($name in $sources.Keys) {
    $file = Join-Path $Target "delegated-$name.txt"
    $client = New-Object Net.WebClient
    $client.Headers['User-Agent'] = 'EvlWatcher'
    $client.DownloadFile($sources[$name], $file)
    $lines = (Select-String -Path $file -Pattern '\|(ipv4|ipv6)\|' -SimpleMatch:$false | Where-Object { $_.Line -match '\|(allocated|assigned)' }).Count
    if ($lines -lt 1000) { throw "$name has only $lines ranges - refusing to ship it" }
    Write-Output ("{0,-8} {1,8} ranges  {2:N1} MB" -f $name, $lines, ((Get-Item $file).Length / 1MB))
}
