# NetEye: refresh the IP-to-organisation database and the threat list (run as administrator).
#   IP-to-ASN: iptoasn.com (Public Domain, PDDL v1.0)
#   Threat list: abuse.ch Feodo Tracker C2 (CC0) + Spamhaus DROP, plus blocklist_custom.txt in the data folder
# The service reads the files at start: Restart-Service NetEye
$ErrorActionPreference = 'Stop'
$data = Join-Path $env:ProgramData 'NetEye'
$ua = 'NetEye-intel-updater'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("neteye-intel-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    try {
        $asn = Join-Path $tmp 'asn.gz'
        Invoke-WebRequest -UseBasicParsing -UserAgent $ua -TimeoutSec 120 -Uri 'https://iptoasn.com/data/ip2asn-v4.tsv.gz' -OutFile $asn
        if ((Get-Item $asn).Length -gt 1000000) {
            Copy-Item $asn (Join-Path $data 'ip2asn-v4.tsv.gz') -Force
            Write-Output "IP 조직 DB 갱신: $data\ip2asn-v4.tsv.gz"
        }
    } catch { Write-Warning "IP 조직 DB를 받지 못했습니다 (기존 파일 유지): $_" }

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("# NetEye threat list, built $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')) UTC")
    $lines.Add('# address[/prefix]  # source')
    $count = 0
    try {
        $feodo = (Invoke-WebRequest -UseBasicParsing -UserAgent $ua -TimeoutSec 60 -Uri 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt').Content
        foreach ($l in ($feodo -split "`n")) { $l = $l.Trim(); if ($l -match '^\d+\.\d+\.\d+\.\d+$') { $lines.Add("$l  # Feodo Tracker"); $count++ } }
    } catch { Write-Warning "Feodo Tracker: $_" }
    try {
        $drop = (Invoke-WebRequest -UseBasicParsing -UserAgent $ua -TimeoutSec 60 -Uri 'https://www.spamhaus.org/drop/drop_v4.json').Content
        foreach ($m in [regex]::Matches($drop, '"cidr":"([0-9./]+)"')) { $lines.Add("$($m.Groups[1].Value)  # Spamhaus DROP"); $count++ }
    } catch { Write-Warning "Spamhaus DROP: $_" }
    $custom = Join-Path $data 'blocklist_custom.txt'
    if (Test-Path $custom) {
        foreach ($l in Get-Content $custom) { if ($l.Trim() -and -not $l.Trim().StartsWith('#')) { $lines.Add($l.Trim()); $count++ } }
    }
    if ($count -gt 0) {
        [IO.File]::WriteAllLines((Join-Path $data 'blocklist.txt'), $lines)
        Write-Output "위협 목록 갱신: $data\blocklist.txt ($count 건)"
    } else {
        Write-Warning '위협 목록을 받지 못했습니다 (기존 파일 유지)'
    }
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
