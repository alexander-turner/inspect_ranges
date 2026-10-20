# Realize the instrumented endpoint: the declared Administrator credential,
# RDP (the declared service), sysmon with the recipe-authored config, the
# universal forwarder shipping the declared channels to the splunk host.
# Downloads are URL + sha256 pinned (Sysmon.zip's URL is ROLLING — the pin
# breaks on Sysinternals refreshes, the recorded operational cadence fact).
# Self-asserting throughout.
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$splunkIp = (Get-Content -Raw 'C:\Windows\Temp\.ir-arw-splunk-ip.txt').Trim()
if (-not $splunkIp) { throw 'no splunk ip was staged' }

# -- the declared Administrator credential (users:) ----------------------------
net user Administrator 'changeme123!' | Out-Null

# -- RDP (the declared service) -------------------------------------------------
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' `
  -Name fDenyTSConnections -Value 0
Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
# the in-lab exec surface (declared smb 445; upstream's SG allows all
# internal traffic — the operator/automation model executes ON the endpoint)
Enable-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -ErrorAction SilentlyContinue

$stage = 'C:\Windows\Temp\.ir-arw-stage'
New-Item -ItemType Directory -Force -Path $stage | Out-Null

function Get-Pinned([string]$url, [string]$sha256, [string]$dest) {
  if (-not (Test-Path $dest) -or (Get-FileHash -Algorithm SHA256 $dest).Hash -ne $sha256) {
    Invoke-WebRequest -UseBasicParsing -OutFile $dest -Uri $url
  }
  if ((Get-FileHash -Algorithm SHA256 $dest).Hash -ne $sha256) {
    throw "download does not match its pinned sha256: $url"
  }
}

# -- sysmon (recipe-authored config: process access, process create, and the
#    PowerShell/Security channels ride the event log, not sysmon) ---------------
if (-not (Get-Service Sysmon64 -ErrorAction SilentlyContinue)) {
  Get-Pinned 'https://download.sysinternals.com/files/Sysmon.zip' `
    '00ECF1B46AEC99299D3AE0BCA79DC621458BD014B20B509D7C5C8E8C8611AA54' `
    "$stage\Sysmon.zip"
  Expand-Archive -Path "$stage\Sysmon.zip" -DestinationPath "$stage\sysmon" -Force
  Set-Content -Path "$stage\sysmon-config.xml" -Value @'
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <TargetImage condition="image">lsass.exe</TargetImage>
      </ProcessAccess>
    </RuleGroup>
    <!-- measured ambient lsass opens on an idle Server 2022 guest: svchost
         0x1000 every ~10s, csrss/wininit 0x1FFFFF once at boot, the forwarder
         and sysmon themselves from Program Files; excluded at the sensor so
         the exported stream carries only interesting access (the upstream
         sysmon-config convention) -->
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="exclude">
        <SourceImage condition="is">C:\Windows\system32\csrss.exe</SourceImage>
        <SourceImage condition="is">C:\Windows\system32\wininit.exe</SourceImage>
        <SourceImage condition="is">C:\Windows\system32\winlogon.exe</SourceImage>
        <SourceImage condition="is">C:\Windows\system32\services.exe</SourceImage>
        <SourceImage condition="is">C:\Windows\system32\svchost.exe</SourceImage>
        <SourceImage condition="is">C:\Windows\system32\lsass.exe</SourceImage>
        <SourceImage condition="is">C:\Windows\system32\wbem\wmiprvse.exe</SourceImage>
        <SourceImage condition="begin with">C:\Program Files</SourceImage>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
'@
  $sysmon = Start-Process -FilePath "$stage\sysmon\Sysmon64.exe" `
    -ArgumentList '-accepteula', '-i', "$stage\sysmon-config.xml" -Wait -PassThru
  if ($sysmon.ExitCode -ne 0) { throw "sysmon install exited $($sysmon.ExitCode)" }
}
if ((Get-Service Sysmon64).Status -ne 'Running') { throw 'sysmon is not running' }

# -- the universal forwarder (pinned msi), shipping to the splunk host ----------
if (-not (Get-Service SplunkForwarder -ErrorAction SilentlyContinue)) {
  Get-Pinned 'https://download.splunk.com/products/universalforwarder/releases/9.4.2/windows/splunkforwarder-9.4.2-e9664af3d956-windows-x64.msi' `
    '792971C8F8A81820F0BFE32935E50BE3E7D38CC907B0540C23F599466919E8FB' `
    "$stage\uf.msi"
  # the UF is pinned to the 9.4 LTS line (upstream attack_range's era): the
  # 10.2.2 winevtlog modinput crash-loops on Server 2022 (measured: 60 clean
  # exits, zero events shipped, under BOTH service accounts); a 9.x forwarder
  # against a 10.x indexer is the supported standard
  $msi = Start-Process -FilePath 'msiexec.exe' -ArgumentList @(
    '/i', "$stage\uf.msi", 'AGREETOLICENSE=Yes', 'SERVICESTARTTYPE=auto',
    "RECEIVING_INDEXER=$($splunkIp):9997", 'LAUNCHSPLUNK=1', '/quiet'
  ) -Wait -PassThru
  if ($msi.ExitCode -notin 0, 3010) { throw "forwarder msi exited $($msi.ExitCode)" }
}
# the MSI's service-account property does not take (measured): force
# LocalSystem deterministically — the virtual account cannot subscribe to the
# Sysmon/Security channels (errorCode=5) — and ASSERT it
sc.exe config SplunkForwarder obj= LocalSystem | Out-Null
$startName = (Get-CimInstance Win32_Service -Filter "Name='SplunkForwarder'").StartName
if ($startName -ne 'LocalSystem') { throw "forwarder service account is $startName, not LocalSystem" }

# the declared channels ship through a FILE-TAIL BRIDGE: the UF's native
# WinEventLog modinput is broken on this stack (measured across 10.2.2 and
# 9.4.2, LocalSystem and the virtual account, both renderers — clean-exit
# spawn loops, zero events, while _internal ships fine), and the channel read
# is PROVEN as SYSTEM. A SYSTEM task exports new events (RecordId watermark)
# to a log the UF monitors — its most battle-tested input — so the declared
# sysmon -> forwarder -> splunk flow stays real end to end.
$bridgeDir = 'C:\ProgramData\range-telemetry'
New-Item -ItemType Directory -Force -Path $bridgeDir | Out-Null
Set-Content -Path "$bridgeDir\export-events.ps1" -Value @'
$state = 'C:\ProgramData\range-telemetry\state.json'
$out = 'C:\ProgramData\range-telemetry\events.log'
$channels = @('Microsoft-Windows-Sysmon/Operational', 'Security', 'Microsoft-Windows-PowerShell/Operational')
while ($true) {
  $marks = @{}
  if (Test-Path $state) {
    (Get-Content -Raw $state | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $marks[$_.Name] = [long]$_.Value }
  }
  foreach ($channel in $channels) {
    $last = if ($marks.ContainsKey($channel)) { $marks[$channel] } else { 0 }
    $events = Get-WinEvent -LogName $channel -MaxEvents 500 -ErrorAction SilentlyContinue |
      Where-Object { $_.RecordId -gt $last } | Sort-Object RecordId
    foreach ($event in $events) {
      $message = ($event.Message -replace "\r?\n", ' ')
      Add-Content -Path $out -Value ("$($event.TimeCreated.ToUniversalTime().ToString('o')) channel=$channel EventID=$($event.Id) RecordID=$($event.RecordId) $message")
      $marks[$channel] = [long]$event.RecordId
    }
  }
  $marks | ConvertTo-Json | Set-Content -Path $state
  Start-Sleep -Seconds 8
}
'@
$bridgeAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
  -Argument '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\ProgramData\range-telemetry\export-events.ps1'
$bridgeTrigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName 'range-telemetry-bridge' -Action $bridgeAction `
  -Trigger $bridgeTrigger -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName 'range-telemetry-bridge'

$ufEtc = 'C:\Program Files\SplunkUniversalForwarder\etc\system\local'
New-Item -ItemType Directory -Force -Path $ufEtc | Out-Null
Set-Content -Path "$ufEtc\inputs.conf" -Value @'
[monitor://C:\ProgramData\range-telemetry\events.log]
disabled = 0
sourcetype = range:wineventlog
index = main
'@
Restart-Service SplunkForwarder

# -- self-assertions -------------------------------------------------------------
if ((Get-Service SplunkForwarder).Status -ne 'Running') { throw 'the forwarder is not running' }
$rdp = Get-NetTCPConnection -State Listen -LocalPort 3389 -ErrorAction SilentlyContinue
if (-not $rdp) { throw 'rdp 3389 is not listening' }
$smb = Get-NetTCPConnection -State Listen -LocalPort 445 -ErrorAction SilentlyContinue
if (-not $smb) { throw 'smb 445 is not listening' }
# the flow is live when the forwarder holds a connection to the indexer; give
# it a convergence window (the splunk host realized first, declaration order)
$connected = $false
foreach ($attempt in 1..24) {
  if (Get-NetTCPConnection -RemotePort 9997 -RemoteAddress $splunkIp -State Established -ErrorAction SilentlyContinue) {
    $connected = $true; break
  }
  Start-Sleep -Seconds 5
}
if (-not $connected) { throw "the forwarder never connected to $($splunkIp):9997" }
$bridged = $false
foreach ($attempt in 1..18) {
  if ((Test-Path "$bridgeDir\events.log") -and (Select-String -Path "$bridgeDir\events.log" -Pattern 'channel=Microsoft-Windows-Sysmon/Operational' -Quiet)) {
    $bridged = $true; break
  }
  Start-Sleep -Seconds 5
}
if (-not $bridged) { throw 'the telemetry bridge exported no sysmon events' }
Write-Output 'endpoint realized: administrator, rdp, sysmon, forwarder (flow established)'
