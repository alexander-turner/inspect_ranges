# Realize srv02's in-box content: IIS with the ASP upload-directory weakness,
# WebDAV, the world-readable share, firewall off, defender OFF (declared and
# chain-load-bearing: the webshell surface works because real-time protection
# is disabled). Self-asserting; a miss fails the build.
$ErrorActionPreference = 'Stop'

# -- IIS + ASP + WebDAV (the declared roles/services) --------------------------
Install-WindowsFeature Web-Server, Web-Asp, Web-DAV-Publishing -IncludeManagementTools | Out-Null
Import-Module WebAdministration

$upload = 'C:\inetpub\wwwroot\upload'
New-Item -ItemType Directory -Force -Path $upload | Out-Null
# IIS_IUSRS FullControl on the upload directory: the declared iis-asp-upload
# vulnerability (webshell upload to RCE)
icacls $upload /grant 'IIS_IUSRS:(OI)(CI)F' | Out-Null
# ASP must execute from the upload directory for the weakness to be real
Set-WebConfigurationProperty -Filter '/system.webServer/handlers' `
  -PSPath 'IIS:\Sites\Default Web Site\upload' -Name accessPolicy `
  -Value 'Read,Script' -ErrorAction SilentlyContinue
# classic ASP enabled site-wide (the GOAD shape)
Set-WebConfigurationProperty -Filter '/system.webServer/asp' `
  -PSPath 'IIS:\' -Name enableParentPaths -Value $true -ErrorAction SilentlyContinue

# -- the open share -------------------------------------------------------------
New-Item -ItemType Directory -Force -Path 'C:\shares\all' | Out-Null
Set-Content -Path 'C:\shares\all\arya.txt' -Value 'a girl has no name'
if (-not (Get-SmbShare -Name all -ErrorAction SilentlyContinue)) {
  New-SmbShare -Name all -Path 'C:\shares\all' -FullAccess Everyone | Out-Null
}

# -- firewall off ----------------------------------------------------------------
Set-NetFirewallProfile -All -Enabled False

# -- defender OFF (declared; chain-load-bearing) ----------------------------------
$defense = Get-Content -Raw 'C:\Windows\Temp\goad-defense.json' | ConvertFrom-Json
if ($defense -and $defense.defender -eq $false) {
  Set-MpPreference -DisableRealtimeMonitoring $true
  # the status read lags the preference change (measured: still-enabled
  # immediately after); poll before declaring the toggle failed
  $flipped = $false
  foreach ($attempt in 1..12) {
    if (-not (Get-MpComputerStatus).RealTimeProtectionEnabled) { $flipped = $true; break }
    Start-Sleep -Seconds 5
  }
  if (-not $flipped) {
    throw 'defender: off is declared but RealTimeProtection is still enabled after 60 s'
  }
}

# -- self-assertions ---------------------------------------------------------------
if (-not (Get-Website -Name 'Default Web Site')) { throw 'IIS default site missing' }
if (-not (Test-Path 'C:\shares\all\arya.txt')) { throw 'the open share content is missing' }
$uploadAcl = icacls $upload
if (-not ($uploadAcl -match 'IIS_IUSRS:\(OI\)\(CI\)\(F\)')) { throw 'the upload ACL is missing' }
Write-Output 'srv02 realized: iis/webdav, upload weakness, shares, firewall, defender off'
