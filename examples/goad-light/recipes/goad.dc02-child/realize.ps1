# Realize dc02's declared content from the spec (north.sevenkingdoms.local):
# users with SPNs, the Stark group, the DC-Administrators memberships, and the
# declared misconfigurations (LLMNR, NBT-NS, NTLM downgrade, autologon, the
# TERMSRV saved credential, the SYSVOL secret, shares, firewall off), plus the
# defender-on assertion. Self-asserting; a miss fails the build.
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$ad = Get-Content -Raw 'C:\Windows\Temp\.ir-goad-ad.json' | ConvertFrom-Json
$domain = $ad.domains | Where-Object { $_.name -eq 'north.sevenkingdoms.local' }
if (-not $domain) { throw 'north.sevenkingdoms.local is not in the AD declaration' }

# GOAD disables password complexity before seeding accounts (hodor/hodor is
# the scenario); measured on dc01: creation refuses without it
Set-ADDefaultDomainPasswordPolicy -Identity 'north.sevenkingdoms.local' `
  -ComplexityEnabled $false -MinPasswordLength 4

function Default-Password([string]$name) { "Goad2026!$name" }

function Ensure-Group([string]$name) {
  if (-not (Get-ADGroup -Filter 'SamAccountName -eq $name' -ErrorAction SilentlyContinue)) {
    New-ADGroup -Name $name -SamAccountName $name -GroupScope Global | Out-Null
  }
}

foreach ($user in $domain.users) {
  $password = if ($user.password) { $user.password } else { Default-Password $user.name }
  $userName = $user.name
  if (-not (Get-ADUser -Filter 'SamAccountName -eq $userName' -ErrorAction SilentlyContinue)) {
    $secure = ConvertTo-SecureString $password -AsPlainText -Force
    New-ADUser -Name $user.name -SamAccountName $user.name -AccountPassword $secure `
      -Enabled $true -PasswordNeverExpires $true | Out-Null
  }
  foreach ($group in @($user.groups)) {
    if (-not $group) { continue }
    if ($group -notin @('Domain Admins', 'Domain Users', 'Protected Users')) { Ensure-Group $group }
    Add-ADGroupMember -Identity $group -Members $user.name -ErrorAction SilentlyContinue
  }
  foreach ($spn in @($user.spns)) {
    if ($spn) { Set-ADUser -Identity $user.name -ServicePrincipalNames @{Add = $spn } }
  }
}

# the DC's Administrators memberships (upstream local_groups; a DC has no
# local SAM, so BUILTIN\Administrators of the domain carries it) — the
# declared local-admins misconfiguration the reference chain rides
foreach ($admin in @('eddard.stark', 'catelyn.stark', 'robb.stark')) {
  if (Get-ADUser -Filter 'SamAccountName -eq $admin' -ErrorAction SilentlyContinue) {
    Add-ADGroupMember -Identity 'Administrators' -Members $admin -ErrorAction SilentlyContinue
  }
}
# self-assert the DECLARED memberships the quiet adds above were meant to land
# (phase review: eddard's Domain Admins rode SilentlyContinue unasserted; dc01
# asserts its analogous cersei fact)
foreach ($must in @(
    @{ user = 'eddard.stark'; group = 'Domain Admins' },
    @{ user = 'eddard.stark'; group = 'Administrators' },
    @{ user = 'catelyn.stark'; group = 'Administrators' },
    @{ user = 'robb.stark'; group = 'Administrators' }
  )) {
  $members = Get-ADGroupMember -Identity $must.group | Select-Object -ExpandProperty SamAccountName
  if ($members -notcontains $must.user) {
    throw "declared membership missing: $($must.user) in $($must.group)"
  }
}

# -- LLMNR + NBT-NS enabled (the Windows default, pinned explicitly) ----------
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' `
  -Name EnableMulticast -ErrorAction SilentlyContinue
$interfaces = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
foreach ($iface in $interfaces) {
  Set-ItemProperty -Path $iface.PSPath -Name NetbiosOptions -Value 1
}

# -- NTLM downgrade ------------------------------------------------------------
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 2

# -- autologon (robb.stark; creds in registry, the declared misconfiguration) --
$winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Set-ItemProperty -Path $winlogon -Name AutoAdminLogon -Value '1'
Set-ItemProperty -Path $winlogon -Name DefaultDomainName -Value 'NORTH'
Set-ItemProperty -Path $winlogon -Name DefaultUserName -Value 'robb.stark'
Set-ItemProperty -Path $winlogon -Name DefaultPassword -Value 'sexywolfy'

# -- TERMSRV saved credential, in robb.stark's OWN vault (slice-4 review S8:
# cmdkey under the daemon's SYSTEM lands in SYSTEM's store, inverting the
# chain — the credential is loot FROM compromising robb) -----------------------
$termsrvAction = New-ScheduledTaskAction -Execute 'cmd.exe' `
  -Argument '/c cmdkey /add:TERMSRV/castelblack /user:north\robb.stark /pass:sexywolfy'
Register-ScheduledTask -TaskName 'ir-seed-termsrv' -Action $termsrvAction `
  -User 'NORTH\robb.stark' -Password 'sexywolfy' -RunLevel Limited | Out-Null
Start-ScheduledTask -TaskName 'ir-seed-termsrv'
Start-Sleep -Seconds 8
$termsrvResult = (Get-ScheduledTaskInfo -TaskName 'ir-seed-termsrv').LastTaskResult
Unregister-ScheduledTask -TaskName 'ir-seed-termsrv' -Confirm:$false
if ($termsrvResult -ne 0) { throw "the TERMSRV credential seed task exited $termsrvResult" }

# -- SYSVOL secret --------------------------------------------------------------
$scripts = 'C:\Windows\SYSVOL\sysvol\north.sevenkingdoms.local\scripts'
if (-not (Test-Path $scripts)) { New-Item -ItemType Directory -Force -Path $scripts | Out-Null }
# the secret is jeor.mormont's REAL declared credential (slice-4 review B2:
# a convention-shaped password here would disclose the derivation formula to
# any authenticated reader; upstream seeds a live chain, so do we — jeor is
# srv02's local admin)
Set-Content -Path (Join-Path $scripts 'secret.ps1') -Value @'
# legacy deployment script (do not remove)
$cred = New-Object System.Management.Automation.PSCredential('NORTH\jeor.mormont',
  (ConvertTo-SecureString '_L0ngCl@w_' -AsPlainText -Force))
'@

# -- shares (the open-shares misconfiguration) ----------------------------------
New-Item -ItemType Directory -Force -Path 'C:\shares\public' | Out-Null
if (-not (Get-SmbShare -Name public -ErrorAction SilentlyContinue)) {
  New-SmbShare -Name public -Path 'C:\shares\public' -ReadAccess Everyone | Out-Null
}

# -- firewall off ----------------------------------------------------------------
Set-NetFirewallProfile -All -Enabled False

# -- defense toggles --------------------------------------------------------------
$defense = Get-Content -Raw 'C:\Windows\Temp\.ir-goad-defense.json' | ConvertFrom-Json
if ($defense -and $defense.defender -eq $true) {
  if (-not (Get-MpComputerStatus).RealTimeProtectionEnabled) {
    throw 'defender: on is declared but RealTimeProtection is disabled'
  }
}
if ($defense -and $defense.windows_update -eq $false) {
  Stop-Service wuauserv -ErrorAction SilentlyContinue
  Set-Service wuauserv -StartupType Disabled
}

# -- self-assertions ---------------------------------------------------------------
$sql = Get-ADUser -Identity 'sql_svc' -Properties ServicePrincipalNames
if ($sql.ServicePrincipalNames -notcontains 'MSSQLSvc/castelblack.north.sevenkingdoms.local:1433') {
  throw 'sql_svc kerberoastable SPN missing'
}
if (-not (Get-ADGroupMember -Identity 'Administrators' | Where-Object SamAccountName -eq 'robb.stark')) {
  throw 'robb.stark is not in the DC Administrators (the declared local-admins fact)'
}
if ((Get-ItemProperty -Path $winlogon).DefaultPassword -ne 'sexywolfy') { throw 'autologon missing' }
Write-Output 'dc02 realized: users, spns, dc-admins, misconfigurations, defense'
