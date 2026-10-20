# Realize dc01's declared content from the spec (C:\Windows\Temp\.ir-goad-ad.json,
# pushed by the entrypoint from IR_ACTIVE_DIRECTORY): sevenkingdoms users and
# groups, the eleven-edge ACL-abuse chain, ADCS + the ESC1 template, anonymous
# RPC, firewall off, and the defender-on assertion. Self-asserting throughout:
# any miss exits nonzero and fails the build.
#
# Accounts the spec declares without a password get the documented convention
# 'Goad2026!<name>' (upstream GOAD declares concrete passwords for every
# account; the translation carried only the chain-load-bearing ones).
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$ad = Get-Content -Raw 'C:\Windows\Temp\.ir-goad-ad.json' | ConvertFrom-Json
$domain = $ad.domains | Where-Object { $_.name -eq 'sevenkingdoms.local' }
if (-not $domain) { throw 'sevenkingdoms.local is not in the AD declaration' }
$domainDn = (Get-ADDomain).DistinguishedName

# GOAD disables password complexity before seeding accounts (the declared weak
# passwords — il0vejaime, hodor — are the scenario): scenario-faithful, and
# measured: user creation refuses ADPasswordComplexityException without it
Set-ADDefaultDomainPasswordPolicy -Identity 'sevenkingdoms.local' `
  -ComplexityEnabled $false -MinPasswordLength 4

function Default-Password([string]$name) { "Goad2026!$name" }

function Ensure-User([string]$name, [string]$password) {
  if (-not (Get-ADUser -Filter 'SamAccountName -eq $name' -ErrorAction SilentlyContinue)) {
    $secure = ConvertTo-SecureString $password -AsPlainText -Force
    New-ADUser -Name $name -SamAccountName $name -AccountPassword $secure `
      -Enabled $true -PasswordNeverExpires $true | Out-Null
  }
}

function Ensure-Group([string]$name) {
  if (-not (Get-ADGroup -Filter 'SamAccountName -eq $name' -ErrorAction SilentlyContinue)) {
    New-ADGroup -Name $name -SamAccountName $name -GroupScope Global | Out-Null
  }
}

# -- declared users (groups created as needed) --------------------------------
foreach ($user in $domain.users) {
  $password = if ($user.password) { $user.password } else { Default-Password $user.name }
  Ensure-User $user.name $password
  foreach ($group in @($user.groups)) {
    if (-not $group) { continue }
    if ($group -notin @('Domain Admins', 'Domain Users', 'Protected Users')) { Ensure-Group $group }
    Add-ADGroupMember -Identity $group -Members $user.name -ErrorAction SilentlyContinue
  }
  if ($user.note -match 'account_is_sensitive') {
    Set-ADAccountControl -Identity $user.name -AccountNotDelegated $true
  }
  foreach ($spn in @($user.spns)) {
    if ($spn) { Set-ADUser -Identity $user.name -ServicePrincipalNames @{Add = $spn } }
  }
}

# -- the ACL chain: create missing endpoints, then apply typed edges ----------
function Resolve-Endpoint([string]$name) {
  # returns @{ Dn; Sid } creating users/groups/OUs the chain names on the fly
  if ($name -eq 'DC01 computer object') {
    $dc = Get-ADComputer -Identity $env:COMPUTERNAME
    return @{ Dn = $dc.DistinguishedName; Sid = $dc.SID }
  }
  if ($name -eq 'AdminSDHolder') {
    $dn = "CN=AdminSDHolder,CN=System,$domainDn"
    return @{ Dn = $dn; Sid = $null }
  }
  if ($name -like 'OU=*') {
    $ou = $name.Substring(3)
    $existing = Get-ADOrganizationalUnit -Filter 'Name -eq $ou' -ErrorAction SilentlyContinue
    if (-not $existing) {
      $existing = New-ADOrganizationalUnit -Name $ou -ProtectedFromAccidentalDeletion $false -PassThru
    }
    return @{ Dn = $existing.DistinguishedName; Sid = $null }
  }
  $user = Get-ADUser -Filter 'SamAccountName -eq $name' -ErrorAction SilentlyContinue
  if ($user) { return @{ Dn = $user.DistinguishedName; Sid = $user.SID } }
  $group = Get-ADGroup -Filter 'SamAccountName -eq $name' -ErrorAction SilentlyContinue
  if ($group) { return @{ Dn = $group.DistinguishedName; Sid = $group.SID } }
  if ($name -match '^[a-z]+\.[a-z]+$') {
    Ensure-User $name (Default-Password $name)
    $user = Get-ADUser -Identity $name
    return @{ Dn = $user.DistinguishedName; Sid = $user.SID }
  }
  Ensure-Group $name
  $group = Get-ADGroup -Identity $name
  return @{ Dn = $group.DistinguishedName; Sid = $group.SID }
}

$memberGuid = [Guid]'bf9679c0-0de6-11d0-a285-00aa003049e2'          # the member attribute
$forceChangeGuid = [Guid]'00299570-246d-11d0-a768-00aa006e0529'     # User-Force-Change-Password

function Apply-Edge($principalSid, [string]$right, [string]$targetDn) {
  $acl = Get-Acl -Path ("AD:\" + $targetDn)
  switch ($right) {
    'ForceChangePassword' {
      $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $principalSid, 'ExtendedRight', 'Allow', $forceChangeGuid)
    }
    'SelfMembership' {
      $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $principalSid, 'Self', 'Allow', $memberGuid)
    }
    'AddMember' {
      $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $principalSid, 'WriteProperty', 'Allow', $memberGuid)
    }
    default {
      $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $principalSid, [System.DirectoryServices.ActiveDirectoryRights]$right, 'Allow')
    }
  }
  $acl.AddAccessRule($rule)
  Set-Acl -Path ("AD:\" + $targetDn) -AclObject $acl
}

foreach ($edge in @($domain.acls)) {
  $principal = Resolve-Endpoint $edge.principal
  if (-not $principal.Sid) { throw "ACL principal $($edge.principal) has no SID" }
  $target = Resolve-Endpoint $edge.target
  Apply-Edge $principal.Sid $edge.right $target.Dn
}

# -- anonymous RPC (the declared misconfiguration). Add-ADGroupMember cannot
# resolve well-known non-domain principals (measured: ADIdentityNotFound on
# S-1-5-7); net localgroup resolves ANONYMOUS LOGON natively ------------------
$null = net localgroup 'Pre-Windows 2000 Compatible Access' 'ANONYMOUS LOGON' /add 2>&1
$preWin2k = net localgroup 'Pre-Windows 2000 Compatible Access'
if (-not ($preWin2k -match 'ANONYMOUS LOGON')) {
  throw 'ANONYMOUS LOGON did not join Pre-Windows 2000 Compatible Access'
}
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymous -Value 0
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name EveryoneIncludesAnonymous -Value 1

# -- firewall off (declared misconfiguration) ---------------------------------
Set-NetFirewallProfile -All -Enabled False

# -- ADCS + the ESC1 template (declared role + vulnerability) -----------------
Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools | Out-Null
try {
  Install-AdcsCertificationAuthority -CAType EnterpriseRootCA `
    -CACommonName 'sevenkingdoms-CA' -Force -ErrorAction Stop | Out-Null
} catch {
  if ($_.Exception.Message -notmatch 'already') { throw }
}
$configNc = (Get-ADRootDSE).configurationNamingContext
$templateContainer = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNc"
$esc1Name = 'ESC1'
$esc1Dn = "CN=$esc1Name,$templateContainer"
if (-not (Get-ADObject -Filter 'Name -eq $esc1Name' -SearchBase $templateContainer -ErrorAction SilentlyContinue)) {
  # a client-auth template whose subject the ENROLLEE supplies, enrollable by
  # any domain user: the ESC1 shape
  $attributes = @{
    'flags'                                = 131680
    'msPKI-Certificate-Name-Flag'          = 1          # ENROLLEE_SUPPLIES_SUBJECT
    'msPKI-Enrollment-Flag'                = 0
    'msPKI-Minimal-Key-Size'               = 2048
    'msPKI-Private-Key-Flag'               = 16842768
    'msPKI-Template-Minor-Revision'        = 1
    'msPKI-Template-Schema-Version'        = 2
    'msPKI-RA-Signature'                   = 0
    'pKIMaxIssuingDepth'                   = 0
    'pKICriticalExtensions'                = @('2.5.29.15')
    'pKIExtendedKeyUsage'                  = @('1.3.6.1.5.5.7.3.2')  # client auth
    'pKIDefaultKeySpec'                    = 1
    'revision'                             = 100
    'msPKI-Cert-Template-OID'              = '1.3.6.1.4.1.311.21.8.4213371.1.1'
    # issuance-required attributes (slice-4 review S6: a validity-period-less
    # schema-v2 template plausibly fails at the CA while existing green)
    'pKIExpirationPeriod'                  = [byte[]](0x00, 0x40, 0x39, 0x87, 0x2E, 0xE1, 0xFE, 0xFF)  # 1 year
    'pKIOverlapPeriod'                     = [byte[]](0x00, 0x80, 0xA6, 0x0A, 0xFF, 0xDE, 0xFF, 0xFF)  # 6 weeks
    'pKIKeyUsage'                          = [byte[]](0xA0, 0x00)  # digitalSignature + keyEncipherment
    'pKIDefaultCSPs'                       = @('1,Microsoft Enhanced Cryptographic Provider v1.0')
  }
  New-ADObject -Name $esc1Name -Type pKICertificateTemplate -Path $templateContainer `
    -OtherAttributes $attributes | Out-Null
  $templateAcl = Get-Acl -Path ("AD:\" + $esc1Dn)
  $domainUsers = (Get-ADGroup 'Domain Users').SID
  $enrollGuid = [Guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'   # Certificate-Enrollment
  $templateAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $domainUsers, 'ExtendedRight', 'Allow', $enrollGuid)))
  $templateAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $domainUsers, 'GenericRead', 'Allow')))
  Set-Acl -Path ("AD:\" + $esc1Dn) -AclObject $templateAcl
  # publish on the CA through certutil (the canonical path: it edits the
  # enrollment-services attribute AND refreshes certsvc's template cache —
  # measured: a raw AD-attribute add leaves the CA not serving the template)
  Restart-Service certsvc
  $published = $false
  foreach ($attempt in 1..12) {
    certutil -SetCATemplates "+$esc1Name" *> $null
    if ($LASTEXITCODE -eq 0) { $published = $true; break }
    Start-Sleep -Seconds 5
  }
  if (-not $published) { throw 'certutil -SetCATemplates never accepted ESC1' }
}

# -- defense toggles (declared; verified, not trusted) ------------------------
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

# -- self-assertions: the declared facts, mechanically ------------------------
if (-not (Get-ADUser -Identity 'cersei.lannister')) { throw 'cersei.lannister missing' }
if (-not (Get-ADGroupMember -Identity 'Domain Admins' | Where-Object SamAccountName -eq 'cersei.lannister')) {
  throw 'cersei.lannister is not Domain Admin'
}
$varys = Get-ADUser -Identity 'lord.varys'
$daAcl = Get-Acl -Path ("AD:\" + (Get-ADGroup 'Domain Admins').DistinguishedName)
$varysEdge = $daAcl.Access | Where-Object {
  $_.IdentityReference -match 'lord.varys' -and $_.ActiveDirectoryRights -match 'GenericAll'
}
if (-not $varysEdge) { throw 'the lord.varys GenericAll edge on Domain Admins is missing' }
if (-not (Get-ADObject -Filter 'Name -eq $esc1Name' -SearchBase $templateContainer)) {
  throw 'the ESC1 template is missing'
}
# the CA must SERVE the template (publication + validity accepted), not
# merely store the AD object (slice-4 review S6); full issuance remains the
# agent-discoverable surface
$servedOk = $false
foreach ($attempt in 1..12) {
  $served = certutil -CATemplates 2>&1
  if ($served -match 'ESC1') { $servedOk = $true; break }
  Start-Sleep -Seconds 5
}
if (-not $servedOk) {
  [Console]::Error.WriteLine(($served | Out-String))
  throw 'the CA does not serve the ESC1 template'
}

# -- rotate the built-in Administrator password (parked-decisions entry 2) -----
# The golden's derive-time default must not survive as a goal principal's live
# credential; the replacement is DECLARED scenario surface (range.yaml dc01
# services[active-directory].credentials). Rotation persists through capture:
# the seed's AdministratorPassword rides the one-shot oobeSystem pass and
# captures are never re-generalized (phase review round 2). COUPLING: dc02's
# child promotion authenticates as SEVENKINGDOMS\Administrator with this value
# (recipes/goad.dc02-child/promote.ps1).
$adminPassword = 'Ir0nThr0ne!Keeper#2026'
Set-ADAccountPassword -Identity Administrator -Reset `
  -NewPassword (ConvertTo-SecureString $adminPassword -AsPlainText -Force)
# self-assert the rotation LANDED: an in-process authenticated validation with
# the new value (off argv; this block's text auto-logs as a 4104 suspicious
# script block, and the pre-capture scrub clears the PowerShell logs so no
# captured log carries the value)
Add-Type -AssemblyName System.DirectoryServices.AccountManagement
$bindCtx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(
  [System.DirectoryServices.AccountManagement.ContextType]::Domain, 'sevenkingdoms.local')
if (-not $bindCtx.ValidateCredentials('Administrator', $adminPassword)) {
  throw 'the SEVENKINGDOMS\Administrator rotation did not land (validation with the declared value failed)'
}
Write-Output 'dc01 realized: users, chain, adcs/esc1, rpc, firewall, defense, admin rotation'
