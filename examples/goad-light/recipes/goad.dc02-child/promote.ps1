# Child domain promotion (north.sevenkingdoms.local) with DNS delegation in
# the parent zone (goad-forest lessons: -NewDomainNetbiosName is required and
# the child is the long pole). The reboot is issued DETACHED.
$ErrorActionPreference = 'Stop'
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
# the parent credential is the DECLARED rotation value: dc01's realize rotates
# SEVENKINGDOMS\Administrator before this recipe runs (range.yaml dc01
# services[active-directory].credentials; parked-decisions entry 2)
$parentPass = ConvertTo-SecureString 'Ir0nThr0ne!Keeper#2026' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('SEVENKINGDOMS\Administrator', $parentPass)
# the DSRM safe-mode password is a SET, not an authentication: it stays the
# golden's derive-time constant (winimage/render
# DEFAULT_WINDOWS_ADMIN_PASSWORD). DSRM is recovery-mode only, not a goal
# principal; it is deliberately outside the entry-2 rotation's scope.
$pass = ConvertTo-SecureString 'RangeAdm!n2026' -AsPlainText -Force
Install-ADDSDomain -NewDomainName 'north' -ParentDomainName 'sevenkingdoms.local' `
  -NewDomainNetbiosName 'NORTH' -DomainType ChildDomain -Credential $cred `
  -SafeModeAdministratorPassword $pass -InstallDns -CreateDnsDelegation `
  -NoRebootOnCompletion -Force -WarningAction SilentlyContinue | Out-Null
shutdown /r /t 5
