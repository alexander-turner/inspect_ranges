# Child domain promotion (north.sevenkingdoms.local) with DNS delegation in
# the parent zone (goad-forest lessons: -NewDomainNetbiosName is required and
# the child is the long pole). The reboot is issued DETACHED.
$ErrorActionPreference = 'Stop'
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
$pass = ConvertTo-SecureString 'RangeAdm!n2026' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('SEVENKINGDOMS\Administrator', $pass)
Install-ADDSDomain -NewDomainName 'north' -ParentDomainName 'sevenkingdoms.local' `
  -NewDomainNetbiosName 'NORTH' -DomainType ChildDomain -Credential $cred `
  -SafeModeAdministratorPassword $pass -InstallDns -CreateDnsDelegation `
  -NoRebootOnCompletion -Force -WarningAction SilentlyContinue | Out-Null
shutdown /r /t 5
