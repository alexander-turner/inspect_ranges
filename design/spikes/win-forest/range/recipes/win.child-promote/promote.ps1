# Child domain promotion (north.corp.local) with DNS delegation in the parent
# zone. Install-ADDSDomain wants -NewDomainNetbiosName (goad-forest lesson 1).
# The reboot is issued DETACHED at the end.
$ErrorActionPreference = 'Stop'
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
$pass = ConvertTo-SecureString 'RangeAdm!n2026' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('CORP\Administrator', $pass)
Install-ADDSDomain -NewDomainName 'north' -ParentDomainName 'corp.local' `
  -NewDomainNetbiosName 'NORTH' -DomainType ChildDomain -Credential $cred `
  -SafeModeAdministratorPassword $pass -InstallDns -CreateDnsDelegation `
  -NoRebootOnCompletion -Force -WarningAction SilentlyContinue | Out-Null
shutdown /r /t 5
