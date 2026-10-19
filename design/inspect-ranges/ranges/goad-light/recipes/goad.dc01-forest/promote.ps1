# Forest root promotion (sevenkingdoms.local). The reboot is issued DETACHED
# at the end (the exec session dies with a reboot).
$ErrorActionPreference = 'Stop'
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
$pass = ConvertTo-SecureString 'RangeAdm!n2026' -AsPlainText -Force
Install-ADDSForest -DomainName 'sevenkingdoms.local' -DomainNetbiosName 'SEVENKINGDOMS' `
  -SafeModeAdministratorPassword $pass -InstallDns `
  -NoRebootOnCompletion -Force -WarningAction SilentlyContinue | Out-Null
shutdown /r /t 5
