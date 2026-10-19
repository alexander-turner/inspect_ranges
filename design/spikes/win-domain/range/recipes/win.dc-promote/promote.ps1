# AD DS forest promotion for the win-domain battery. The reboot is issued
# DETACHED at the end: the exec session dies with a reboot, so the script must
# return before the OS goes down (ad-domain lesson 5).
$ErrorActionPreference = 'Stop'
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
$pass = ConvertTo-SecureString 'RangeAdm!n2026' -AsPlainText -Force
Install-ADDSForest -DomainName 'range.local' -DomainNetbiosName 'RANGE' `
  -SafeModeAdministratorPassword $pass -InstallDns `
  -NoRebootOnCompletion -Force -WarningAction SilentlyContinue | Out-Null
shutdown /r /t 5
