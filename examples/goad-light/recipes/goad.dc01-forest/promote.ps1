# Forest root promotion (sevenkingdoms.local). The reboot is issued DETACHED
# at the end (the exec session dies with a reboot).
$ErrorActionPreference = 'Stop'
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
# the DSRM safe-mode password is a SET, not an authentication: it stays the
# golden's derive-time constant (winimage/render
# DEFAULT_WINDOWS_ADMIN_PASSWORD). The built-in Administrator's LIVE
# credential is rotated to the declared value at the end of realize.ps1
# (parked-decisions entry 2); DSRM is recovery-mode only, not a goal principal.
$pass = ConvertTo-SecureString 'RangeAdm!n2026' -AsPlainText -Force
Install-ADDSForest -DomainName 'sevenkingdoms.local' -DomainNetbiosName 'SEVENKINGDOMS' `
  -SafeModeAdministratorPassword $pass -InstallDns `
  -NoRebootOnCompletion -Force -WarningAction SilentlyContinue | Out-Null
shutdown /r /t 5
