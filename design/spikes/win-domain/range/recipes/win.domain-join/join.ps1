# Domain join for the win-domain battery; the join reboot is issued DETACHED
# (the exec session dies with a reboot). No in-build sysprep: the member clone
# specialized from the generalized golden at boot, so its SID already differs
# from the DC's (the production path makes the ad-domain spike's
# sysprep-before-join step free).
$ErrorActionPreference = 'Stop'
$pass = ConvertTo-SecureString 'RangeAdm!n2026' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('RANGE\Administrator', $pass)
Add-Computer -DomainName 'range.local' -Credential $cred -Force -WarningAction SilentlyContinue
shutdown /r /t 5
