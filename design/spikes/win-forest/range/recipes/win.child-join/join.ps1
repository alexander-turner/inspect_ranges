# Member join to the CHILD domain; the join reboot is issued DETACHED. No
# in-build sysprep: the member clone specialized from the generalized golden
# with a fresh SID (the slice-2 proof carries over).
$ErrorActionPreference = 'Stop'
$pass = ConvertTo-SecureString 'RangeAdm!n2026' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('NORTH\Administrator', $pass)
Add-Computer -DomainName 'north.corp.local' -Credential $cred -Force -WarningAction SilentlyContinue
shutdown /r /t 5
