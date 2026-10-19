# Member join to the child domain; the join reboot is issued DETACHED. No
# in-build sysprep (clones specialize from the generalized golden with fresh
# SIDs — the windows-ad-v1 slice 2 proof).
$ErrorActionPreference = 'Stop'
$pass = ConvertTo-SecureString 'RangeAdm!n2026' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('NORTH\Administrator', $pass)
Add-Computer -DomainName 'north.sevenkingdoms.local' -Credential $cred -Force -WarningAction SilentlyContinue
shutdown /r /t 5
