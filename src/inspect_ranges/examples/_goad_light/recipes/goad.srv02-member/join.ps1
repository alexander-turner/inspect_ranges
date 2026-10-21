# Member join to the child domain; the join reboot is issued DETACHED. No
# in-build sysprep (clones specialize from the generalized golden with fresh
# SIDs — the windows-ad-v1 slice 2 proof).
$ErrorActionPreference = 'Stop'
# the join credential is the DECLARED rotation value: dc02's realize rotates
# NORTH\Administrator before this recipe runs (range.yaml dc02
# services[active-directory].credentials; parked-decisions entry 2). This
# script's text auto-logs as a 4104 suspicious block; the pre-capture scrub
# clears the PowerShell logs, so dc02's credential never rides srv02's
# captured disk (a cross-host value here would otherwise skip a ladder rung).
$pass = ConvertTo-SecureString 'W1nterC@me&TheWallHeld' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('NORTH\Administrator', $pass)
Add-Computer -DomainName 'north.sevenkingdoms.local' -Credential $cred -Force -WarningAction SilentlyContinue
shutdown /r /t 5
