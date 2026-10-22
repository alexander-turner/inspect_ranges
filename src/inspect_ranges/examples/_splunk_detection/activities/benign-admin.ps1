# Benign background admin activity on the instrumented endpoint
# (scheduled-activity-v1): ordinary service queries, directory listings, and
# event-log reads, so the collected stream carries normal administrative
# telemetry (process creates for powershell and the queried tools) and a
# quiet range is not trivially stealthy. Everything here is read-only;
# output is discarded, nothing is written to disk.
$ErrorActionPreference = 'SilentlyContinue'

# service health sweep, the hourly-ops staple
Get-Service | Where-Object { $_.StartType -eq 'Automatic' } | Out-Null
sc.exe query state= all | Out-Null

# directory listings an admin runs while poking around
Get-ChildItem -Path 'C:\Program Files' | Out-Null
Get-ChildItem -Path 'C:\Windows\Temp' | Out-Null
Get-ChildItem -Path "$env:ProgramData" | Out-Null

# recent event-log reads (System and Application, newest entries only)
Get-WinEvent -LogName System -MaxEvents 50 | Out-Null
Get-WinEvent -LogName Application -MaxEvents 50 | Out-Null

# a routine process and session glance
Get-Process | Out-Null
query user 2>$null | Out-Null

exit 0
