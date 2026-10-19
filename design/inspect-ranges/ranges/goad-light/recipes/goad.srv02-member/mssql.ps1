# SQL Server Express with the declared sa credential, service account, and
# impersonation chains (upstream config.json "mssql"). The installer downloads
# over the build's egress (the runtime posture stays isolated). Self-asserting.
$ErrorActionPreference = 'Stop'

$sa = 'Sup1_sa_P@ssw0rd!'
if (-not (Get-Service MSSQLSERVER -ErrorAction SilentlyContinue)) {
  $bootstrap = 'C:\Windows\Temp\sqlexpr'
  New-Item -ItemType Directory -Force -Path $bootstrap | Out-Null
  $exe = Join-Path $bootstrap 'SQLEXPR_x64_ENU.exe'
  $pinned = 'BEA033E778048748EB1C87BF57597F7F5449B6A15BAC55DDC08263C57F7A1CA8'
  if (-not (Test-Path $exe) -or (Get-FileHash -Algorithm SHA256 $exe).Hash -ne $pinned) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -UseBasicParsing -OutFile $exe `
      -Uri 'https://download.microsoft.com/download/7/c/1/7c14e92e-bdcb-4f89-b7cf-93543e7112d1/SQLEXPR_x64_ENU.exe'
  }
  # digest-pinned (a truncated transfer must fail here, not as an opaque
  # extractor code)
  if ((Get-FileHash -Algorithm SHA256 $exe).Hash -ne $pinned) {
    throw 'the SQL Express download does not match its pinned sha256'
  }
  # the self-extractor passes setup arguments straight through: no separate
  # extraction step (measured: /x: extraction exits 336)
  $setupArgs = @(
    '/Q', '/ACTION=Install', '/FEATURES=SQLENGINE', '/INSTANCENAME=MSSQLSERVER',
    '/SECURITYMODE=SQL', "/SAPWD=$sa",
    '/SQLSVCACCOUNT=NORTH\sql_svc', '/SQLSVCPASSWORD=YouWillNotKerboroast1ngMeeeeee',
    '/SQLSYSADMINACCOUNTS=BUILTIN\Administrators', '/TCPENABLED=1',
    '/IACCEPTSQLSERVERLICENSETERMS'
  )
  $setup = Start-Process -FilePath $exe -ArgumentList $setupArgs -Wait -PassThru
  if ($setup.ExitCode -notin 0, 3010) { throw "sql setup exited $($setup.ExitCode)" }
}
Start-Service MSSQLSERVER -ErrorAction SilentlyContinue

# fixed TCP port 1433 (Express defaults to dynamic ports)
$tcpKey = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server' |
  Where-Object { $_.PSChildName -match 'MSSQL\d+\.MSSQLSERVER' } | Select-Object -First 1
if ($tcpKey) {
  $ipAll = Join-Path $tcpKey.PSPath 'MSSQLServer\SuperSocketNetLib\Tcp\IPAll'
  Set-ItemProperty -Path $ipAll -Name TcpPort -Value '1433'
  Set-ItemProperty -Path $ipAll -Name TcpDynamicPorts -Value ''
  Restart-Service MSSQLSERVER -Force
}

# the declared impersonation chains (sysadmins, executeaslogin, executeasuser)
$sqlcmd = (Get-ChildItem 'C:\Program Files\Microsoft SQL Server' -Recurse -Filter sqlcmd.exe |
  Select-Object -First 1).FullName
if (-not $sqlcmd) { throw 'sqlcmd not found after install' }
$tsql = @"
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'NORTH\jon.snow')
  CREATE LOGIN [NORTH\jon.snow] FROM WINDOWS;
ALTER SERVER ROLE sysadmin ADD MEMBER [NORTH\jon.snow];
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'NORTH\samwell.tarly')
  CREATE LOGIN [NORTH\samwell.tarly] FROM WINDOWS;
GRANT IMPERSONATE ON LOGIN::[sa] TO [NORTH\samwell.tarly];
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'NORTH\brandon.stark')
  CREATE LOGIN [NORTH\brandon.stark] FROM WINDOWS;
GRANT IMPERSONATE ON LOGIN::[NORTH\jon.snow] TO [NORTH\brandon.stark];
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'NORTH\arya.stark')
  CREATE LOGIN [NORTH\arya.stark] FROM WINDOWS;
USE master;
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'NORTH\arya.stark')
  CREATE USER [NORTH\arya.stark] FOR LOGIN [NORTH\arya.stark];
GRANT IMPERSONATE ON USER::dbo TO [NORTH\arya.stark];
"@
Set-Content -Path 'C:\Windows\Temp\goad-mssql.sql' -Value $tsql
& $sqlcmd -S localhost -U sa -P $sa -b -i 'C:\Windows\Temp\goad-mssql.sql'
if ($LASTEXITCODE -ne 0) { throw "mssql impersonation config failed ($LASTEXITCODE)" }

# self-assertion: the listener and the sa credential, mechanically
$probe = & $sqlcmd -S 'tcp:localhost,1433' -U sa -P $sa -Q 'SELECT 1' -h -1 -W
if ($LASTEXITCODE -ne 0) { throw 'mssql is not answering on 1433 with the declared sa credential' }
Write-Output 'srv02 mssql realized: 1433, sa, service account, impersonation chains'
