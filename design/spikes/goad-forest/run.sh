#!/bin/bash
# GOAD-light forest spike: build the example range.yaml's two-domain forest
# (root DC + child-domain DC + child-domain member + Linux attacker) through
# our pipeline, then verify trust, DNS chain, cross-domain auth, Linux
# resolution of the AD zone, and save/restore of the whole forest.
# See README.md. Usage: ./run.sh [down]
set -euo pipefail
cd "$(dirname "$0")"

export IMAGE_CACHE="${IMAGE_CACHE:-$HOME/.cache/inspect-ranges/images}"
V="virsh -c qemu:///system"
C="python3 ../vsock-exec/host/client.py"
PY="../../../.venv/bin/python"
PW='Sp1keAdm!n2026'

if [[ "${1:-}" == "down" ]]; then
  docker compose down -v
  exit 0
fi

for f in ws2022-eval.iso virtio-win.iso ubuntu-noble.qcow2; do
  [[ -f "$IMAGE_CACHE/$f" ]] || { echo "missing $IMAGE_CACHE/$f (see win-guest / net-compile READMEs)"; exit 1; }
done

"$PY" gen-plan.py
source tmp/plan/plan.env

docker compose up -d --build --wait

if ! docker compose exec -T range test -f /scratch/win-golden.qcow2; then
  echo "=== golden image install (one-time, ~3 min) ==="
  docker compose exec -T range bash /assets/install.sh
  until [[ "$(docker compose exec -T range $V domstate wininstall)" != "running" ]]; do sleep 15; done
  docker compose exec -T range $V undefine wininstall
fi

sid_of() {
  python3 ga.py ps "$1" 180 2>/dev/null <<'EOF'
$ProgressPreference = 'SilentlyContinue'
$sid = (Get-CimInstance Win32_UserAccount -Filter "LocalAccount='True' AND Name='Administrator'").SID
$sid -replace '-500$', ''
EOF
}

configure_guest() {  # $1 domain, $2 ip, $3 dns, $4 newname
  python3 ga.py ps "$1" 300 <<EOF
\$ProgressPreference = 'SilentlyContinue'
\$ErrorActionPreference = 'Stop'
\$a = Get-NetAdapter | Sort-Object ifIndex | Select-Object -First 1
Set-NetIPInterface -InterfaceIndex \$a.ifIndex -Dhcp Disabled
New-NetIPAddress -InterfaceIndex \$a.ifIndex -IPAddress $2 -PrefixLength $PREFIX | Out-Null
Set-DnsClientServerAddress -InterfaceIndex \$a.ifIndex -ServerAddresses $3
Rename-Computer -NewName $4 -Force -WarningAction SilentlyContinue | Out-Null
& shutdown.exe /r /t 3
EOF
}

sysprep_vm() {  # $1 domain
  python3 ga.py ps "$1" 300 <<'EOF'
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
$xml = @'
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ComputerName>*</ComputerName>
      <TimeZone>UTC</TimeZone>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <InputLocale>en-US</InputLocale>
      <SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage>
      <UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <HideLocalAccountScreen>true</HideLocalAccountScreen>
        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <ProtectYourPC>3</ProtectYourPC>
      </OOBE>
      <UserAccounts>
        <AdministratorPassword>
          <Value>Sp1keAdm!n2026</Value><PlainText>true</PlainText>
        </AdministratorPassword>
      </UserAccounts>
    </component>
  </settings>
</unattend>
'@
Set-Content -Path C:\sysprep-unattend.xml -Value $xml -Encoding UTF8
Start-Process -FilePath C:\Windows\System32\Sysprep\sysprep.exe `
  -ArgumentList '/generalize', '/oobe', '/reboot', '/quiet', '/unattend:C:\sysprep-unattend.xml'
EOF
}

wait_newsid() {  # $1 domain, $2 old sid
  local s
  for _ in $(seq 1 180); do
    s=$(sid_of "$1" || true)
    if [[ -n "$s" && "$s" != "$2" ]]; then echo "$s"; return 0; fi
    sleep 5
  done
  echo "ERROR: $1 never specialized" >&2
  return 1
}

echo "=== boot forest from the range.yaml plan: $FOREST_ROOT + $CHILD_DOMAIN ==="
TSTART=$(date +%s)
docker compose exec -T range bash /assets/boot-forest.sh >/dev/null 2>&1
for vm in dc01 dc02 srv02; do python3 ga.py wait "$vm" 300; done
SID_GOLD=$(sid_of dc01)
echo "golden machine SID: $SID_GOLD"

echo "=== sysprep dc02 + srv02 in parallel (SID uniqueness: child domain SID derives from dc02; srv02's SID must differ from both domain SIDs) ==="
sysprep_vm dc02
sysprep_vm srv02

echo "=== configure + promote dc01 -> forest root $FOREST_ROOT ==="
BT=$(python3 ga.py boottime dc01)
configure_guest dc01 "$DC01_IP" 127.0.0.1 "$DC01_HOSTNAME"
python3 ga.py wait-newboot dc01 "$BT" 600
TPROMO=$(date +%s)
BT=$(python3 ga.py boottime dc01)
python3 ga.py ps dc01 1800 <<EOF
\$ProgressPreference = 'SilentlyContinue'
\$ErrorActionPreference = 'Stop'
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
\$pw = ConvertTo-SecureString '$PW' -AsPlainText -Force
Install-ADDSForest -DomainName $FOREST_ROOT -DomainNetbiosName $FOREST_NETBIOS \`
  -SafeModeAdministratorPassword \$pw -InstallDns -Force -NoRebootOnCompletion \`
  -WarningAction SilentlyContinue | Out-Null
& shutdown.exe /r /t 3
EOF
python3 ga.py wait-newboot dc01 "$BT" 900
converged=""
for _ in $(seq 1 90); do
  if python3 ga.py ps dc01 60 >/dev/null 2>&1 <<EOF
\$ProgressPreference = 'SilentlyContinue'
\$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
Get-ADDomain $FOREST_ROOT | Out-Null
Resolve-DnsName -Type SRV _ldap._tcp.$FOREST_ROOT -Server 127.0.0.1 | Out-Null
EOF
  then converged=1; break; fi
  sleep 10
done
[[ -n "$converged" ]] || { echo "dc01 never converged"; exit 1; }
echo "forest root promotion: $(( $(date +%s) - TPROMO ))s"

echo "=== configure + promote dc02 -> child domain $CHILD_DOMAIN ==="
NEWSID_DC02=$(wait_newsid dc02 "$SID_GOLD")
echo "dc02 specialized, SID $NEWSID_DC02"
BT=$(python3 ga.py boottime dc02)
configure_guest dc02 "$DC02_IP" "$DC02_DNS" "$DC02_HOSTNAME"
python3 ga.py wait-newboot dc02 "$BT" 600
TCHILD=$(date +%s)
BT=$(python3 ga.py boottime dc02)
python3 ga.py ps dc02 1800 <<EOF
\$ProgressPreference = 'SilentlyContinue'
\$ErrorActionPreference = 'Stop'
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
\$pw = ConvertTo-SecureString '$PW' -AsPlainText -Force
\$cred = New-Object System.Management.Automation.PSCredential('$FOREST_NETBIOS\\Administrator', \$pw)
Install-ADDSDomain -NewDomainName $CHILD_NEW_NAME -ParentDomainName $FOREST_ROOT \`
  -DomainType ChildDomain -NewDomainNetbiosName $CHILD_NETBIOS -InstallDns -CreateDnsDelegation \`
  -Credential \$cred -SafeModeAdministratorPassword \$pw -Force -NoRebootOnCompletion \`
  -WarningAction SilentlyContinue | Out-Null
& shutdown.exe /r /t 3
EOF
python3 ga.py wait-newboot dc02 "$BT" 900
converged=""
for _ in $(seq 1 90); do
  if python3 ga.py ps dc02 60 >/dev/null 2>&1 <<EOF
\$ProgressPreference = 'SilentlyContinue'
\$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
Get-ADDomain $CHILD_DOMAIN | Out-Null
Resolve-DnsName -Type SRV _ldap._tcp.$CHILD_DOMAIN -Server 127.0.0.1 | Out-Null
EOF
  then converged=1; break; fi
  sleep 10
done
[[ -n "$converged" ]] || { echo "dc02 never converged"; exit 1; }
echo "child domain promotion: $(( $(date +%s) - TCHILD ))s"

echo "=== configure + join srv02 -> $CHILD_DOMAIN ==="
NEWSID_SRV=$(wait_newsid srv02 "$SID_GOLD")
echo "srv02 specialized, SID $NEWSID_SRV"
BT=$(python3 ga.py boottime srv02)
configure_guest srv02 "$SRV02_IP" "$SRV02_DNS" "$SRV02_HOSTNAME"
python3 ga.py wait-newboot srv02 "$BT" 600
TJOIN=$(date +%s)
BT=$(python3 ga.py boottime srv02)
python3 ga.py ps srv02 600 <<EOF
\$ProgressPreference = 'SilentlyContinue'
\$ErrorActionPreference = 'Stop'
Resolve-DnsName $DC02_FQDN | Out-Null
\$pw = ConvertTo-SecureString '$PW' -AsPlainText -Force
\$cred = New-Object System.Management.Automation.PSCredential('$CHILD_NETBIOS\\Administrator', \$pw)
Add-Computer -DomainName $CHILD_DOMAIN -Credential \$cred -Force -WarningAction SilentlyContinue
& shutdown.exe /r /t 3
EOF
python3 ga.py wait-newboot srv02 "$BT" 600
echo "member join: $(( $(date +%s) - TJOIN ))s"

echo "=== verify: forest shape, trust, DNS chain, cross-domain auth ==="
python3 ga.py ps dc01 300 <<EOF
\$ProgressPreference = 'SilentlyContinue'
\$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
'forest domains: ' + ((Get-ADForest).Domains -join ', ')
\$t = Get-ADTrust -Filter * | Select-Object -First 1
'trust: ' + \$t.Name + ' direction=' + \$t.Direction + ' parent-child=' + \$t.IntraForest
New-ADUser tester-parent -AccountPassword (ConvertTo-SecureString 'T3ster!2026' -AsPlainText -Force) -Enabled \$true
'created $FOREST_NETBIOS\tester-parent'
EOF

python3 ga.py ps srv02 300 <<EOF
\$ProgressPreference = 'SilentlyContinue'
\$ErrorActionPreference = 'Stop'
hostname
if (-not (Test-ComputerSecureChannel)) { exit 1 }
'secure channel to $CHILD_DOMAIN: OK'
'DNS chain (srv02 -> dc02 -> dc01): ' + (Resolve-DnsName $DC01_FQDN | Select-Object -First 1 -ExpandProperty IPAddress)
& net.exe use \\\\$DC01_FQDN\\SYSVOL /user:$FOREST_NETBIOS\\tester-parent T3ster!2026 | Out-Null
if (\$LASTEXITCODE -ne 0) { 'cross-domain auth (child member -> parent DC) FAILED'; exit 1 }
'cross-domain auth: child member reached parent DC share as $FOREST_NETBIOS\tester-parent'
& net.exe use \\\\$DC01_FQDN\\SYSVOL /delete | Out-Null
New-Item -ItemType Directory -Force -Path C:\\share | Out-Null
New-SmbShare -Name share -Path C:\\share -ErrorAction SilentlyContinue | Out-Null
Set-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -Enabled True -Profile Any
'share up on member'
EOF

python3 ga.py ps dc01 300 <<EOF
\$ProgressPreference = 'SilentlyContinue'
\$ErrorActionPreference = 'Stop'
& net.exe use \\\\$SRV02_FQDN\\share /user:$FOREST_NETBIOS\\tester-parent T3ster!2026 | Out-Null
if (\$LASTEXITCODE -ne 0) { 'cross-domain auth (parent user -> child member share) FAILED'; exit 1 }
'cross-domain auth: parent user reached child-domain member share through the trust'
& net.exe use \\\\$SRV02_FQDN\\share /delete | Out-Null
EOF

echo "=== Linux attacker: resolve the AD zone through DC DNS, reach Kerberos/LDAP ==="
$C 9 wait
$C 9 exec "cloud-init status --wait >/dev/null 2>&1; getent hosts $DC01_FQDN $DC02_FQDN $SRV02_FQDN"
$C 9 exec "for ip in $DC01_IP $DC02_IP; do for p in 88 389; do timeout 3 bash -c \"echo > /dev/tcp/\$ip/\$p\" && echo \"PASS \$ip:\$p reachable\"; done; done"

TBUILD=$(( $(date +%s) - TSTART ))
echo "=== save/restore the whole forest ==="
TSAVE=$(date +%s)
for vm in dc01 dc02 srv02 attacker; do docker compose exec -T range $V save "$vm" "/scratch/$vm.sav" >/dev/null; done
for vm in dc01 dc02 srv02 attacker; do docker compose exec -T range $V restore "/scratch/$vm.sav" >/dev/null; done
for vm in dc01 dc02 srv02; do python3 ga.py wait "$vm" 120 && python3 ga.py settime "$vm"; done
echo "save+restore 4 VMs: $(( $(date +%s) - TSAVE ))s"
python3 ga.py ps srv02 300 <<'EOF'
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
if (-not (Test-ComputerSecureChannel)) { exit 1 }
'secure channel after restore: OK'
EOF
python3 ga.py ps dc01 300 <<'EOF'
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
'forest after restore: ' + ((Get-ADForest).Domains -join ', ')
EOF
$C 9 wait
$C 9 exec "getent hosts $DC01_FQDN >/dev/null && echo 'PASS attacker resolution after restore'"

echo "TOTAL build (boot -> verified forest): ${TBUILD}s"
echo "OK. Tear down with: ./run.sh down"
