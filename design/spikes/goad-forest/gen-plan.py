"""Derive the forest build plan from the example's actual range.yaml.

Loads the goad-light fixture's `range.yaml` (now promoted to `examples/goad-light/`) through `inspect_ranges.schema.load_range` (the first time an example fixture drives real VMs) and emits:

- `tmp/plan/plan.env` — shell variables for run.sh and the in-container boot script: guest names, hostnames, FQDNs, IPs, the derived domain structure (forest root and child from the FQDNs), and the DNS chain (attacker -> first authoritative; dc02 -> dc01; srv02 -> dc02, per the range's provider-inventory note).
- `tmp/plan/{network-config,user-data,meta-data}` — the Linux attacker box's cloud-init seed: static IP on the lab subnet, DNS pointed at the authoritative DC, matching how the compiler would realize `attacker.interfaces`.

Run with the repo venv: `../../../.venv/bin/python gen-plan.py`
"""

import ipaddress
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent.parent / "src"))

from inspect_ranges.schema import load_range  # noqa: E402

RANGE_YAML = HERE.parent.parent.parent / "examples" / "goad-light" / "range.yaml"
PLAN = HERE / "tmp" / "plan"
ATTACKER_HOST_INDEX = 50  # IPAM allocation for the attacker's unpinned interface
ATTACKER_MAC = "52:54:00:60:00:32"


def main() -> None:
    spec = load_range(RANGE_YAML)
    PLAN.mkdir(parents=True, exist_ok=True)

    network = spec.networks[0]
    subnet = ipaddress.ip_network(network.cidr)
    hosts = {h.name: h for h in spec.hosts}
    assert network.dns is not None and network.dns.authoritative
    authoritative_ip = hosts[network.dns.authoritative[0]].interfaces[0].ip

    env: list[str] = [f"BRIDGE=br-{network.name}", f"PREFIX={subnet.prefixlen}"]
    domains: dict[str, str] = {}
    for name, host in hosts.items():
        assert host.fqdn is not None and host.hostname is not None
        domain = host.fqdn.split(".", 1)[1]
        domains[name] = domain
        up = name.upper()
        env += [
            f"{up}_IP={host.interfaces[0].ip}",
            f"{up}_HOSTNAME={host.hostname}",
            f"{up}_FQDN={host.fqdn}",
            f"{up}_DOMAIN={domain}",
        ]

    forest_root = domains["dc01"]
    child = domains["dc02"]
    assert child.endswith("." + forest_root), f"{child} is not a child of {forest_root}"
    attacker_ip = subnet.network_address + ATTACKER_HOST_INDEX
    env += [
        f"FOREST_ROOT={forest_root}",
        f"FOREST_NETBIOS={forest_root.split('.')[0].upper()}",
        f"CHILD_NEW_NAME={child.split('.')[0]}",
        f"CHILD_NETBIOS={child.split('.')[0].upper()}",
        f"CHILD_DOMAIN={child}",
        # the DNS chain from the range's dns note: dc02 -> dc01, srv02 -> dc02
        f"DC02_DNS={hosts['dc01'].interfaces[0].ip}",
        f"SRV02_DNS={hosts['dc02'].interfaces[0].ip}",
        f"ATTACKER_IP={attacker_ip}",
        f"ATTACKER_DNS={authoritative_ip}",
        f"ATTACKER_MAC={ATTACKER_MAC}",
    ]
    (PLAN / "plan.env").write_text("\n".join(env) + "\n")

    (PLAN / "network-config").write_text(
        f"""version: 2
ethernets:
  lab0:
    match: {{ macaddress: "{ATTACKER_MAC}" }}
    set-name: lab0
    addresses: [{attacker_ip}/{subnet.prefixlen}]
    nameservers:
      addresses: [{authoritative_ip}]
      search: [{forest_root}]
"""
    )
    (PLAN / "user-data").write_text("#cloud-config\nhostname: attacker\n")
    (PLAN / "meta-data").write_text("instance-id: goad-attacker\n")
    print(f"plan derived from {RANGE_YAML.name}: root={forest_root}, child={child}, attacker={attacker_ip} dns={authoritative_ip}")


if __name__ == "__main__":
    main()
