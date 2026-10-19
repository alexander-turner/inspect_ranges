#!/usr/bin/env python3
"""Spike-grade range compiler: spec.yaml -> every runtime networking artifact.

Emits to tmp/render/: allocation.json (IPAM: IPs, MACs, vsock CIDs),
bridges.txt, range-netns.nft (hypervisor-side invariants), per-VM cloud-init
seeds (static addressing, router nftables ruleset), and boot-vms.sh. Nothing
downstream is hand-written; this is the single-source-of-truth demonstration.
"""

import ipaddress
import json
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).parent
RENDER = HERE / "tmp" / "render"

GOLDEN = "/images/ubuntu-noble.qcow2"
FIRST_CID = 3
HOST_IP_BASE = 10  # hosts allocate .10, .11, ...; agent gets .2; routers declare theirs
AGENT_IP_OFFSET = 2


def bridge(network: str) -> str:
    return f"br-{network}"[:15]


def nic(network: str) -> str:
    return f"{network}0"[:15]


def mac(seg_index: int, host_index: int) -> str:
    return f"52:54:00:50:{seg_index:02x}:{host_index:02x}"


def main() -> None:
    spec = yaml.safe_load((HERE / "spec.yaml").read_text())
    nets = {n["name"]: ipaddress.ip_network(n["cidr"]) for n in spec["networks"]}
    net_index = {name: i for i, name in enumerate(nets)}

    # --- IPAM: deterministic allocation ------------------------------------
    vms: list[dict] = []  # {name, role, cid, interfaces: [{network, ip, mac}]}
    counters = {name: HOST_IP_BASE for name in nets}

    def allocate(name: str, role: str, interfaces: list[dict]) -> None:
        out = []
        for i, iface in enumerate(interfaces):
            network = iface["network"]
            if "ip" in iface:
                ip = ipaddress.ip_address(iface["ip"])
            elif role == "agent":
                ip = nets[network][AGENT_IP_OFFSET]
            else:
                ip = nets[network][counters[network]]
                counters[network] += 1
            out.append(
                {
                    "network": network,
                    "ip": str(ip),
                    "prefix": nets[network].prefixlen,
                    "mac": mac(net_index[network], len(vms) * 4 + i),
                }
            )
        vms.append(
            {"name": name, "role": role, "cid": FIRST_CID + len(vms), "interfaces": out}
        )

    for router in spec.get("routers", []):
        allocate(router["name"], "router", router["interfaces"])
    for host in spec.get("hosts", []):
        allocate(host["name"], "host", host["interfaces"])
    allocate(spec["attacker"]["host"], "agent", spec["attacker"]["interfaces"])

    gateways = {  # segment -> router ip on it
        iface["network"]: iface["ip"]
        for vm in vms
        if vm["role"] == "router"
        for iface in vm["interfaces"]
    }

    # --- render -------------------------------------------------------------
    for vm in vms:
        d = RENDER / "vms" / vm["name"]
        d.mkdir(parents=True, exist_ok=True)
        d.joinpath("meta-data").write_text(
            f"instance-id: {spec['range']['name']}-{vm['name']}\nlocal-hostname: {vm['name']}\n"
        )
        ethernets = {}
        for iface in vm["interfaces"]:
            entry: dict = {
                "match": {"macaddress": iface["mac"]},
                "set-name": nic(iface["network"]),
                "addresses": [f"{iface['ip']}/{iface['prefix']}"],
            }
            if vm["role"] != "router":
                entry["routes"] = [
                    {"to": "default", "via": gateways[iface["network"]]}
                ]
            ethernets[nic(iface["network"])] = entry
        d.joinpath("network-config").write_text(
            yaml.safe_dump({"version": 2, "ethernets": ethernets}, sort_keys=False)
        )
        user_data: dict = {"hostname": vm["name"]}
        if vm["role"] == "router":
            router_spec = next(
                r for r in spec["routers"] if r["name"] == vm["name"]
            )
            user_data["write_files"] = [
                {"path": "/etc/nftables.conf", "content": router_nft(router_spec)}
            ]
            user_data["runcmd"] = [
                ["sysctl", "-w", "net.ipv4.ip_forward=1"],
                ["systemctl", "enable", "--now", "nftables"],
            ]
        d.joinpath("user-data").write_text(
            "#cloud-config\n" + yaml.safe_dump(user_data, sort_keys=False)
        )

    RENDER.joinpath("bridges.txt").write_text(
        "".join(f"{bridge(name)}\n" for name in nets)
    )
    # hypervisor-side invariant: the range netns never routes between segments,
    # even if ip_forward were somehow enabled (bridged frames don't hit this
    # hook while br_netfilter is off; routing is the router guest's job)
    RENDER.joinpath("range-netns.nft").write_text(
        "flush ruleset\n"
        "table inet rangehost {\n"
        "  chain forward { type filter hook forward priority 0; policy drop; }\n"
        "}\n"
    )
    RENDER.joinpath("allocation.json").write_text(json.dumps(vms, indent=2) + "\n")
    RENDER.joinpath("boot-vms.sh").write_text(boot_script(vms))
    print(f"rendered {len(vms)} VMs, {len(nets)} segments -> {RENDER}")


def router_nft(router: dict) -> str:
    rules = []
    for entry in router.get("acl", []):
        for allow in entry["allow"]:
            proto, port = allow.split("/")
            rules.append(
                f'    iifname "{nic(entry["from"])}" oifname "{nic(entry["to"])}" '
                f"{proto} dport {port} accept"
            )
    body = "\n".join(rules)
    return (
        "#!/usr/sbin/nft -f\n"
        "flush ruleset\n"
        "table inet fw {\n"
        "  chain forward {\n"
        "    type filter hook forward priority 0; policy drop;\n"
        "    ct state established,related accept\n"
        f"{body}\n"
        "  }\n"
        "}\n"
    )


def boot_script(vms: list[dict]) -> str:
    lines = [
        "#!/bin/bash",
        "# Generated by compile.py; runs inside the range container.",
        "set -euxo pipefail",
    ]
    for vm in vms:
        name = vm["name"]
        networks = " ".join(
            f"--network bridge={bridge(i['network'])},model=virtio,mac={i['mac']}"
            for i in vm["interfaces"]
        )
        lines += [
            f"qemu-img create -f qcow2 -F qcow2 -b {GOLDEN} /scratch/{name}.qcow2 10G",
            f"cloud-localds -N /render/vms/{name}/network-config /scratch/{name}-seed.iso "
            f"/render/vms/{name}/user-data /render/vms/{name}/meta-data",
            f"virt-install --connect qemu:///system --name {name} "
            "--memory 1024 --vcpus 1 --cpu host-passthrough "
            f"--disk path=/scratch/{name}.qcow2,format=qcow2,bus=virtio "
            f"--disk path=/scratch/{name}-seed.iso,device=cdrom "
            f"{networks} --vsock cid.address={vm['cid']} "
            "--osinfo ubuntu24.04 --import --graphics none --noautoconsole",
        ]
    lines.append("virsh -c qemu:///system list")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.exit(main())
