# Spike battery: cat-attack (standard images v1, slice 1)

*The standard attack image as bytes: the kali-class toolset (user-ratified 2026-10-18, metasploit included) recipe-builds over the noble golden with build-time egress (distro apt plus metasploit's official apt repository), presence-asserts every tool inside the build so a dropped package fails the producer, captures as a realized image, and a consumer range whose ATTACKER boots that image answers live probes over the channel: every ratified tool on PATH, nmap actually scanning the lab segment, msfvenom enumerating payload formats. The attack box boots under cloud-hypervisor (the attacker default), proving the image is CH-clean. Promotion to the bare catalog name `attack` and the spec default is slice-2/4 work (`publish`). Serializes on `/tmp/inspect-ranges-battery.lock`; CID band 4060.*

*Reproduce: `./run.sh` (noble vendor image in the shared cache, `vhost_vsock`, docker). `./run.sh down` tears down.*

## Checks

1. **A1/A2** the factory range builds green (the recipe's own tool assertions ran in-build) and the realized attack image lands in the cache.
2. **A3** a consumer spec names the realized image as its attacker: render accepts it, the box boots under cloud-hypervisor.
3. **A3c** every ratified tool answers on the booted box (nmap, sqlmap, hydra, john, msfconsole, msfvenom, ncat, socat, gobuster, ffuf, smbclient; impacket/requests asserted in-build).
4. **A3d/A3e** the toolset is functional, not just present: nmap scans a lab host; msfvenom enumerates formats.

## Files

- `run.sh`: derive, build, consumer boot, live tool probes under the battery lock.
- The factory itself lives in-tree at `catalog/attack/` (range.yaml plus the `catalog.attack-tools` recipe): project-owned content, built like any range.
