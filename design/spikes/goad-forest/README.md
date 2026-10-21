# Spike: GOAD-light forest — the flagship example's two-domain AD forest, driven by its range.yaml

*Closes the two items the [ad-domain spike](../ad-domain/README.md) left open: a full parent+child forest, and Linux guests resolving the AD zone. The build plan (guest names, hostnames, FQDNs, IPs, subnet, DNS chain, domain structure) is **derived from the actual example fixture** — `gen-plan.py` loads [goad-light/range.yaml](../../../src/inspect_ranges/examples/_goad_light/range.yaml) through `inspect_ranges.schema.load_range` and parses the forest shape from the FQDNs — the first time an example range.yaml drives real VMs. Run on the m6i.metal devbox, 2026-10-04. `./run.sh` reproduces end to end; `./run.sh down` tears down. Deviation from upstream, noted honestly: guests are Server 2022 eval (the cached ISO) rather than GOAD's 2019; forest mechanics are version-independent.*

## Verdict

**The full GOAD-light topology works through the pipeline: forest root (`sevenkingdoms.local`, kingslanding), child domain (`north.sevenkingdoms.local`, winterfell) with automatic DNS delegation, a member joined to the child domain (castelblack), and the Linux attack box resolving the whole AD zone — built unattended in ~17 minutes, verified by cross-domain authentication in both directions, and restored from a whole-forest snapshot in 48 seconds with everything intact.**

## Measurements (metal, clean run; wall-clock)

| What | Result |
|---|---|
| Forest root promotion (feature + `Install-ADDSForest` + converged) | **186 s** |
| Child domain promotion (`Install-ADDSDomain` -ChildDomain + delegation + converged) | **467 s** |
| Member join to the child domain | **74 s** |
| Total: boot clones → fully verified forest (incl. 2 parallel syspreps) | **1007 s** |
| Save + restore all 4 VMs (3 Windows + Linux) | **48 s**; secure channel, forest, and attacker DNS resolution intact |
| SID uniqueness | three distinct machine SIDs (golden/dc02/srv02), per the ad-domain finding: the child domain's SID derives from dc02, so dc02 and srv02 are sysprep-generalized (in parallel with the root promotion); dc01 keeps the golden SID |

## What was verified (all green)

- **Forest shape**: `Get-ADForest` lists both domains; the parent-child trust is BiDirectional and intra-forest.
- **DNS chain exactly as the range.yaml notes it** (`srv02 → dc02 → dc01`): the member resolves the parent DC's FQDN through the child DC, whose DNS server picked up a forwarder to dc01 automatically at promotion (ADDS copies the client DNS settings), with the parent holding the delegation for `north`.
- **Cross-domain authentication, both directions**: the child-domain member reached the parent DC's SYSVOL as `SEVENKINGDOMS\tester-parent`, and the parent-domain user reached an SMB share on the child-domain member through the trust.
- **Linux guest in the AD zone** (the dnsmasq-forwarding gap, closed for the realization our compiler would emit): the attack box's cloud-init seed points its DNS at the authoritative DC per `dns.authoritative`; it resolves all three AD FQDNs and reaches Kerberos (88) and LDAP (389) on both DCs. (A range whose *Linux* guests get range-served DNS would instead need dnsmasq forwarding to the DC — that variant is compiler work, not an open platform question.)
- **Whole-forest checkpointing holds at 4-VM scale**: serialized saves, restore, clocks pushed, secure channel and trust intact — the multi-guest skew tolerance from checkpoint-clone re-verified on a forest.

## Lessons

1. **`Install-ADDSDomain` wants `-NewDomainNetbiosName`** (not `-DomainNetbiosName`, which `Install-ADDSForest` uses as `-DomainNetbiosName`) — the spike's only code fix.
2. **Child promotion is the long pole** (467 s vs 186 s for the root: it must contact the parent, create the delegation, and replicate), and it serializes behind the root. Build-time cost only: the whole converged forest restores in 48 s, so per-sample instantiation economics are unchanged from checkpoint-clone.
3. **Sysprep parallelizes cleanly** against the root promotion (two guests specializing while dc01 promotes), as predicted; the specialize-while-promoting overlap kept total build near the sum of the two promotions.
4. The range.yaml fixture was sufficient to drive the entire build: hosts, addressing, FQDN-derived domain structure, and the DNS chain all came from the spec; the only spike-side inventions were the attacker's IPAM allocation (`.50`) and credentials.

## Files

- `gen-plan.py` — range.yaml → `tmp/plan/plan.env` + the attacker's cloud-init seed (via `inspect_ranges.schema`)
- `run.sh` — golden (one-time), boot forest, parallel sysprep, root promotion, child promotion, join, verification battery, forest save/restore
- `assets/boot-forest.sh` — bridge + 3 Windows clones + Linux attack box (vsock CID 9)
- `assets/{autounattend.xml,install.sh}`, `ga.py`, `range/` — the shared Windows spike machinery (+ cloud-image-utils for the Linux seed)
- `tmp/run-final-clean.log` — the authoritative clean run
