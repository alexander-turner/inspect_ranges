---
type: decision
title: "Networking v0.2: richer ACLs, explicit routing, scoped egress, dual-stack types — under a lockstep rule"
status: proposed
tags: [inspect-ranges, range-yaml, schema, networking, decision]
timestamp: 2026-10-06
---

# Networking v0.2: richer ACLs, explicit routing, scoped egress, dual-stack types — under a lockstep rule

*Decision record for the networking surface of schema v0.2, produced ahead of the compiler's plan/allocation and render stages so those stages encode the richer model once instead of migrating later. Supersedes the "one ACL vocabulary, on routers" normalization in [schema-v0.1-scope](schema-v0.1-scope.md) (which remains accurate for v0.1). Draft fixtures exercising every construct live in [ranges-v0.2-drafts/](ranges-v0.2-drafts/).*

## The lockstep rule (binding for all of v0.2)

Every expressible construct ships as a four-part unit: **schema shape + semantic validation + compiler realization + booted conformance check** (the net-compile T-battery pattern). The networking schema is a containment claim; a field the runtime does not enforce is a lie about the topology. Where this record designs ahead of realization, the construct is documented here but gated by a reject-don't-guess validator with a stable error code, so `validate` refuses what the compiler cannot yet realize. Enabling a construct later means deleting its gate validator in the same change that lands its realization and conformance battery, never editing types.

## 1. ACL v2

One vocabulary, still on routers, still default-deny and stateful (`established,related` always accepted). What changes:

- **Endpoints**: `network-name | host-name | CIDR`. Host names resolve to their allocated interface addresses at plan time (which is why allocation must precede rule rendering); a CIDR is the escape hatch for literal addresses, including `/32` single hosts and `0.0.0.0/0`. Network names and guest names therefore become **one namespace**: v0.2 requires them disjoint (`name-collision`).
- **Protocols**: `tcp | udp | icmp`. `icmp` takes no port (`invalid-icmp-rule` otherwise); tcp/udp keep `proto/port` and `proto/lo-hi`.
- **Rule order is first-match**, and rules carry exactly one of `allow:` or `deny:`. `deny` exists for carve-outs inside a broader allow (deny ssh from dmz to one host, allow the rest). v0.1 lists (all-allow) are order-insensitive, so their semantics are unchanged.

```yaml
routers:
  - name: router
    interfaces: [{ network: dmz }, { network: internal }]
    acl:
      - { from: dmz, to: db, deny: [tcp/22] }            # carve-out, first-match
      - { from: dmz, to: internal, allow: [tcp/5432] }   # v0.1 form, unchanged
      - { from: web, to: db, allow: [tcp/3306] }         # host endpoints
      - { from: 0.0.0.0/0, to: dmz, allow: [tcp/1-65535] }  # CIDR endpoint
      - { from: dmz, to: internal, allow: [icmp] }
```

**Realization sketch.** Network endpoints keep the net-compile symbolic-interface pattern (`iifname`/`oifname` against the router's MAC-pinned NIC names). Host endpoints compile to allocated-IP matches (`ip saddr`/`ip daddr`) combined with the interface match of the host's network. CIDR endpoints compile to address matches alone. First-match order is nftables' native evaluation order; `deny` rules emit `drop` verdicts in place. ICMP emits `meta l4proto icmp accept` (and `icmpv6` once the family gate opens).

**Forced-by / design-ahead ledger:**

| Construct | Evidence |
|---|---|
| CIDR endpoints, `0.0.0.0/0` | MHBench `security_rules.tf` (remote_ip_prefix); restores the two things the v0.1 translation dropped (direction expressed as rule pairs, the any-source form) |
| Subnet-keyed rules | CybORG CAGE-2 NACLs (the syntax `networks[].acl` was originally shaped after); v0.1 already had the network-endpoint case |
| Host endpoints | Design-ahead: no surveyed artifact forces them (OpenStack groups in MHBench coincide with subnets), but host-granular segmentation is standard enterprise practice and retrofitting endpoint resolution into a hardened renderer is the expensive path. The plan-time host→IP resolution also establishes the pattern `attack_path` reachability linting needs later |
| `icmp` | Design-ahead: ping-based discovery is baseline tradecraft; a model that cannot express "ICMP allowed between segments" cannot describe most real networks |
| `deny` carve-outs | Design-ahead: the standard idiom for "everything except" policies; without it, carve-outs explode into allow-list enumerations |

**Semantics note recorded for the fixture:** OpenStack security groups admit a new flow only when the destination group has a matching ingress rule *and* the source group has a matching egress rule. A single ordered router list expresses the same reachability by enumerating the allowed (src, dst) pairs; [mhbench-acl-lossless.yaml](ranges-v0.2-drafts/mhbench-acl-lossless.yaml) carries the rule-for-rule mapping in comments.

## 2. Routing

v0.1 has no routing model: the compiler would have to guess default gateways, and two routers on one segment is silently ambiguous. v0.2 makes routing explicit and cheap in the common case:

- **Gateway election per network**: when exactly one router attaches to a network, it is that network's gateway (all six v0.1 examples remain valid unchanged, since none has more than one router per segment). When more than one router attaches, the network must declare `gateway: <router-name>`; otherwise `ambiguous-gateway`.
- **Static routes on routers**: `routers[].routes: [{to: CIDR, via: IP}]` for chained topologies (the via address must belong to a network the router attaches to; otherwise `unreachable-route`). Guests get only their gateway default route; per-host routes stay out until something forces them.

```yaml
networks:
  - name: core
    cidr: 10.80.20.0/24
    mode: isolated
    gateway: r1            # two routers attach to core; election must be explicit
routers:
  - name: r1
    interfaces: [{ network: dmz }, { network: core, ip: 10.80.20.1 }]
    routes: [{ to: 10.80.30.0/24, via: 10.80.20.2 }]   # vault lives behind r2
  - name: r2
    interfaces: [{ network: core, ip: 10.80.20.2 }, { network: vault }]
```

Routing changes one v0.1 ACL check: on a transit router, rule endpoints may be networks the router *reaches via its routes*, not only attached ones (each transit router enforces its own policy on traffic through it). `acl-unattached-network` therefore relaxes from an attachment check to a reachability check: an endpoint must be attached or covered by a route, else rejected.

Forcing fixture: [chained-routers.yaml](ranges-v0.2-drafts/chained-routers.yaml). Conformance shape: the T-battery extended with a cross-router path (allowed port reachable end-to-end through two hops, denied port dropped at the declaring router, return path stateful).

## 3. Egress

`none | open` grows a scoped form, on both network egress (`mode: nat`) and the attacker:

```yaml
networks:
  - name: corp
    cidr: 10.80.10.0/24
    mode: nat
    egress:
      allow: ["198.51.100.7:tcp/443", "0.0.0.0/0:udp/123", "updates.example.com:tcp/443"]
attacker:
  egress: none             # shorthands stay; or the same {allow: [...]} form
```

Entries are `CIDR[:proto/port]` or `FQDN:proto/port`. CIDR entries realize as nftables rules in the range netns (the hypervisor-side invariants remain the external containment authority, per the hardened-container finding). **FQDN entries are gated** (`egress-fqdn-not-realized`) until a realization is designed (candidate: dnsmasq-populated nft sets); they are in the vocabulary now because egress-by-name is how real allowlists are written (the inspect-glovebox precedent). The queued NAT-conformance spike is this section's acceptance battery: no-egress conformance already holds (hardened-container); the granted case must prove exactly-the-allowlist, before and after in-range compromise.

## 4. Address family

Schema types move to the generic pydantic forms (`IPvAnyAddress`, `IPvAnyNetwork`) so the type surface never needs a second migration. Expressibility stays IPv4: any IPv6 literal anywhere is rejected with `ipv6-not-realized` until, per construct, its slice lands (allocation family handling, `inet`-family nftables with `icmpv6`, DNS AAAA records, and conformance additions, including the mitm6-class scenarios that will eventually force this). All address-family assumptions concentrate in the allocation module so the gate-opening change is localized.

## 5. Exclusions, with teeth

Still excluded, now each with a stable error code so the boundary is visible to authors and models (today these surface as `unknown-key`; the codes reserve the names):

| Excluded | Code | Revisit when |
|---|---|---|
| VLANs / trunking on shared bridges | `vlan-not-supported` | A Ludus-class range is translated |
| Same-network multi-NIC | (existing `duplicate-attachment`) | Something forces bonding/failover scenarios |
| Traffic shaping / latency injection | `shaping-not-supported` | Defender-timing or WAN-realism work |

## 6. Reserved error codes

Added to the diagnostics registry as the v0.2 slices land: `name-collision`, `ambiguous-gateway`, `unreachable-route`, `acl-endpoint-unknown` (endpoint resolves to neither network, host, nor CIDR; carries did-you-mean), `invalid-icmp-rule`, `invalid-deny-rule` (rule with both or neither of allow/deny), `ipv6-not-realized`, `egress-fqdn-not-realized`, `vlan-not-supported`, `shaping-not-supported`.

## 7. Migration

`schema_version: "0.2"`. Fully additive: every valid v0.1 spec is a valid v0.2 spec with identical semantics (v0.1 ACL lists are the all-allow, network-endpoint case, where order is immaterial; `egress: none|open` and absent `gateway`/`routes` keep their meanings). The six examples migrate by changing only the version literal. One new constraint can invalidate pathological v0.1 specs: network/guest name disjointness (`name-collision`); none of the six collides.

## 8. Public spec API (typed sandbox configuration)

The sandbox configuration is `str | RangeSpec`: a `range.yaml` path or a fully realized pydantic object, matching Inspect's sandbox contract (`SandboxEnvironmentConfigType` is `BaseModel | str`) and the precedent set by the Docker, k8s, and Proxmox sandboxes. `sandbox=("libvirt_range", RangeSpec(...))` and `sandbox=("libvirt_range", "range.yaml")` are equally supported, and programmatic range construction (including by the generation layer later) goes through the same types as hand-written YAML.

Consequences:

- **Every spec model is public API, housed in `inspect_ranges.types`**: `RangeSpec`, `Network`, `Router`, `Host`, `Attacker`, `Interface`, `AclRule`, `Os`, `Resources`, `DnsConfig`, `DnsRecord`, `RangeMeta`, and the diagnostics types `Issue` and `ValidationReport`. The callables (`load_range`, `validate_range`, `semantic_issues`) export from the package top level. Everything is documented in the reference docs, and model and field names become stability-governed by `schema_version` exactly like the YAML surface: a renamed field is a schema version bump, whichever surface it entered through.
- **Validation parity, documented difference in ergonomics**: a typed config is structurally and semantically valid at construction (the model validators run; an invalid construction raises with every finding, via `IssueError`); the YAML path additionally gets source positions and rendered hints via `validate_range`. Same checks, one implementation, two entry points.
- **Provider contract**: the sandbox provider accepts both forms; `config_files()` discovers `range.yaml` for the path form; the compiler consumes `RangeSpec` either way (as the e2e spike already demonstrated).

Construction ergonomics (level-set 2026-10-06, verified against the implemented models):

- **Typed construction reads like the YAML, including under strict type checking.** Strings coerce to address types (`cidr="10.80.10.0/24"`), literals take plain strings, and nested dicts are accepted via `model_validate` for fully config-literal style. Address-typed fields carry a `TYPE_CHECKING`-only `__init__` declaration so string inputs pass strict checkers while attribute reads keep the narrow types (`spec.networks[0].cidr` is `IPv4Network`); pyright itself guards stub/field drift. Field names are the statically-typed kwargs (`meta=`, `from_=`) via `validation_alias`/`serialization_alias`, with the YAML spellings (`range:`, `from:`) accepted in validation and emitted in serialization — plain `alias=` would have made `AclRule` unconstructible under strict checking, since `from=` is a syntax error.
- **`from` stays `from`** in YAML; typed construction writes `from_=` (Python keyword), documented as the one spelling divergence. No rename.
- **Models stay mutable** for flexible programmatic construction; valid-by-construction is therefore a point-in-time property, not an invariant. The compensating contract: **every consumer boundary revalidates**. When a `RangeSpec` object is passed as sandbox config, the provider round-trips it through `model_validate` (catching semantic drift and type-unsafe mutations alike) before compiling; `validate` and the compiler do the same for any typed input. Mutating between construction and handoff is safe and supported.
- **`RangeSpec` is the canonical public name** (the overview's earlier `Range` wording is updated); no alias.

## 9. Implementation path (the follow-on, not this record)

Each construct lands as a vertical slice under the lockstep rule, in dependency order: (0) public spec API — top-level exports, reference docs for every model, and the dual-form config contract stated in the provider design; (1) dual-stack types + gates and name disjointness (schema-only semantics, no realization needed); (2) ACL v2 with plan-time endpoint resolution — this forces the allocation stage design and is why this record precedes it; (3) routing (gateway election + static routes) with the two-hop conformance battery; (4) scoped CIDR egress with the NAT conformance spike; FQDN egress and IPv6 stay gated until their slices.
