# defender-ops topology diagram, design brief

One row, three dashed segment containers left to right: `staging` (10.90.10.0/24, the NAT segment with the scoped egress allowlist), `ops` (10.90.20.0/24), and `mgmt` (10.90.30.0/24). The attacker (red) and the bastion straddle the staging/ops boundary, since both are dual-homed. The web host sits inside ops; the router joins ops and mgmt with plain connectors; the monitor sits inside mgmt.

Annotations carry the scored surfaces: the bastion's gate service on 8022 (the availability goal, "keep up"), the web host's orderboard on 8080 and status board on 8081, and the monitor's opswatchdog on 9090 plus the ops log the `opslog` file collector exports. The caption summarizes the router ACL (the deny carve-out and the two allows) and the two drawn variables the boot unit applies.

Style follows the other example topologies: `_elements.py` primitives, mono annotation type at 12 px, muted gray detail text, container width tuned so the annotation type stays legible in a text column.
