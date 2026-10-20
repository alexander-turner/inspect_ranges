# Spike battery: cyris-build (linux-examples v1, slice 2)

*The CyRIS reference fixture promoted to a built, verified, solved range: the desktop recipe realizes upstream's tasks (accounts with the weak root password, analyst tools, the emulated ssh-attack log noise, both planted captures synthesized deterministically, the dummy resident `daemon` process), the webserver recipe realizes apache2+php and its captures, the firewall rides as a plain-router guest carrying the upstream 25/53 forwarding ACL, the build's behavioral trios prove all three challenges (local privesc via the weak root password over a pty; the firewall-policy measurement by closed-vs-filtered; forensics triage with tshark), and a real `inspect eval` boots the built range with every reference chain scoring 1.0 through the DESKTOP FOOTHOLD and the sandbox wall pinned. Serializes on `/tmp/inspect-ranges-battery.lock`; CID band 4110.*

*Reproduce: `./run.sh` (noble + focal vendor images in the shared cache, `vhost_vsock`; ~25 min). `./run.sh down` tears down.*

## Checks

1. **C1** the fixture builds green; all nine check scripts ran (`behavioral checks=9`), reference 1.0 / insufficient 0.0 / forged 0.0 per challenge.
2. **C2** the eval leg: three samples (one per challenge), each reference chain exits clean and scores 1.0 valid; the registered sandbox is the desktop and `sandbox("webserver")` lands there too.

## Files

- `run.sh`: derive, build, eval under the battery lock.
- `cyris_eval.py`: the mockllm eval whose per-sample solver replays the matching reference script through the foothold.
