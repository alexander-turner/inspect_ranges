# Range container for the networking spike: libvirtd + QEMU + nftables (for
# the generated range-netns ruleset). Bridges and firewall rules come from
# compiled artifacts mounted at /render — nothing here is hand-configured.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    libvirt-daemon-system libvirt-clients virtinst \
    qemu-system-x86 qemu-utils \
    cloud-image-utils \
    iproute2 nftables \
    && rm -rf /var/lib/apt/lists/*

# same in-container qemu.conf as the earlier spikes (see l2-attach README)
RUN printf 'user = "root"\ngroup = "root"\nsecurity_driver = "none"\ndynamic_ownership = 0\nremember_owner = 0\ncgroup_controllers = []\n' \
    >> /etc/libvirt/qemu.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
