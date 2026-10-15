# The production hardened range container (realizer-v1 slice 2, from the
# hardened-container spike template): QEMU runs as the unprivileged
# libvirt-qemu user with its seccomp sandbox on, libvirt's private mount
# namespaces are off (they need CAP_SYS_ADMIN, which the profile denies), and
# the outer jail (capability floor, docker-default seccomp/AppArmor,
# no-new-privileges, network_mode none) lives in the bundle's rendered
# compose.yaml. Realization artifacts arrive read-only at /render.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
# python3 + tcpdump serve the evidence-capture SIDECAR (same pinned image, its
# own compose service): inert in the range service itself, which holds no
# NET_RAW; the capture grant lives only on the sidecar (evidence-v1.md)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libvirt-daemon-system libvirt-clients virtinst \
    qemu-system-x86 qemu-utils \
    cloud-image-utils \
    iproute2 nftables dnsmasq \
    procps libcap2-bin \
    python3 tcpdump \
    && rm -rf /var/lib/apt/lists/*

RUN printf 'user = "libvirt-qemu"\ngroup = "kvm"\nsecurity_driver = "none"\ndynamic_ownership = 1\nremember_owner = 0\ncgroup_controllers = []\nnamespaces = []\nseccomp_sandbox = 1\n' \
    >> /etc/libvirt/qemu.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
