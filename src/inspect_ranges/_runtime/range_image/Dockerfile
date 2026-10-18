# The production hardened range container (realizer-v1 slice 2, from the
# hardened-container spike template): QEMU runs as the unprivileged
# libvirt-qemu user with its seccomp sandbox on, libvirt's private mount
# namespaces are off (they need CAP_SYS_ADMIN, which the profile denies), and
# the outer jail (capability floor, docker-default seccomp/AppArmor,
# no-new-privileges, network_mode none) lives in the bundle's rendered
# compose.yaml. Realization artifacts arrive read-only at /render.

# Cloud Hypervisor for `vmm: cloud-hypervisor` guests and its EDK2 firmware,
# pinned by release and sha256. Fetched in a throwaway stage so the range image
# carries the two verified files and no download tooling.
FROM ubuntu:24.04 AS cloud-hypervisor
ARG CH_VERSION=v54.0
ARG CH_EDK2_TAG=ch-97eeb7b09
WORKDIR /out/usr/local
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && install -d -m 0755 bin share/cloud-hypervisor \
    && curl -fsSL -o bin/cloud-hypervisor "https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/$CH_VERSION/cloud-hypervisor-static" \
    && curl -fsSL -o share/cloud-hypervisor/firmware.fd "https://github.com/cloud-hypervisor/edk2/releases/download/$CH_EDK2_TAG/CLOUDHV.fd" \
    && printf '%s  %s\n' \
       4f4f98a3d661a40f3e5272627cc895a1b2e525f2f6bedf5f895f9cd21ba5c65b bin/cloud-hypervisor \
       dc2fc8f0e43b96712d9fccc52a3a590769606412b3e1bc911d217addd3bef624 share/cloud-hypervisor/firmware.fd \
       | sha256sum -c - \
    && chmod 0755 bin/cloud-hypervisor && chmod 0644 share/cloud-hypervisor/firmware.fd

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

# started directly by the boot script, unprivileged, default seccomp filter on;
# the tree carries its own modes (COPY --chmod would also apply to the parent
# directory it creates, leaving it untraversable by the unprivileged VMM)
COPY --from=cloud-hypervisor /out/ /

# security_driver = "none" disables only the MAC slot (sVirt): per-VM AppArmor
# profile loads need CAP_MAC_ADMIN and securityfs, which the outer jail denies
# by design. The per-VM boundary is DAC instead, which libvirt stacks
# regardless of the MAC choice: every domain's static seclabel runs its QEMU
# as its own GUEST_UID_BASE+cid uid (issue #5), with QEMU's seccomp sandbox on
# and docker-default AppArmor/seccomp confining the whole container.
# dynamic_ownership stays off: the boot script pre-owns each guest's files, so
# libvirt never chowns a shared backing golden.
RUN printf 'user = "libvirt-qemu"\ngroup = "kvm"\nsecurity_driver = "none"\ndynamic_ownership = 0\nremember_owner = 0\ncgroup_controllers = []\nnamespaces = []\nseccomp_sandbox = 1\n' \
    >> /etc/libvirt/qemu.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
