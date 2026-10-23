"""Windows golden installation (windows-ad-v1 slice 1): eval ISO to sysprep'd golden.

The Windows analogue of `derive_golden`, with a different mechanism because Windows goldens are INSTALLED, not overlaid: a one-shot hardened range container boots `virt-install` against the digest-pinned install ISO with an autounattend answer file, the first logon installs the virtio guest tools and the vsock control daemon (compiled in-guest from the daemon bundle's Windows sources by the in-box `csc.exe` — the vsockd-win spike's proven path), and `sysprep /generalize /oobe /shutdown` finalizes the disk. The result is a generalized golden whose daemon service survives sysprep, so clones specialize per boot from the render-emitted unattend seed and announce readiness over vsock like any Linux guest.

The ratified posture (windows-ad-v1): artifacts are LOCAL ONLY, recipes-not-images — this module and the repo's answer files are what ships; the eval ISO comes from Microsoft per machine, and nothing Windows-derived is ever published.
"""

import fcntl
import hashlib
import logging
import os
import secrets
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path
from xml.sax.saxutils import escape

from .._build.manifest import now_iso
from .._compiler.render import DEFAULT_WINDOWS_ADMIN_PASSWORD
from .images import (
    DEFAULT_ARTIFACT_DIR,
    DaemonPin,
    DeriveError,
    ImageMetadata,
    _cache_file_name,  # pyright: ignore[reportPrivateUsage]
    _load_metadata,  # pyright: ignore[reportPrivateUsage]
    _metadata_path,  # pyright: ignore[reportPrivateUsage]
    _name_lock,  # pyright: ignore[reportPrivateUsage]
    resolve_daemon_bundle,
    sha256_file,
)
from .rangeimage import ensure_range_image

logger = logging.getLogger("inspect_ranges.winimage")

WIN_RECIPE_VERSION = "3"
"""Bumps re-key every Windows golden (the derive-recipe discipline)."""

DEFAULT_ADMIN_PASSWORD = DEFAULT_WINDOWS_ADMIN_PASSWORD
"""The golden's built-in Administrator password: deliberate scenario content (ranges authenticate in-guest with it; the CONTROL plane is the vsock daemon as SYSTEM and never uses it). Override per derive with `--admin-password`. The constant lives with the compiler (`render` falls back to it when a golden records no password), so a default-derived golden and a default-rendered seed agree."""

INSTALL_CID = 2900
"""The installer VM's vsock CID: `install-daemon.ps1` verifies the viosock driver BINDS (not merely stages), which needs a live device during install. Below 3000 per the realizer CID partition (batteries at 3000+, the channel harness below), high enough to dodge the harness's own fixtures."""

INSTALL_TIMEOUT_S = 2400.0
"""Bound on the unattended install (the win-guest spike measured ~190 s plus guest-tools and the daemon compile; eval media on slow storage can take far longer)."""

DISK_GB = 40
"""The golden's virtual disk size (sparse; the finalized image compacts at capture)."""

_INSTALL_UNATTEND = """<?xml version="1.0" encoding="utf-8"?>
<!-- Unattended Windows Server 2022 eval install (Standard Core, image index 1)
     for the inspect-ranges Windows golden: viostor injected in WinPE, virtio
     guest tools + the vsock control daemon installed at first logon, then
     sysprep /generalize /shutdown finalizes. No cached sysprep answer file is
     left behind: clones specialize from the per-guest unattend seed ISO the
     render emits. -->
<unattend xmlns="urn:schemas-microsoft-com:unattend"
          xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <SetupUILanguage><UILanguage>en-US</UILanguage></SetupUILanguage>
      <InputLocale>en-US</InputLocale>
      <SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage>
      <UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-PnpCustomizationsWinPE" processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <DriverPaths>
        <PathAndCredentials wcm:action="add" wcm:keyValue="1"><Path>E:\\amd64\\2k22</Path></PathAndCredentials>
        <PathAndCredentials wcm:action="add" wcm:keyValue="2"><Path>D:\\amd64\\2k22</Path></PathAndCredentials>
      </DriverPaths>
    </component>
    <component name="Microsoft-Windows-Setup" processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <DiskConfiguration>
        <Disk wcm:action="add">
          <DiskID>0</DiskID>
          <WillWipeDisk>true</WillWipeDisk>
          <CreatePartitions>
            <CreatePartition wcm:action="add">
              <Order>1</Order><Type>Primary</Type><Extend>true</Extend>
            </CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add">
              <Order>1</Order><PartitionID>1</PartitionID>
              <Format>NTFS</Format><Label>OS</Label><Active>true</Active>
            </ModifyPartition>
          </ModifyPartitions>
        </Disk>
      </DiskConfiguration>
      <ImageInstall>
        <OSImage>
          <InstallFrom>
            <MetaData wcm:action="add"><Key>/IMAGE/INDEX</Key><Value>1</Value></MetaData>
          </InstallFrom>
          <InstallTo><DiskID>0</DiskID><PartitionID>1</PartitionID></InstallTo>
        </OSImage>
      </ImageInstall>
      <UserData>
        <AcceptEula>true</AcceptEula>
        <FullName>user</FullName>
        <Organization>lab</Organization>
      </UserData>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ComputerName>WINGOLD</ComputerName>
      <TimeZone>UTC</TimeZone>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <HideLocalAccountScreen>true</HideLocalAccountScreen>
        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <ProtectYourPC>3</ProtectYourPC>
      </OOBE>
      <UserAccounts>
        <AdministratorPassword>
          <Value>__ADMIN_PASSWORD__</Value><PlainText>true</PlainText>
        </AdministratorPassword>
      </UserAccounts>
      <AutoLogon>
        <Enabled>true</Enabled>
        <Username>Administrator</Username>
        <Password><Value>__ADMIN_PASSWORD__</Value><PlainText>true</PlainText></Password>
        <LogonCount>1</LogonCount>
      </AutoLogon>
      <FirstLogonCommands>
        <SynchronousCommand wcm:action="add">
          <Order>1</Order>
          <CommandLine>cmd /c for %d in (D E F G) do if exist %d:\\virtio-win-guest-tools.exe %d:\\virtio-win-guest-tools.exe /install /passive /norestart</CommandLine>
          <Description>install virtio drivers and guest tools</Description>
        </SynchronousCommand>
        <SynchronousCommand wcm:action="add">
          <Order>2</Order>
          <CommandLine>cmd /c for %d in (D E F G) do if exist %d:\\install-daemon.ps1 powershell -ExecutionPolicy Bypass -NoProfile -File %d:\\install-daemon.ps1</CommandLine>
          <Description>install guest tooling</Description>
        </SynchronousCommand>
        <SynchronousCommand wcm:action="add">
          <Order>3</Order>
          <CommandLine>C:\\Windows\\System32\\Sysprep\\sysprep.exe /generalize /oobe /shutdown /quiet</CommandLine>
          <Description>generalize and finalize the golden (no cached answer file: clones specialize from the seed ISO)</Description>
        </SynchronousCommand>
      </FirstLogonCommands>
    </component>
  </settings>
</unattend>
"""

# the hardened profile's measured capability floor (the compose template's
# list) minus NET_ADMIN, which only the bridge/nft work needs and the installer
# has none of (`--network none`, a networkless domain); of the device nodes,
# /dev/kvm and /dev/vhost-vsock are granted — the install VM carries a live
# vsock device so `install-daemon.ps1` can verify the viosock driver BINDS
_INSTALLER_CAPS = (
    "CHOWN",
    "DAC_OVERRIDE",
    "FOWNER",
    "SETUID",
    "SETGID",
    "SETPCAP",
    "KILL",
)


def install_windows_golden(
    iso: Path,
    iso_sha256: str,
    virtio_iso: Path,
    virtio_sha256: str,
    cache: Path,
    name: str = "windows-2022",
    admin_password: str = DEFAULT_ADMIN_PASSWORD,
    artifact_dir: Path | None = None,
    daemon_sha256: str | None = None,
    timeout_s: float = INSTALL_TIMEOUT_S,
) -> tuple[ImageMetadata, bool]:
    """Install a sysprep'd Windows golden into the cache from digest-pinned media.

    Both ISOs are verified before anything runs; both are copied into the cache when absent or stale against their pins (the install ISO is the golden's recorded vendor, so chain verification works like any derive). The install runs in a one-shot hardened range container with `--network none` and only the KVM and vhost-vsock device nodes; the finalized disk is compacted (`qemu-img convert`) and landed atomically with its metadata, sidecar first.

    Returns:
        The golden's metadata and whether the cache already satisfied the request (same key discipline as `derive_golden`: recipe version, both ISO digests, the daemon bundle digest).

    Raises:
        DeriveError: Stage-named failure (media missing/mismatched, daemon pin mismatch, container or install failure, timeout); nothing is left behind in the cache.
    """
    expected_iso = iso_sha256.removeprefix("sha256:").lower()
    expected_virtio = virtio_sha256.removeprefix("sha256:").lower()
    for path, expected, label in (
        (iso, expected_iso, "install ISO"),
        (virtio_iso, expected_virtio, "virtio-win ISO"),
    ):
        if not path.is_file():
            raise DeriveError("verify-media", f"{label} not found: {path}")
        actual = sha256_file(path)
        if actual != expected:
            raise DeriveError(
                "verify-media",
                f"{label} digest mismatch for {path.name}: expected {expected}, found {actual}",
            )

    bundle_path, daemon_info = resolve_daemon_bundle(
        artifact_dir if artifact_dir is not None else DEFAULT_ARTIFACT_DIR,
        expected_sha256=daemon_sha256,
    )

    file = _cache_file_name(name)
    key_material = (
        f"recipe:{WIN_RECIPE_VERSION}|iso:{expected_iso}|virtio:{expected_virtio}"
        f"|daemon:{daemon_info.bundle_sha256}|admin:{hashlib.sha256(admin_password.encode()).hexdigest()}"
    )
    key = hashlib.sha256(key_material.encode()).hexdigest()

    cache.mkdir(parents=True, exist_ok=True)
    golden_path = cache / file
    metadata_path = _metadata_path(cache, file)

    from .._dist.gc import chains_lock

    with chains_lock(cache, exclusive=False), _name_lock(cache, file):
        # a crashed prior install of this name may have left temps; we hold the lock
        temp_golden = cache / f".{file}.deriving"
        metadata_temp = metadata_path.with_suffix(".json.deriving")
        temp_golden.unlink(missing_ok=True)
        metadata_temp.unlink(missing_ok=True)

        if metadata_path.is_file():
            existing = _load_metadata(metadata_path)
            if existing is None:
                # non-conforming sidecar: unmanaged, exactly as `images list` reports it
                raise DeriveError(
                    "prepare",
                    f"{metadata_path} is not a valid provenance sidecar (unmanaged); refusing to touch it, remove it to re-install",
                )
            if (
                existing.derivation_key == key
                and golden_path.is_file()
                and sha256_file(golden_path) == existing.golden_sha256
            ):
                return existing, True
        elif golden_path.exists():
            raise DeriveError(
                "prepare",
                f"{golden_path} exists without metadata (unmanaged); refusing to overwrite",
            )

        try:
            _install_locked(
                iso,
                expected_iso,
                virtio_iso,
                expected_virtio,
                cache,
                bundle_path,
                admin_password,
                temp_golden,
                timeout_s,
            )
            metadata = ImageMetadata(
                name=name,
                file=file,
                recipe_version=WIN_RECIPE_VERSION,
                derivation_key=key,
                vendor_file=iso.name,
                vendor_sha256=expected_iso,
                daemon=DaemonPin(
                    name=daemon_info.name,
                    version=daemon_info.version,
                    sha256=daemon_info.bundle_sha256,
                ),
                golden_sha256=sha256_file(temp_golden),
                created=now_iso(),
                admin_password=admin_password,
            )
            # sidecar lands first (derive_golden's crash ordering): metadata
            # pointing at a missing golden repairs on the next install; a
            # provenance-less golden would refuse as unmanaged forever.
            # 0600: the sidecar carries the admin password PLAINTEXT (the one
            # place it rests outside the image), and the cache dir is
            # user-relocatable (phase review round 1, password journey)
            metadata_temp.touch(mode=0o600)
            metadata_temp.chmod(0o600)  # touch mode is umask-masked; pin it
            metadata_temp.write_text(metadata.model_dump_json(indent=2) + "\n")
            metadata_temp.replace(metadata_path)
            temp_golden.replace(golden_path)
            return metadata, False
        finally:
            temp_golden.unlink(missing_ok=True)
            metadata_temp.unlink(missing_ok=True)


_INSTALLER_ENTRYPOINT = """\
set -euo pipefail
chown root:kvm /dev/kvm /dev/vhost-vsock
chmod 660 /dev/kvm /dev/vhost-vsock
mkdir -p /run/libvirt
/usr/sbin/virtlogd -d
/usr/sbin/libvirtd -d
until virsh -c qemu:///system version >/dev/null 2>&1; do sleep 0.2; done
touch /run/range-ready
exec sleep infinity
"""
"""The installer's entrypoint: the range image's own startup minus everything bundle-shaped (no bridges, no nft — the install VM has no network and no control plane; the answer file drives it). Vsock stays: the install VM carries a live vsock device so the daemon's install-time bind check passes."""


def _install_locked(
    iso: Path,
    expected_iso: str,
    virtio_iso: Path,
    expected_virtio: str,
    cache: Path,
    bundle_path: Path,
    admin_password: str,
    temp_golden: Path,
    timeout_s: float,
) -> None:
    # media is cache-resident so the chain verifies and the container sees it;
    # an in-cache copy only counts when it still matches the pin (derive_golden's
    # rule: the cache is local working state, not a signed artifact)
    for source, expected in ((iso, expected_iso), (virtio_iso, expected_virtio)):
        target = cache / source.name
        if target.resolve() == source.resolve():
            continue
        if target.is_file() and sha256_file(target) == expected:
            continue
        # atomic and pid-suffixed: a kill mid-copy must never leave a partial
        # ISO, and concurrent installs of different names share no lock
        temp = cache / f".{source.name}.{os.getpid()}.deriving"
        try:
            shutil.copy2(source, temp)
            temp.replace(target)
        finally:
            temp.unlink(missing_ok=True)

    container = f"ir-win-derive-{secrets.token_hex(4)}"
    scratch = Path(tempfile.mkdtemp(prefix="ir-win-derive-"))
    try:
        _build_payload(scratch, bundle_path, admin_password)
        run_args = [
            "docker",
            "run",
            "-d",
            "--rm",
            "--name",
            container,
            "--network",
            "none",
            "--init",
            "--cap-drop",
            "ALL",
            *[f"--cap-add={cap}" for cap in _INSTALLER_CAPS],
            "--security-opt",
            "no-new-privileges:true",
            "--device",
            "/dev/kvm",
            "--device",
            "/dev/vhost-vsock",
            "-v",
            f"{cache}:/images:ro",
            "-v",
            f"{scratch}:/scratch",
            "--entrypoint",
            "/bin/bash",
            ensure_range_image(),
            "-c",
            _INSTALLER_ENTRYPOINT,
        ]
        # INSTALL_CID is host-global (vhost-vsock): one install at a time per host
        with open(
            Path(tempfile.gettempdir()) / "inspect-ranges-win-install.lock", "w"
        ) as install_lock:
            fcntl.flock(install_lock, fcntl.LOCK_EX)
            _run("installer-container", run_args)
            try:
                _wait_container_ready(container, 60.0)
                # the hardened image runs qemu as libvirt-qemu with dynamic
                # ownership off: the VMM must traverse the scratch mount
                # (group-execute only — the answer file and seed ISOs carry the
                # Administrator password and must never be other-readable on a
                # multi-user host) and own the files it opens
                _exec(container, "chgrp kvm /scratch && chmod 710 /scratch")
                _exec(
                    container,
                    "genisoimage -quiet -o /scratch/unattend.iso -J -R /scratch/answer/autounattend.xml",
                )
                _exec(
                    container,
                    "genisoimage -quiet -o /scratch/payload.iso -J -R /scratch/payload",
                )
                _exec(
                    container,
                    f"qemu-img create -f qcow2 /scratch/golden.qcow2 {DISK_GB}G",
                )
                _exec(
                    container,
                    "chown libvirt-qemu:kvm /scratch/golden.qcow2 "
                    "/scratch/unattend.iso /scratch/payload.iso && "
                    "chmod 640 /scratch/golden.qcow2 "
                    "/scratch/unattend.iso /scratch/payload.iso",
                )
                _exec(
                    container,
                    "virt-install --connect qemu:///system --name wininstall "
                    "--memory 4096 --vcpus 4 --cpu host-passthrough "
                    "--disk path=/scratch/golden.qcow2,format=qcow2,bus=virtio "
                    f"--disk path=/images/{shlex.quote(iso.name)},device=cdrom,readonly=on "
                    f"--disk path=/images/{shlex.quote(virtio_iso.name)},device=cdrom,readonly=on "
                    "--disk path=/scratch/unattend.iso,device=cdrom,readonly=on "
                    "--disk path=/scratch/payload.iso,device=cdrom,readonly=on "
                    "--network none --boot hd,cdrom --graphics vnc,listen=127.0.0.1 "
                    f"--vsock cid.address={INSTALL_CID} "
                    "--osinfo win2k22 --import --noautoconsole",
                )
                deadline = time.monotonic() + timeout_s
                while time.monotonic() < deadline:
                    state = _exec(
                        container, "virsh -c qemu:///system domstate wininstall"
                    )
                    if state.strip() == "shut off":
                        break
                    time.sleep(15)
                else:
                    # the container is gone once we raise: capture what it knew
                    diagnostics = subprocess.run(
                        [
                            "docker",
                            "exec",
                            container,
                            "sh",
                            "-c",
                            "virsh -c qemu:///system domstate wininstall; "
                            "tail -c 2000 /var/log/libvirt/qemu/wininstall.log 2>/dev/null",
                        ],
                        capture_output=True,
                        text=True,
                    ).stdout
                    raise DeriveError(
                        "install",
                        f"the unattended install did not finish within {timeout_s:.0f} s; "
                        f"last domain state and VMM log:\n{diagnostics[-2000:]}",
                    )
                # compact in-container (root reads the libvirt-qemu-owned disk;
                # the host user cannot, by design) and hand the result back
                # other-readable like any cache golden — the password lives
                # inside the image either way
                _exec(
                    container,
                    "qemu-img convert -O qcow2 /scratch/golden.qcow2 "
                    "/scratch/golden-compact.qcow2 && "
                    "chmod 644 /scratch/golden-compact.qcow2",
                )
            finally:
                subprocess.run(
                    ["docker", "rm", "-f", container], capture_output=True, text=True
                )
        shutil.move(str(scratch / "golden-compact.qcow2"), str(temp_golden))
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def _build_payload(scratch: Path, bundle_path: Path, admin_password: str) -> None:
    """The answer file and the daemon payload (the bundle tar's `windows/` members) for the installer's seed ISOs."""
    answer = scratch / "answer"
    payload = scratch / "payload"
    answer.mkdir()
    payload.mkdir()
    answer_file = answer / "autounattend.xml"
    # XML-escaped: the password is the one caller value the template cannot
    # constrain, and an unescaped `<&>` would break Setup's XML parse (the
    # install then burns the whole timeout). Owner-only: it is plaintext
    # scenario credentials and the container's genisoimage reads it as root.
    answer_file.write_text(
        _INSTALL_UNATTEND.replace("__ADMIN_PASSWORD__", escape(admin_password))
    )
    answer_file.chmod(0o600)
    with tarfile.open(bundle_path) as tar:
        for member in tar.getmembers():
            if member.name.startswith("windows/") and member.isfile():
                data = tar.extractfile(member)
                assert data is not None
                (payload / Path(member.name).name).write_bytes(data.read())
    if not (payload / "install-daemon.ps1").is_file():
        raise DeriveError(
            "payload",
            f"the daemon bundle {bundle_path.name} carries no windows/install-daemon.ps1",
        )


def _run(stage: str, argv: list[str]) -> str:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, check=True)
    except FileNotFoundError as error:
        raise DeriveError(stage, f"{argv[0]} not found on this host") from error
    except subprocess.CalledProcessError as error:
        raise DeriveError(stage, f"{argv[0]} failed: {error.stderr[-400:]}") from error
    return result.stdout


def _exec(container: str, command: str) -> str:
    return _run("install", ["docker", "exec", container, "sh", "-c", command])


def _wait_container_ready(container: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        result = subprocess.run(
            ["docker", "exec", container, "test", "-e", "/run/range-ready"],
            capture_output=True,
        )
        if result.returncode == 0:
            return
        time.sleep(2)
    raise DeriveError(
        "installer-container", "the installer container never became ready"
    )
