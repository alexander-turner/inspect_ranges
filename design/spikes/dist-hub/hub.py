"""The hub conformance spike: the production path against the real Docker Hub, run once and recorded (the s3-pull discipline).

A tiny REAL qcow2 chain (qemu-img created, so backing validation runs for real) publishes as the range `ir-dist-test` to `docker.io/meridianlabsai` (the private test repo), pulls back into fresh caches through the hub's actual token flow and blob-storage redirects, verifies byte-identically, refuses anonymously, and records the hub's rate-limit headers for the fleet guidance.
"""

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from inspect_ranges._build.manifest import (
    BuildManifest,
    GuestRecord,
    VerificationRecord,
    load_manifest,
    now_iso,
    save_manifest,
)
from inspect_ranges._compiler.plan import spec_sha256
from inspect_ranges._dist import DistError, parse_location, pull_pinned, push_range
from inspect_ranges._dist.resolve import pull_range
from inspect_ranges._runtime.images import DaemonPin, ImageMetadata
from inspect_ranges.schema import load_range

CHECKS: list[tuple[bool, str]] = []


def check(ok: bool, label: str) -> None:
    CHECKS.append((ok, label))
    print(f"{'PASS ' if ok else 'FAIL '} {label}", flush=True)


def sha(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


SPEC_YAML = """
range:
  name: ir-dist-test
  schema_version: "0.3"
  description: hub conformance fixture (private test repo; never canonical)
networks:
  - name: lab
    cidr: 10.96.0.0/24
    mode: isolated
hosts:
  - name: web
    os: { type: linux }
    image: hub-golden
    interfaces: [{ network: lab, ip: 10.96.0.10 }]
    services:
      - name: probe
        port: 80
attacker:
  image: hub-golden
  interfaces: [{ network: lab }]
  entry: external
"""


def build_fixture(root: Path) -> tuple[Path, Path, object]:
    """A real tiny qcow2 chain + manifest: vendor (raw) <- golden (qcow2) <- realized (qcow2)."""
    cache = root / "images"
    builds = root / "builds"
    cache.mkdir(parents=True)
    run = lambda *argv: subprocess.run(list(argv), check=True, capture_output=True)  # noqa: E731
    run("qemu-img", "create", "-f", "raw", str(cache / "hub-vendor.img"), "1M")
    run(
        "qemu-img", "create", "-f", "qcow2",
        "-b", "hub-vendor.img", "-F", "raw",
        str(cache / "hub-golden.qcow2"), "4M",
    )
    (cache / "hub-golden.json").write_text(
        ImageMetadata(
            name="hub-golden",
            file="hub-golden.qcow2",
            recipe_version="4",
            derivation_key="k" * 64,
            vendor_file="hub-vendor.img",
            vendor_sha256=sha(cache / "hub-vendor.img"),
            daemon=DaemonPin(name="vsockd", version="3.1.0", sha256="d" * 64),
            golden_sha256=sha(cache / "hub-golden.qcow2"),
            created=now_iso(),
        ).model_dump_json()
    )
    realized = "ir-dist-test-web-" + "b" * 12 + ".qcow2"
    run(
        "qemu-img", "create", "-f", "qcow2",
        "-b", "hub-golden.qcow2", "-F", "qcow2",
        str(cache / realized), "4M",
    )
    (cache / (realized.removesuffix(".qcow2") + ".realized.json")).write_text(
        json.dumps(
            {
                "type": "realized",
                "range_name": "ir-dist-test",
                "guest": "web",
                "build_key": "b" * 64,
                "golden_file": "hub-golden.qcow2",
                "sha256": sha(cache / realized),
                "created": now_iso(),
            }
        )
    )
    spec_path = root / "range.yaml"
    spec_path.write_text(SPEC_YAML)
    spec = load_range(spec_path)
    manifest = BuildManifest(
        range_name="ir-dist-test",
        schema_version="0.3",
        spec_sha256=spec_sha256(spec),
        built_at=now_iso(),
        guests=(
            GuestRecord(
                name="web",
                golden_reference="hub-golden",
                golden_digest=f"sha256:{sha(cache / 'hub-golden.qcow2')}",
                realized_file=realized,
                realized_sha256=sha(cache / realized),
                build_key="b" * 64,
                recipes=(),
            ),
        ),
        verification=VerificationRecord(verified_at=now_iso(), declarations=()),
    )
    save_manifest(manifest, builds)
    return cache, builds, spec


def rate_limit_probe() -> str:
    request = urllib.request.Request(
        "https://registry-1.docker.io/v2/library/registry/manifests/2",
        method="HEAD",
        headers={"Accept": "application/vnd.docker.distribution.manifest.v2+json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            headers = dict(response.headers)
    except urllib.error.HTTPError as error:
        if error.code == 401:
            # fetch an anonymous token and retry: this IS the anonymous path
            challenge = error.headers.get("WWW-Authenticate", "")
            import re as re_module

            params = dict(
                re_module.findall(r'(\w+)="([^"]*)"', challenge.removeprefix("Bearer "))
            )
            with urllib.request.urlopen(
                f"{params['realm']}?service={params['service']}&scope=repository:library/registry:pull",
                timeout=30,
            ) as token_response:
                token = json.loads(token_response.read())["token"]
            request.add_header("Authorization", f"Bearer {token}")
            with urllib.request.urlopen(request, timeout=30) as response:
                headers = dict(response.headers)
        else:
            raise
    return "; ".join(
        f"{key}: {value}"
        for key, value in headers.items()
        if key.lower().startswith("ratelimit")
    ) or "no ratelimit headers (authenticated or unlimited path)"


def main() -> int:
    root = Path(tempfile.mkdtemp(prefix="dist-hub-"))
    try:
        cache, builds, spec = build_fixture(root)
        hub = parse_location("docker.io/meridianlabsai")
        manifest = load_manifest(builds, "ir-dist-test")
        assert manifest is not None

        root_descriptor = push_range(
            manifest, hub, image_cache=cache, build_cache=builds
        )
        check(
            root_descriptor.digest.startswith("sha256:"),
            f"H1 push to the hub over the production token flow (root {root_descriptor.digest[:19]}...)",
        )

        pulled = root / "pulled"
        for sub in ("images", "builds", "recipes"):
            (pulled / sub).mkdir(parents=True)
        report = pull_range(
            spec,  # type: ignore[arg-type]
            [hub],
            image_cache=pulled / "images",
            build_cache=pulled / "builds",
            recipe_cache=pulled / "recipes",
        )
        check(
            report.root == root_descriptor.digest,
            "H2 spec-driven pull resolved the hub's spec ref to the pushed root",
        )
        identical = all(
            sha(pulled / "images" / f.name) == sha(f)
            for f in cache.glob("*.qcow2")
        ) and (pulled / "builds" / "ir-dist-test" / "manifest.json").read_bytes() == (
            builds / "ir-dist-test" / "manifest.json"
        ).read_bytes()
        check(
            identical,
            "H3 pulled bytes identical through the hub's blob-storage redirects (real qemu-img chain validation ran)",
        )

        pin_side = root / "pin"
        for sub in ("images", "builds", "recipes"):
            (pin_side / sub).mkdir(parents=True)
        pin_report = pull_pinned(
            "ir-dist-test",
            root_descriptor.digest,
            [hub],
            image_cache=pin_side / "images",
            build_cache=pin_side / "builds",
            recipe_cache=pin_side / "recipes",
        )
        check(
            pin_report.root == root_descriptor.digest,
            "H4 the name@sha256 pin form works against the hub",
        )

        # anonymity: strip the credential and the private repo must deny
        anonymous_config = root / "anon-docker.json"
        anonymous_config.write_text("{}")
        from inspect_ranges._dist.registry import RegistryRepo

        anonymous = RegistryRepo(
            "https://registry-1.docker.io",
            "meridianlabsai/ir-dist-test",
            docker_config=anonymous_config,
        )
        try:
            anonymous.ref("latest")
            check(False, "H5 anonymous access to the private repo was ALLOWED")
        except DistError as error:
            check(
                error.code in ("registry-denied", "ref-not-found"),
                f"H5 anonymous access denies cleanly ({error.code})",
            )

        print(f"MEASURED  anonymous pull rate limits: {rate_limit_probe()}")
        failed = sum(1 for ok, _ in CHECKS if not ok)
        print(f"\n{len(CHECKS) - failed} passed, {failed} failed (hub conformance)")
        return 1 if failed else 0
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
