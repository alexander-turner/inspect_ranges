"""The hub repo-name-prefix probe, run once and recorded (the s3-pull discipline).

The prefixed hub form (`docker.io/<org>/<prefix>`, user decision 2026-10-19) spells name `test` as the repo `meridianlabsai/ir-dist-test` — exactly the standing private test repo, so the mapping proves live with the already-logged-in scoped token and zero new repos. A real tiny qcow2 chain publishes as the bare name `test` through `push_image_artifact` (no catalog write: nothing may auto-create `ir-dist-catalog` on the org) and pulls back into a fresh cache byte-identically through the production token flow.

Run: `uv run python design/spikes/dist-hub/prefix_probe.py` (hub login required).
"""

import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path

from inspect_ranges._dist import parse_location
from inspect_ranges._dist.resolve import pull_image, push_image_artifact
from inspect_ranges._build.manifest import now_iso
from inspect_ranges._runtime.images import DaemonPin, ImageMetadata

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


def main() -> int:
    location = parse_location("docker.io/meridianlabsai/ir-dist")
    store = location.store_for("test")
    check(
        getattr(store, "repo", None) == "meridianlabsai/ir-dist-test",
        f"the prefixed location spells name 'test' as the standing test repo "
        f"(got {getattr(store, 'repo', None)!r})",
    )
    with tempfile.TemporaryDirectory(prefix="ir-prefix-probe-") as temp:
        cache = Path(temp) / "images"
        cache.mkdir()
        run = lambda *argv: subprocess.run(list(argv), check=True, capture_output=True)  # noqa: E731
        run("qemu-img", "create", "-f", "raw", str(cache / "test-vendor.img"), "1M")
        run(
            "qemu-img",
            "create",
            "-f",
            "qcow2",
            "-b",
            "test-vendor.img",
            "-F",
            "raw",
            str(cache / "test.qcow2"),
            "4M",
        )
        (cache / "test.json").write_text(
            ImageMetadata(
                name="test",
                file="test.qcow2",
                recipe_version="4",
                derivation_key="k" * 64,
                vendor_file="test-vendor.img",
                vendor_sha256=sha(cache / "test-vendor.img"),
                daemon=DaemonPin(name="vsockd", version="3.1.0", sha256="d" * 64),
                golden_sha256=sha(cache / "test.qcow2"),
                created=now_iso(),
            ).model_dump_json()
        )
        golden_sha = sha(cache / "test.qcow2")
        root = push_image_artifact("test", location, image_cache=cache)
        check(bool(root.digest), f"push landed the chain root ({root.digest[:19]}...)")
        consumer = Path(temp) / "consumer"
        consumer.mkdir()
        pulled = pull_image("test", [location], image_cache=consumer)
        check(pulled is not None, "pull by bare name through the prefixed location")
        check(
            (consumer / "test.qcow2").is_file()
            and sha(consumer / "test.qcow2") == golden_sha,
            "the pulled golden is byte-identical",
        )
        check(
            (consumer / "test-vendor.img").is_file(),
            "the vendor base travelled with the chain",
        )
    failed = sum(1 for ok, _ in CHECKS if not ok)
    print(f"\n{len(CHECKS) - failed} passed, {failed} failed (prefix probe)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
