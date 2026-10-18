"""The OCI layout and blob-store contract: content addressing, atomic writes, verified reads, and the named refusals (no network, no artifacts)."""

import hashlib
import json
from pathlib import Path

import pytest
from inspect_ranges._dist import Descriptor, DistError, OciLayout, OciManifest
from inspect_ranges._dist.oci import MEDIA_TYPE_MANIFEST, blob_sha256


def layout(tmp_path: Path) -> OciLayout:
    return OciLayout(tmp_path / "layout").ensure()


def test_layout_skeleton_and_reopen(tmp_path: Path) -> None:
    created = layout(tmp_path)
    assert (created.root / "oci-layout").is_file()
    assert (created.root / "blobs" / "sha256").is_dir()
    reopened = OciLayout(created.root).open()
    assert reopened.index().manifests == []


def test_open_refuses_non_layouts(tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    with pytest.raises(DistError, match="layout-invalid"):
        OciLayout(plain).open()
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "oci-layout").write_text(json.dumps({"imageLayoutVersion": "2.0.0"}))
    with pytest.raises(DistError, match="layout-invalid"):
        OciLayout(bad).open()


def test_blob_round_trip_is_content_addressed(tmp_path: Path) -> None:
    store = layout(tmp_path)
    data = b"artifact bytes"
    digest = store.put_blob_bytes(data)
    assert digest == "sha256:" + hashlib.sha256(data).hexdigest()
    descriptor = Descriptor(
        media_type="application/octet-stream", digest=digest, size=len(data)
    )
    assert store.read_blob(descriptor) == data
    # idempotent: a second put of the same content is the same blob
    assert store.put_blob_bytes(data) == digest


def test_file_blob_verify_while_copy(tmp_path: Path) -> None:
    store = layout(tmp_path)
    source = tmp_path / "image.qcow2"
    source.write_bytes(b"q" * 4096)
    digest = store.put_blob_file(source)
    assert digest == blob_sha256(source)
    with pytest.raises(DistError, match="blob-digest-mismatch"):
        store.put_blob_file(source, expected="sha256:" + "0" * 64)
    # the failed put left nothing addressable and no temp debris
    assert not store.blob_path("sha256:" + "0" * 64).exists()
    assert not list(store.root.rglob(".incoming-*"))


def test_read_refuses_tampered_blob(tmp_path: Path) -> None:
    store = layout(tmp_path)
    digest = store.put_blob_bytes(b"original")
    store.blob_path(digest).write_bytes(b"tampered!")
    descriptor = Descriptor(
        media_type="application/octet-stream", digest=digest, size=9
    )
    with pytest.raises(DistError, match="blob-digest-mismatch"):
        store.read_blob(descriptor)


def test_copy_blob_to_verifies_and_lands_atomically(tmp_path: Path) -> None:
    store = layout(tmp_path)
    source = tmp_path / "big.bin"
    source.write_bytes(b"x" * 10_000)
    digest = store.put_blob_file(source)
    descriptor = Descriptor(
        media_type="application/octet-stream", digest=digest, size=10_000
    )
    out = tmp_path / "cache" / "big.bin"
    store.copy_blob_to(descriptor, out)
    assert out.read_bytes() == b"x" * 10_000
    store.blob_path(digest).write_bytes(b"x" * 9_999 + b"y")
    with pytest.raises(DistError, match="blob-digest-mismatch"):
        store.copy_blob_to(descriptor, tmp_path / "cache" / "other.bin")
    assert not (tmp_path / "cache" / "other.bin").exists()


def test_manifest_round_trip_and_index_refs(tmp_path: Path) -> None:
    store = layout(tmp_path)
    config = store.ensure_empty_config()
    data_digest = store.put_blob_bytes(b"layer bytes")
    manifest = OciManifest(
        artifact_type="application/vnd.inspect-ranges.test.v1",
        config=config,
        layers=[
            Descriptor(
                media_type="application/octet-stream",
                digest=data_digest,
                size=len(b"layer bytes"),
            )
        ],
        annotations={"org.inspect-ranges.test": "yes"},
    )
    descriptor = store.put_manifest(manifest)
    store.set_ref("test-artifact", descriptor)
    resolved = store.ref("test-artifact")
    assert resolved.digest == descriptor.digest
    parsed = store.manifest(resolved)
    assert parsed.artifact_type == "application/vnd.inspect-ranges.test.v1"
    assert parsed.layers[0].digest == data_digest
    # the serialized form uses OCI's camelCase keys
    raw = json.loads(store.read_blob(resolved))
    assert raw["mediaType"] == MEDIA_TYPE_MANIFEST
    assert raw["schemaVersion"] == 2
    assert raw["artifactType"] == "application/vnd.inspect-ranges.test.v1"
    # replacing a ref keeps one entry per name
    store.set_ref("test-artifact", descriptor)
    names = [
        (entry.annotations or {}).get("org.opencontainers.image.ref.name")
        for entry in store.index().manifests
    ]
    assert names == ["test-artifact"]
    with pytest.raises(DistError, match="ref-not-found"):
        store.ref("absent")


def test_manifest_blob_must_parse(tmp_path: Path) -> None:
    store = layout(tmp_path)
    digest = store.put_blob_bytes(b"not json at all")
    descriptor = Descriptor(media_type=MEDIA_TYPE_MANIFEST, digest=digest, size=15)
    with pytest.raises(DistError, match="manifest-invalid"):
        store.manifest(descriptor)


def test_digest_grammar_is_enforced(tmp_path: Path) -> None:
    store = layout(tmp_path)
    with pytest.raises(DistError, match="unsupported-digest"):
        store.blob_path("md5:abcd")
    with pytest.raises(DistError, match="unsupported-digest"):
        Descriptor(
            media_type="application/octet-stream", digest="sha512:" + "a" * 128, size=1
        ).require_sha256()
