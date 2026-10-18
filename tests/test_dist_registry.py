"""The registry client against an in-process v2 server (a real HTTP server, not a mock: the client's full request path runs), including the bearer-token flow and transfer dedup."""

import base64
import hashlib
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, ClassVar

import pytest
from inspect_ranges._dist import DistError, OciLayout, materialize_closure, push_build
from inspect_ranges._dist.oci import Descriptor, OciManifest
from inspect_ranges._dist.registry import RegistryRepo, docker_auth_for
from inspect_ranges._dist.transfer import copy_closure

from tests.test_dist_encode import Fixture, fresh_dirs


@pytest.fixture(autouse=True)
def fake_backing_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    """Same fake as test_dist_encode: synthetic blobs are not qcow2s; the battery proves the real probe."""

    def probe(path: Path) -> str | None:
        if path.name.startswith("distfix-web-"):
            return "focal-guest.qcow2"
        return {"focal-guest.qcow2": "noble.img"}.get(path.name)

    monkeypatch.setattr("inspect_ranges._dist.materialize._qcow2_backing_name", probe)
    monkeypatch.setattr("inspect_ranges._dist.encode.qcow2_backing_name", probe)


class FakeRegistryState:
    """One registry's content: blobs and manifests by reference, plus auth and behavior knobs."""

    def __init__(self, *, require_token: bool = False) -> None:
        self.blobs: dict[str, bytes] = {}
        self.manifests: dict[str, tuple[bytes, str]] = {}
        self.require_token = require_token
        self.token = "fake-token-abc"
        self.seen_basic: list[str] = []
        self.uploads = 0
        self.auth_seen: list[str | None] = []
        self.redirect_blobs_to: str | None = None
        self.put_401_budget = 0
        self.tokens_issued = 0


class _Handler(BaseHTTPRequestHandler):
    state: ClassVar[FakeRegistryState]

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def _authorized(self) -> bool:
        if not self.state.require_token:
            return True
        if self.path.startswith("/token"):
            return True
        return self.headers.get("Authorization") == f"Bearer {self.state.token}"

    def _challenge(self) -> None:
        self.send_response(401)
        host = self.headers.get("Host", "127.0.0.1")
        self.send_header(
            "WWW-Authenticate",
            f'Bearer realm="http://{host}/token",service="fake-registry"',
        )
        self.end_headers()
        self.wfile.write(b"{}")

    def _send(self, status: int, body: bytes = b"", **headers: str) -> None:
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key.replace("_", "-"), value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self) -> None:
        self.state.auth_seen.append(self.headers.get("Authorization"))
        if self.path.startswith("/token"):
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Basic "):
                self.state.seen_basic.append(auth.removeprefix("Basic "))
            self.state.tokens_issued += 1
            self._send(200, json.dumps({"token": self.state.token}).encode())
            return
        if not self._authorized():
            self._challenge()
            return
        parts = self.path.split("/")
        if "/blobs/" in self.path:
            if self.state.redirect_blobs_to is not None and self.command == "GET":
                self._send(
                    307,
                    Location=f"{self.state.redirect_blobs_to}{self.path}",
                )
                return
            blob = self.state.blobs.get(parts[-1])
            if blob is None:
                self._send(404)
            else:
                self._send(200, blob)
            return
        if "/manifests/" in self.path:
            entry = self.state.manifests.get(urllib.parse.unquote(parts[-1]))
            if entry is None:
                self._send(404)
            else:
                self._send(200, entry[0], Content_Type=entry[1])
            return
        self._send(200, b"{}")

    do_HEAD = do_GET

    def do_POST(self) -> None:
        if not self._authorized():
            self._challenge()
            return
        if self.path.endswith("/blobs/uploads/"):
            self.state.uploads += 1
            repo = self.path.split("/v2/")[1].removesuffix("/blobs/uploads/")
            self._send(202, Location=f"/v2/{repo}/blobs/uploads/session-1")
            return
        self._send(404)

    def do_PUT(self) -> None:
        if not self._authorized():
            self._challenge()
            return
        if self.state.put_401_budget > 0:
            # simulate a token expiring between upload start and the PUT
            self.state.put_401_budget -= 1
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            self._challenge()
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        if "/blobs/uploads/" in self.path:
            query = urllib.parse.urlparse(self.path).query
            digest = urllib.parse.parse_qs(query)["digest"][0]
            actual = f"sha256:{hashlib.sha256(body).hexdigest()}"
            if actual != digest:
                self._send(400)
                return
            self.state.blobs[digest] = body
            self._send(201, Docker_Content_Digest=digest)
            return
        if "/manifests/" in self.path:
            reference = urllib.parse.unquote(self.path.split("/manifests/")[1])
            media = self.headers.get("Content-Type", "")
            digest = f"sha256:{hashlib.sha256(body).hexdigest()}"
            self.state.manifests[reference] = (body, media)
            self.state.manifests[digest] = (body, media)
            self._send(201, Docker_Content_Digest=digest)
            return
        self._send(404)


@pytest.fixture()
def fake_registry() -> "Any":
    """A live threaded v2 server; yields (base_url, state)."""

    def start(require_token: bool = False) -> tuple[str, FakeRegistryState, Any]:
        state = FakeRegistryState(require_token=require_token)
        handler = type("Handler", (_Handler,), {"state": state})
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return f"http://127.0.0.1:{server.server_port}", state, server

    servers: list[Any] = []

    def factory(require_token: bool = False) -> tuple[str, FakeRegistryState]:
        url, state, server = start(require_token)
        servers.append(server)
        return url, state

    yield factory
    for server in servers:
        server.shutdown()


def test_registry_round_trip(tmp_path: Path, fake_registry: Any) -> None:
    """push_build into a registry repo, materialize back into fresh caches: the same closure logic over the HTTP store."""
    url, state = fake_registry()
    fixture = Fixture(tmp_path)
    repo = RegistryRepo(url, "ranges/distfix")
    root = push_build(
        fixture.manifest,
        repo,
        image_cache=fixture.image_cache,
        build_cache=fixture.build_cache,
        range_dir=fixture.range_dir,
    )
    assert root.digest.startswith("sha256:")
    assert repo.ref("distfix").digest == root.digest
    images, builds, recipes = fresh_dirs(tmp_path)
    result = materialize_closure(
        repo,
        root,
        image_cache=images,
        build_cache=builds,
        recipe_cache=recipes,
    )
    assert (builds / "distfix" / "manifest.json").is_file()
    assert len(result.fetched) > 0
    uploads_after_first = state.uploads
    # a second push uploads nothing: HEAD dedup answers for every blob
    push_build(
        fixture.manifest,
        repo,
        image_cache=fixture.image_cache,
        build_cache=fixture.build_cache,
        range_dir=fixture.range_dir,
    )
    assert state.uploads == uploads_after_first


def test_bearer_token_flow_uses_docker_config(
    tmp_path: Path, fake_registry: Any
) -> None:
    """A 401 bearer challenge is answered with a token fetched using the docker config's Basic credential, then retried."""
    url, state = fake_registry(require_token=True)
    host = url.removeprefix("http://")
    credential = base64.b64encode(b"org:secret-token").decode()
    config = tmp_path / "docker-config.json"
    config.write_text(json.dumps({"auths": {host: {"auth": credential}}}))
    repo = RegistryRepo(url, "ranges/auth-check", docker_config=config)
    digest = repo.put_blob_bytes(b"authenticated bytes")
    assert repo.has_blob(digest)
    assert credential in state.seen_basic


def test_registry_get_verifies_bytes(tmp_path: Path, fake_registry: Any) -> None:
    """A registry answering with wrong bytes refuses by digest on blob reads, streamed copies, and digest-addressed manifests."""
    url, state = fake_registry()
    repo = RegistryRepo(url, "ranges/tamper")
    digest = repo.put_blob_bytes(b"true content")
    state.blobs[digest] = b"evil content"
    descriptor = Descriptor(
        media_type="application/octet-stream", digest=digest, size=12
    )
    with pytest.raises(DistError, match="blob-digest-mismatch"):
        repo.read_blob(descriptor)
    with pytest.raises(DistError, match="blob-digest-mismatch"):
        repo.copy_blob_to(descriptor, tmp_path / "out.bin")
    assert not (tmp_path / "out.bin").exists()
    manifest = OciManifest(config=repo.ensure_empty_config(), layers=[descriptor])
    put = repo.put_manifest(manifest)
    state.manifests[put.digest] = (b'{"schemaVersion": 2, "evil": true}', "x")
    with pytest.raises(DistError, match="blob-digest-mismatch"):
        repo.manifest(put)


def test_copy_closure_layout_to_registry_and_between(
    tmp_path: Path, fake_registry: Any
) -> None:
    """The mirror engine: layout -> registry copies everything; registry -> registry dedups what the destination holds."""
    url_a, _state_a = fake_registry()
    url_b, _ = fake_registry()
    fixture = Fixture(tmp_path)
    layout, root = fixture.push(tmp_path)
    repo_a = RegistryRepo(url_a, "mirror/distfix")
    result = copy_closure(layout, repo_a, root, name="distfix")  # type: ignore[arg-type]
    assert result.copied and not result.present
    assert repo_a.ref("distfix").digest == result.root
    # second copy into the same destination: everything already present
    again = copy_closure(layout, repo_a, root, name="distfix")  # type: ignore[arg-type]
    assert not again.copied and again.present
    # cross-registry: b holds nothing, gets everything, byte-for-byte
    repo_b = RegistryRepo(url_b, "mirror/distfix")
    across = copy_closure(repo_a, repo_b, repo_a.ref("distfix"), name="distfix")
    assert across.copied and across.root == result.root
    images, builds, recipes = fresh_dirs(tmp_path)
    materialize_closure(
        repo_b,
        repo_b.ref("distfix"),
        image_cache=images,
        build_cache=builds,
        recipe_cache=recipes,
    )
    assert (builds / "distfix" / "manifest.json").read_bytes() == (
        fixture.build_cache / "distfix" / "manifest.json"
    ).read_bytes()


def test_docker_auth_for_hub_aliases(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps({"auths": {"https://index.docker.io/v1/": {"auth": "aGk="}}})
    )
    for host in ("docker.io", "registry-1.docker.io", "index.docker.io"):
        assert docker_auth_for(host, config) == "aGk="
    assert docker_auth_for("registry.example.net", config) is None
    assert docker_auth_for("docker.io", tmp_path / "absent.json") is None


def test_redirects_never_carry_the_token_off_origin(
    tmp_path: Path, fake_registry: Any
) -> None:
    """Round-2 B3: a blob GET redirected to a different origin (presigned storage) must not receive the bearer token, and the content still verifies."""
    url_storage, state_storage = fake_registry()
    url_reg, state_reg = fake_registry(require_token=True)
    host = url_reg.removeprefix("http://")
    config = tmp_path / "docker-config.json"
    config.write_text(
        json.dumps({"auths": {host: {"auth": base64.b64encode(b"o:s").decode()}}})
    )
    repo = RegistryRepo(url_reg, "ranges/redir", docker_config=config)
    data = b"redirected blob bytes"
    digest = repo.put_blob_bytes(data)
    # redirect blob GETs to the storage origin, which also holds the bytes
    state_storage.blobs[digest] = data
    state_reg.redirect_blobs_to = url_storage
    descriptor = Descriptor(
        media_type="application/octet-stream", digest=digest, size=len(data)
    )
    assert repo.read_blob(descriptor) == data
    out = tmp_path / "redir.bin"
    repo.copy_blob_to(descriptor, out)
    assert out.read_bytes() == data
    assert any(auth for auth in state_reg.auth_seen if auth), (
        "the registry origin itself saw the bearer token"
    )
    assert all(auth is None for auth in state_storage.auth_seen), (
        "the bearer token leaked to the storage origin"
    )


def test_expired_token_replays_file_uploads_and_codes_stream_uploads(
    tmp_path: Path, fake_registry: Any
) -> None:
    """Round-2 B1: a 401 on the upload PUT re-streams file-backed bodies with full bytes, and a one-shot stream refuses with a coded re-run message instead of stalling."""
    url, state = fake_registry(require_token=True)
    host = url.removeprefix("http://")
    config = tmp_path / "docker-config.json"
    config.write_text(
        json.dumps({"auths": {host: {"auth": base64.b64encode(b"o:s").decode()}}})
    )
    repo = RegistryRepo(url, "ranges/expiry", docker_config=config)
    source = tmp_path / "payload.bin"
    source.write_bytes(b"p" * 50_000)
    state.put_401_budget = 1
    digest = repo.put_blob_file(source)
    assert state.blobs[digest] == b"p" * 50_000, (
        "the retried PUT must carry the full body, not a drained stream"
    )
    # a one-shot stream under the same expiry refuses with the coded re-run
    state.put_401_budget = 1
    chunks = iter([b"q" * 10_000])
    expected = "sha256:" + hashlib.sha256(b"q" * 10_000).hexdigest()
    with pytest.raises(DistError, match="re-run the transfer"):
        repo.put_blob_stream(chunks, expected=expected, size=10_000)


def test_copy_closure_preserves_foreign_manifest_bytes(tmp_path: Path) -> None:
    """Round-2 B2: manifests move as raw verified bytes, so a foreign (pretty-printed) manifest keeps its digest across a transfer."""
    source = OciLayout(tmp_path / "source").ensure()
    blob_digest = source.put_blob_bytes(b"foreign layer")
    config_digest = source.put_blob_bytes(b"{}")
    foreign_manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.empty.v1+json",
                "digest": config_digest,
                "size": 2,
            },
            "layers": [
                {
                    "mediaType": "application/octet-stream",
                    "digest": blob_digest,
                    "size": 13,
                }
            ],
        },
        indent=2,  # NOT our canonical serialization
    ).encode()
    manifest_digest = source.put_blob_bytes(foreign_manifest)
    member = Descriptor(
        media_type="application/vnd.oci.image.manifest.v1+json",
        digest=manifest_digest,
        size=len(foreign_manifest),
    )
    foreign_index = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [member.model_dump(by_alias=True, exclude_none=True)],
        },
        indent=2,
    ).encode()
    root = Descriptor(
        media_type="application/vnd.oci.image.index.v1+json",
        digest=source.put_blob_bytes(foreign_index),
        size=len(foreign_index),
    )
    source.set_ref("foreign", root)
    destination = OciLayout(tmp_path / "dest").ensure()
    result = copy_closure(source, destination, root, name="foreign")
    assert result.root == root.digest
    landed_root = destination.ref("foreign")
    assert landed_root.digest == root.digest
    # the member digest survived: the index's reference resolves at the destination
    assert destination.manifest_bytes(member) == foreign_manifest
    assert (
        destination.read_blob(
            Descriptor(
                media_type="application/octet-stream", digest=blob_digest, size=13
            )
        )
        == b"foreign layer"
    )
