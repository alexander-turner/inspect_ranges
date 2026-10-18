"""The OCI registry client: one repository as a `ContentStore`, over the distribution v2 protocol.

Pure Python by decision (distribution-v1.md slice 2, settled by the opening probe against `registry:2` and the live hub token flow): the protocol surface this layer needs (ping, HEAD, monolithic blob upload, cross-repo mount, manifest put/get by digest and tag) is small, and owning it keeps zero external binary dependencies and full control of verification: every byte a registry returns verifies against its descriptor digest before use, exactly like the directory form.

Auth is the standard docker credential config plus the bearer-token flow: an unauthenticated registry (a local `registry:2`) works anonymously; a 401 with a `WWW-Authenticate: Bearer` challenge is answered by fetching a token from the named realm, with Basic credentials from `~/.docker/config.json` when the host has an entry. Tokens cache per scope. Credentials never appear in errors or logs.
"""

import hashlib
import json
import os
import re
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import IO, Any, cast

from .errors import DistError
from .oci import (
    DIGEST_PATTERN,
    EMPTY_BLOB,
    MEDIA_TYPE_EMPTY,
    MEDIA_TYPE_INDEX,
    MEDIA_TYPE_MANIFEST,
    Descriptor,
    OciIndex,
    OciManifest,
)

__all__ = ["RegistryRepo", "docker_auth_for"]

_CHUNK = 1 << 20
_ACCEPT_MANIFESTS = f"{MEDIA_TYPE_INDEX}, {MEDIA_TYPE_MANIFEST}"
_REPO_SEGMENT = r"[a-z0-9]+(?:[._-][a-z0-9]+)*"


def docker_auth_for(host: str, config_path: Path | None = None) -> str | None:
    """The base64 `user:secret` from the docker credential config for `host`, or `None` for anonymous.

    Docker Hub's hosts (`docker.io`, `registry-1.docker.io`, `index.docker.io`) all map to the config's legacy `https://index.docker.io/v1/` key.
    """
    path = config_path or Path.home() / ".docker" / "config.json"
    try:
        config: dict[str, Any] = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    raw_auths = config.get("auths")
    if not isinstance(raw_auths, dict):
        return None
    auths = cast("dict[str, object]", raw_auths)
    candidates = [host, f"https://{host}", f"http://{host}"]
    if host in ("docker.io", "registry-1.docker.io", "index.docker.io"):
        candidates.append("https://index.docker.io/v1/")
    for key in candidates:
        entry = auths.get(key)
        if isinstance(entry, dict):
            auth = cast("dict[str, object]", entry).get("auth")
            if isinstance(auth, str):
                return auth
    return None


class _StreamBody:
    """A file-like over a chunk iterator for streamed uploads (http.client reads it; Content-Length rides the headers)."""

    def __init__(self, chunks: Iterator[bytes]) -> None:
        self._chunks = chunks
        self._buffer = b""

    def read(self, amount: int = -1) -> bytes:
        if amount < 0:
            rest = self._buffer + b"".join(self._chunks)
            self._buffer = b""
            return rest
        while len(self._buffer) < amount:
            chunk = next(self._chunks, None)
            if chunk is None:
                break
            self._buffer += chunk
        out, self._buffer = self._buffer[:amount], self._buffer[amount:]
        return out


class RegistryRepo:
    """One registry repository as a `ContentStore` (see `oci.ContentStore` for the semantics every store holds).

    `base_url` is the registry origin (`http://127.0.0.1:5055`, `https://registry-1.docker.io`); `repo` is the repository path (`meridianlabsai/ir-dist-test`). Refs are tags; indexes and manifests ride the manifests endpoint, blobs the blobs endpoint, and a pushed index is also addressable by digest exactly like the directory form's root.
    """

    def __init__(
        self,
        base_url: str,
        repo: str,
        *,
        docker_config: Path | None = None,
    ) -> None:
        if not re.fullmatch(rf"{_REPO_SEGMENT}(?:/{_REPO_SEGMENT})*", repo):
            raise DistError(
                "registry-protocol", f"{repo!r} is not a valid repository name"
            )
        self.base_url = base_url.rstrip("/")
        self.repo = repo
        self._host = urllib.parse.urlparse(self.base_url).netloc
        self._docker_config = docker_config
        self._tokens: dict[str, str] = {}

    # -- protocol plumbing ---------------------------------------------------------

    def _url(self, suffix: str) -> str:
        return f"{self.base_url}/v2/{self.repo}/{suffix}"

    def _request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        data: "bytes | _StreamBody | None" = None,
        ok: tuple[int, ...] = (200,),
        stream: bool = False,
        _retried: bool = False,
    ) -> "tuple[int, dict[str, str], bytes | IO[bytes]]":
        request = urllib.request.Request(
            url, method=method, data=data, headers=dict(headers or {})
        )
        scope = f"repository:{self.repo}:pull,push"
        token = self._tokens.get(scope)
        if token:
            request.add_header("Authorization", f"Bearer {token}")
        try:
            response = urllib.request.urlopen(request, timeout=120)
        except urllib.error.HTTPError as error:
            if error.code == 401 and not _retried:
                challenge = error.headers.get("WWW-Authenticate", "")
                error.close()
                self._tokens[scope] = self._fetch_token(challenge, scope)
                return self._request(
                    method,
                    url,
                    headers=headers,
                    data=data,
                    ok=ok,
                    stream=stream,
                    _retried=True,
                )
            body = error.read()[:300]
            error.close()
            if error.code in ok:
                return error.code, {}, body
            raise DistError(
                "registry-denied" if error.code in (401, 403) else "registry-protocol",
                f"{method} {url} returned {error.code}: {body.decode(errors='replace')}",
            ) from None
        except (urllib.error.URLError, OSError, TimeoutError) as error:
            raise DistError(
                "registry-unreachable", f"{method} {url} failed: {error}"
            ) from error
        status = response.status
        response_headers = {k: v for k, v in response.headers.items()}
        if status not in ok:
            body = response.read()[:300]
            response.close()
            raise DistError(
                "registry-protocol",
                f"{method} {url} returned {status}: {body.decode(errors='replace')}",
            )
        if stream:
            return status, response_headers, response
        body = response.read()
        response.close()
        return status, response_headers, body

    def _fetch_token(self, challenge: str, scope: str) -> str:
        """Answer a `WWW-Authenticate: Bearer` challenge; Basic credentials ride along when the docker config has them."""
        if not challenge.startswith("Bearer "):
            raise DistError(
                "registry-denied",
                f"{self._host} denied access and offered no bearer challenge",
            )
        params = dict(re.findall(r'(\w+)="([^"]*)"', challenge.removeprefix("Bearer ")))
        realm = params.get("realm")
        if not realm:
            raise DistError(
                "registry-denied",
                f"{self._host} sent a bearer challenge without a realm",
            )
        query = {"scope": params.get("scope", scope)}
        if "service" in params:
            query["service"] = params["service"]
        request = urllib.request.Request(f"{realm}?{urllib.parse.urlencode(query)}")
        auth = docker_auth_for(self._host, self._docker_config)
        if auth:
            request.add_header("Authorization", f"Basic {auth}")
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                payload = json.loads(response.read())
        except (urllib.error.URLError, OSError, ValueError) as error:
            raise DistError(
                "registry-denied", f"token fetch from {realm} failed: {error}"
            ) from error
        token = payload.get("token") or payload.get("access_token")
        if not isinstance(token, str) or not token:
            raise DistError("registry-denied", f"{realm} returned no token")
        return token

    # -- blobs ----------------------------------------------------------------------

    def has_blob(self, digest: str) -> bool:
        if DIGEST_PATTERN.fullmatch(digest) is None:
            raise DistError("unsupported-digest", f"{digest!r} is not a sha256 digest")
        status, _, _ = self._request(
            "HEAD", self._url(f"blobs/{digest}"), ok=(200, 404)
        )
        return status == 200

    def _upload(self, body: "bytes | _StreamBody", digest: str, size: int) -> str:
        _, headers, _ = self._request("POST", self._url("blobs/uploads/"), ok=(202,))
        location = headers.get("Location")
        if not location:
            raise DistError(
                "registry-protocol", f"{self._host} started an upload with no Location"
            )
        if location.startswith("/"):
            location = f"{self.base_url}{location}"
        separator = "&" if "?" in location else "?"
        self._request(
            "PUT",
            f"{location}{separator}digest={urllib.parse.quote(digest, safe=':')}",
            data=body,
            headers={
                "Content-Type": "application/octet-stream",
                "Content-Length": str(size),
            },
            ok=(201,),
        )
        return digest

    def put_blob_bytes(self, data: bytes) -> str:
        digest = f"sha256:{hashlib.sha256(data).hexdigest()}"
        if self.has_blob(digest):
            return digest
        return self._upload(data, digest, len(data))

    def put_blob_file(self, source: Path, *, expected: str | None = None) -> str:
        digest = expected
        if digest is None:
            hasher = hashlib.sha256()
            with source.open("rb") as handle:
                for chunk in iter(lambda: handle.read(_CHUNK), b""):
                    hasher.update(chunk)
            digest = f"sha256:{hasher.hexdigest()}"
        if DIGEST_PATTERN.fullmatch(digest) is None:
            raise DistError("unsupported-digest", f"{digest!r} is not a sha256 digest")
        if self.has_blob(digest):
            return digest

        def verified_chunks() -> Iterator[bytes]:
            hasher = hashlib.sha256()
            with source.open("rb") as handle:
                for chunk in iter(lambda: handle.read(_CHUNK), b""):
                    hasher.update(chunk)
                    yield chunk
            if f"sha256:{hasher.hexdigest()}" != digest:
                raise DistError(
                    "blob-digest-mismatch",
                    f"{source} changed while uploading (expected {digest})",
                )

        return self._upload(
            _StreamBody(verified_chunks()), digest, source.stat().st_size
        )

    def put_blob_stream(
        self, chunks: Iterator[bytes], *, expected: str, size: int
    ) -> str:
        if DIGEST_PATTERN.fullmatch(expected) is None:
            raise DistError(
                "unsupported-digest", f"{expected!r} is not a sha256 digest"
            )
        if self.has_blob(expected):
            for _ in chunks:
                pass
            return expected

        def verified() -> Iterator[bytes]:
            hasher = hashlib.sha256()
            total = 0
            for chunk in chunks:
                hasher.update(chunk)
                total += len(chunk)
                yield chunk
            if f"sha256:{hasher.hexdigest()}" != expected or total != size:
                raise DistError(
                    "blob-digest-mismatch",
                    f"stream disagreed with {expected} ({size} bytes)",
                )

        return self._upload(_StreamBody(verified()), expected, size)

    def read_blob(
        self, descriptor: Descriptor, *, cap: int = 64 * 1024 * 1024
    ) -> bytes:
        digest = descriptor.require_sha256()
        if descriptor.size > cap:
            raise DistError(
                "blob-too-large",
                f"blob {digest} is {descriptor.size} bytes; in-memory reads cap at {cap}",
            )
        status, _, body = self._request(
            "GET", self._url(f"blobs/{digest}"), ok=(200, 404)
        )
        if status == 404:
            raise DistError("missing-blob", f"{self.repo} has no blob {digest}")
        assert isinstance(body, bytes)
        if len(body) > cap:
            raise DistError(
                "blob-too-large", f"blob {digest} exceeded the {cap} byte read cap"
            )
        actual = f"sha256:{hashlib.sha256(body).hexdigest()}"
        if actual != digest:
            raise DistError(
                "blob-digest-mismatch", f"blob {digest} reads back as {actual}"
            )
        return body

    def blob_chunks(self, descriptor: Descriptor) -> Iterator[bytes]:
        digest = descriptor.require_sha256()
        status, _, response = self._request(
            "GET", self._url(f"blobs/{digest}"), ok=(200, 404), stream=True
        )
        if status == 404:
            raise DistError("missing-blob", f"{self.repo} has no blob {digest}")
        assert not isinstance(response, bytes)
        try:
            yield from iter(lambda: response.read(_CHUNK), b"")
        finally:
            response.close()

    def copy_blob_to(
        self,
        descriptor: Descriptor,
        destination: Path,
        *,
        temp_prefix: str | None = None,
    ) -> None:
        digest = descriptor.require_sha256()
        destination.parent.mkdir(parents=True, exist_ok=True)
        hasher = hashlib.sha256()
        fd, temp_name = tempfile.mkstemp(
            dir=destination.parent, prefix=temp_prefix or ".incoming-"
        )
        temp = Path(temp_name)
        try:
            with os.fdopen(fd, "wb") as out:
                for chunk in self.blob_chunks(descriptor):
                    hasher.update(chunk)
                    out.write(chunk)
            actual = f"sha256:{hasher.hexdigest()}"
            if actual != digest:
                raise DistError(
                    "blob-digest-mismatch", f"blob {digest} reads back as {actual}"
                )
            temp.chmod(0o644)
            os.replace(temp, destination)
        finally:
            temp.unlink(missing_ok=True)

    # -- manifests and indexes -------------------------------------------------------

    def _put_manifest_bytes(
        self, reference: str, data: bytes, media_type: str
    ) -> Descriptor:
        self._request(
            "PUT",
            self._url(f"manifests/{reference}"),
            data=data,
            headers={"Content-Type": media_type, "Content-Length": str(len(data))},
            ok=(201,),
        )
        return Descriptor(
            media_type=media_type,
            digest=f"sha256:{hashlib.sha256(data).hexdigest()}",
            size=len(data),
        )

    def _get_manifest_bytes(self, reference: str) -> tuple[bytes, str]:
        status, headers, body = self._request(
            "GET",
            self._url(f"manifests/{reference}"),
            headers={"Accept": _ACCEPT_MANIFESTS},
            ok=(200, 404),
        )
        if status == 404:
            raise DistError(
                "ref-not-found", f"{self.repo} has no manifest {reference!r}"
            )
        assert isinstance(body, bytes)
        if reference.startswith("sha256:"):
            actual = f"sha256:{hashlib.sha256(body).hexdigest()}"
            if actual != reference:
                raise DistError(
                    "blob-digest-mismatch",
                    f"manifest {reference} reads back as {actual}",
                )
        return body, headers.get("Content-Type", MEDIA_TYPE_MANIFEST)

    def put_manifest(self, manifest: OciManifest) -> Descriptor:
        data = manifest.canonical_bytes()
        digest = f"sha256:{hashlib.sha256(data).hexdigest()}"
        descriptor = self._put_manifest_bytes(digest, data, manifest.media_type)
        return descriptor.model_copy(update={"artifact_type": manifest.artifact_type})

    def manifest(self, descriptor: Descriptor) -> OciManifest:
        data, _ = self._get_manifest_bytes(descriptor.require_sha256())
        try:
            return OciManifest.model_validate_json(data)
        except ValueError as error:
            raise DistError(
                "manifest-invalid",
                f"manifest {descriptor.digest} is not a valid OCI manifest: {error}",
            ) from error

    def ensure_empty_config(self) -> Descriptor:
        digest = self.put_blob_bytes(EMPTY_BLOB)
        return Descriptor(
            media_type=MEDIA_TYPE_EMPTY, digest=digest, size=len(EMPTY_BLOB)
        )

    def put_index(self, name: str, index: OciIndex) -> Descriptor:
        data = index.canonical_bytes()
        # by digest first, then the tag: a crash between the two leaves a
        # digest-addressable root and no dangling tag
        digest_descriptor = self._put_manifest_bytes(
            f"sha256:{hashlib.sha256(data).hexdigest()}", data, index.media_type
        )
        self._put_manifest_bytes(name, data, index.media_type)
        return digest_descriptor.model_copy(
            update={"annotations": dict(index.annotations or {}) or None}
        )

    def read_index(self, descriptor: Descriptor) -> OciIndex:
        data, _ = self._get_manifest_bytes(descriptor.require_sha256())
        try:
            return OciIndex.model_validate_json(data)
        except ValueError as error:
            raise DistError(
                "manifest-invalid",
                f"manifest {descriptor.digest} is not a valid OCI index: {error}",
            ) from error

    def ref(self, name: str) -> Descriptor:
        data, media_type = self._get_manifest_bytes(name)
        return Descriptor(
            media_type=media_type,
            digest=f"sha256:{hashlib.sha256(data).hexdigest()}",
            size=len(data),
        )
