"""The OCI registry client: one repository as a `ContentStore`, over the distribution v2 protocol.

Pure Python by decision (distribution-v1.md slice 2, settled by the opening probe against `registry:2` and the live hub token flow): the protocol surface this layer needs (ping, HEAD, monolithic blob upload, manifest put/get by digest and tag) is small, and owning it keeps zero external binary dependencies and full control of verification: every byte a registry returns verifies against its descriptor digest before use, exactly like the directory form. Uploads are monolithic-PUT only, a recorded narrowing of the plan's "chunked and mounted" sketch (round-2 review N6): the live battery proves monolithic against `registry:2`, cross-repo mounts and chunked resume arrive if the slice-6 hub measurements demand them, and until then the simpler protocol has fewer failure states.

Auth is the standard docker credential config plus the bearer-token flow: an unauthenticated registry (a local `registry:2`) works anonymously; a 401 with a `WWW-Authenticate: Bearer` challenge is answered by fetching a token from the named realm, with Basic credentials from `~/.docker/config.json` when the host has a plain-auth entry (credential helpers are not consulted, and denials say so). Operations request least privilege (`pull` for reads, `pull,push` for writes) and tokens cache per requested scope. Redirects never carry the bearer token off the registry's origin: real registries redirect blob GETs to presigned storage URLs, and forwarding `Authorization` there both leaks the token and breaks presigned auth (round-2 review B3). Credentials never appear in errors or logs.
"""

import hashlib
import json
import os
import re
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator
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
    ProgressFn,
)

__all__ = [
    "RegistryRepo",
    "docker_auth_for",
    "docker_config_uses_helper",
    "registry_catalog",
]

_CHUNK = 1 << 20
_MANIFEST_CAP = 16 * 1024 * 1024
_ERROR_BODY_CAP = 300
_ACCEPT_MANIFESTS = f"{MEDIA_TYPE_INDEX}, {MEDIA_TYPE_MANIFEST}"
_REPO_SEGMENT = r"[a-z0-9]+(?:[._-][a-z0-9]+)*"

_HUB_HOSTS = ("docker.io", "registry-1.docker.io", "index.docker.io")


def _load_docker_config(config_path: Path | None) -> dict[str, Any] | None:
    path = config_path or Path.home() / ".docker" / "config.json"
    try:
        config: dict[str, Any] = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    return config


def _host_keys(host: str) -> list[str]:
    candidates = [host, f"https://{host}", f"http://{host}"]
    if host in _HUB_HOSTS:
        candidates.append("https://index.docker.io/v1/")
    return candidates


def docker_auth_for(host: str, config_path: Path | None = None) -> str | None:
    """The base64 `user:secret` from the docker credential config for `host`, or `None` for anonymous.

    Docker Hub's hosts (`docker.io`, `registry-1.docker.io`, `index.docker.io`) all map to the config's legacy `https://index.docker.io/v1/` key. Only plain `auths` entries are read; see `docker_config_uses_helper` for the helper-configured case.
    """
    config = _load_docker_config(config_path)
    if config is None:
        return None
    raw_auths = config.get("auths")
    if not isinstance(raw_auths, dict):
        return None
    auths = cast("dict[str, object]", raw_auths)
    for key in _host_keys(host):
        entry = auths.get(key)
        if isinstance(entry, dict):
            auth = cast("dict[str, object]", entry).get("auth")
            if isinstance(auth, str):
                return auth
    return None


def docker_config_uses_helper(host: str, config_path: Path | None = None) -> bool:
    """Whether the docker config routes `host` through a credential helper this client does not consult (so a denial can say why a logged-in host looked anonymous)."""
    config = _load_docker_config(config_path)
    if config is None:
        return False
    if isinstance(config.get("credsStore"), str) and config["credsStore"]:
        return True
    helpers = config.get("credHelpers")
    if isinstance(helpers, dict):
        helper_map = cast("dict[str, object]", helpers)
        return any(key in helper_map for key in _host_keys(host))
    return False


def registry_catalog(
    base_url: str, prefix: str, *, docker_config: Path | None = None
) -> list[str]:
    """A registry's repository names under `prefix`, through the same bearer-auth flow as every other request (round-5 N4), paginated via `last` (round-5 N3)."""
    host = urllib.parse.urlparse(base_url).netloc
    token: str | None = None
    names: list[str] = []
    last = ""
    while True:
        url = f"{base_url}/v2/_catalog?n=1000" + (
            f"&last={urllib.parse.quote(last)}" if last else ""
        )
        request = urllib.request.Request(url)
        if token:
            request.add_header("Authorization", f"Bearer {token}")
        try:
            response = _OPENER.open(request, timeout=60)
        except urllib.error.HTTPError as error:
            if error.code == 401 and token is None:
                challenge = error.headers.get("WWW-Authenticate", "")
                error.close()
                token = _catalog_token(challenge, host, docker_config)
                continue
            body = error.read()[:200]
            error.close()
            raise DistError(
                "location-unenumerable",
                f"{host} did not answer the catalog listing ({error.code}): "
                f"{body.decode(errors='replace')}; mirror explicit names instead",
            ) from None
        except (urllib.error.URLError, OSError) as error:
            raise DistError(
                "location-unenumerable",
                f"{host} did not answer the catalog listing: {error}; "
                "mirror explicit names instead",
            ) from error
        try:
            payload = json.loads(_read_capped(response, _MANIFEST_CAP, "catalog"))
        finally:
            response.close()
        raw = payload.get("repositories")
        if not isinstance(raw, list):
            raise DistError(
                "location-unenumerable", f"{host} returned no repository list"
            )
        page = [repo for repo in cast("list[object]", raw) if isinstance(repo, str)]
        wanted = f"{prefix}/" if prefix else ""
        names.extend(
            repo.removeprefix(wanted)
            for repo in page
            if not wanted or repo.startswith(wanted)
        )
        if len(page) < 1000:
            return names
        last = page[-1]


def _catalog_token(challenge: str, host: str, docker_config: Path | None) -> str:
    if not challenge.startswith("Bearer "):
        raise DistError(
            "location-unenumerable",
            f"{host} denied the catalog with no bearer challenge",
        )
    params = dict(re.findall(r'(\w+)="([^"]*)"', challenge.removeprefix("Bearer ")))
    realm = params.get("realm")
    if not realm:
        raise DistError("location-unenumerable", f"{host} sent no token realm")
    query = {"scope": params.get("scope", "registry:catalog:*")}
    if "service" in params:
        query["service"] = params["service"]
    request = urllib.request.Request(f"{realm}?{urllib.parse.urlencode(query)}")
    auth = docker_auth_for(host, docker_config)
    if auth:
        request.add_header("Authorization", f"Basic {auth}")
    try:
        with _OPENER.open(request, timeout=60) as response:
            token = json.loads(_read_capped(response, _MANIFEST_CAP, "token")).get(
                "token"
            )
    except (urllib.error.URLError, OSError, ValueError) as error:
        raise DistError(
            "location-unenumerable", f"catalog token fetch failed: {error}"
        ) from error
    if not isinstance(token, str) or not token:
        raise DistError("location-unenumerable", f"{realm} returned no token")
    return token


class _OneShotDrained(Exception):
    """Internal: a non-replayable stream body was asked for a second attempt."""


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


class _OriginBoundRedirects(urllib.request.HTTPRedirectHandler):
    """Follow redirects, but never carry `Authorization` to a different origin: registries redirect blob GETs to presigned storage URLs, where a forwarded bearer token is both a leak and a request-breaker."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: "IO[bytes]",
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            original = urllib.parse.urlparse(req.full_url).netloc
            target = urllib.parse.urlparse(newurl).netloc
            if original != target:
                new.remove_header("Authorization")
        return new


_OPENER = urllib.request.build_opener(_OriginBoundRedirects)


def _read_capped(response: "IO[bytes]", cap: int, context: str) -> bytes:
    """Read a bounded body; a response exceeding `cap` refuses before it is resident (a hostile registry must not OOM the puller)."""
    data = response.read(cap + 1)
    if len(data) > cap:
        raise DistError(
            "blob-too-large", f"{context} exceeded the {cap} byte read bound"
        )
    return data


class RegistryRepo:
    """One registry repository as a `ContentStore` (see `oci.ContentStore` for the semantics every store holds).

    `base_url` is the registry origin (`http://127.0.0.1:5055`, `https://registry-1.docker.io`); `repo` is the repository path (`meridianlabsai/ir-dist-test`). Refs are tags; indexes and manifests ride the manifests endpoint, blobs the blobs endpoint, and a pushed index is also addressable by digest exactly like the directory form's root. A tag is mutable by design and trusted only to NAME a root: `ref` hashes the returned bytes to mint the descriptor, and every subsequent read re-fetches by digest and verifies.
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
        data_factory: "Callable[[], bytes | _StreamBody] | None" = None,
        actions: str = "pull",
        ok: tuple[int, ...] = (200,),
        stream: bool = False,
        cap: int = _MANIFEST_CAP,
        _retried: bool = False,
    ) -> "tuple[int, dict[str, str], bytes | IO[bytes]]":
        """One registry request with least-privilege auth and a single 401 retry.

        `data_factory` produces the request body PER ATTEMPT, so an auth retry never replays a consumed stream (round-2 review B1); a factory that cannot replay raises `_OneShotDrained`, surfaced as a coded refusal rather than a stalled upload. `actions` is the token scope the operation needs (`pull` or `pull,push`); tokens cache per scope.
        """
        body: "bytes | _StreamBody | None" = None
        if data_factory is not None:
            try:
                body = data_factory()
            except _OneShotDrained:
                raise DistError(
                    "registry-denied",
                    f"{self._host} required re-authentication mid-upload and the "
                    "stream cannot replay; re-run the transfer",
                ) from None
        request = urllib.request.Request(
            url, method=method, data=body, headers=dict(headers or {})
        )
        scope = f"repository:{self.repo}:{actions}"
        token = self._tokens.get(scope)
        if token:
            request.add_header("Authorization", f"Bearer {token}")
        try:
            response = _OPENER.open(request, timeout=120)
        except urllib.error.HTTPError as error:
            if error.code == 401 and not _retried:
                challenge = error.headers.get("WWW-Authenticate", "")
                error.close()
                self._tokens[scope] = self._fetch_token(challenge, scope)
                return self._request(
                    method,
                    url,
                    headers=headers,
                    data_factory=data_factory,
                    actions=actions,
                    ok=ok,
                    stream=stream,
                    cap=cap,
                    _retried=True,
                )
            error_body = _read_capped(error, _ERROR_BODY_CAP, "error body")
            error.close()
            if error.code in ok:
                return error.code, {}, error_body
            raise DistError(
                "registry-denied" if error.code in (401, 403) else "registry-protocol",
                f"{method} {url} returned {error.code}: "
                f"{error_body.decode(errors='replace')}"
                f"{self._helper_hint() if error.code in (401, 403) else ''}",
            ) from None
        except BrokenPipeError as error:
            if body is not None:
                # a server rejecting an upload without draining the body
                # surfaces as EPIPE mid-send; name the likely cause instead of
                # miscoding it as unreachable (round-2 review B1)
                raise DistError(
                    "registry-denied",
                    f"{self._host} closed the connection mid-upload (commonly an "
                    "auth or size rejection without draining the body); re-run "
                    f"the transfer{self._helper_hint()}",
                ) from error
            raise DistError(
                "registry-unreachable", f"{method} {url} failed: {error}"
            ) from error
        except (urllib.error.URLError, OSError, TimeoutError) as error:
            raise DistError(
                "registry-unreachable", f"{method} {url} failed: {error}"
            ) from error
        status = response.status
        # header names normalize to lowercase: real registries (the hub's LB
        # among them) emit lowercase headers, and a plain dict is case-blind
        response_headers = {k.lower(): v for k, v in response.headers.items()}
        if status not in ok:
            unexpected = _read_capped(response, _ERROR_BODY_CAP, "error body")
            response.close()
            raise DistError(
                "registry-protocol",
                f"{method} {url} returned {status}: "
                f"{unexpected.decode(errors='replace')}",
            )
        if stream:
            return status, response_headers, response
        payload = _read_capped(response, cap, f"{method} {url} response")
        response.close()
        return status, response_headers, payload

    def _helper_hint(self) -> str:
        if docker_auth_for(self._host, self._docker_config) is None and (
            docker_config_uses_helper(self._host, self._docker_config)
        ):
            return (
                " (the docker config routes this host through a credential "
                "helper, which this client does not consult; log in with a "
                "plain auths entry)"
            )
        return ""

    def _fetch_token(self, challenge: str, scope: str) -> str:
        """Answer a `WWW-Authenticate: Bearer` challenge; Basic credentials ride along when the docker config has them."""
        if not challenge.startswith("Bearer "):
            raise DistError(
                "registry-denied",
                f"{self._host} denied access and offered no bearer challenge"
                f"{self._helper_hint()}",
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
            with _OPENER.open(request, timeout=60) as response:
                payload = json.loads(_read_capped(response, _MANIFEST_CAP, "token"))
        except (urllib.error.URLError, OSError, ValueError) as error:
            raise DistError(
                "registry-denied",
                f"token fetch from {realm} failed: {error}{self._helper_hint()}",
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

    def _upload(
        self,
        body_factory: "Callable[[], bytes | _StreamBody]",
        digest: str,
        size: int,
    ) -> str:
        _, headers, _ = self._request(
            "POST",
            self._url("blobs/uploads/"),
            headers={"Content-Length": "0"},
            data_factory=lambda: b"",
            actions="pull,push",
            ok=(202,),
        )
        location = headers.get("location")
        if not location:
            raise DistError(
                "registry-protocol", f"{self._host} started an upload with no Location"
            )
        if location.startswith("/"):
            location = f"{self.base_url}{location}"
        elif urllib.parse.urlparse(location).netloc != self._host:
            # the bearer token must never travel to a foreign origin (the
            # redirect handler covers redirects; this covers server-supplied
            # upload URLs, phase round-1 N1); on-origin uploads are what every
            # real registry does
            raise DistError(
                "registry-protocol",
                f"{self._host} directed the upload to a different origin "
                f"({urllib.parse.urlparse(location).netloc}); refusing to send "
                "credentials there",
            )
        separator = "&" if "?" in location else "?"
        self._request(
            "PUT",
            f"{location}{separator}digest={urllib.parse.quote(digest, safe=':')}",
            data_factory=body_factory,
            actions="pull,push",
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
        return self._upload(lambda: data, digest, len(data))

    def put_blob_file(
        self,
        source: Path,
        *,
        expected: str | None = None,
        progress: "ProgressFn | None" = None,
    ) -> str:
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
            if progress is not None:
                progress(digest, "exists", 0, 0)
            return digest
        bound = digest
        total = source.stat().st_size

        def fresh_body() -> _StreamBody:
            # file-backed uploads replay freely: each attempt streams the file
            # again with its own verifying hasher (round-2 review B1)
            def verified_chunks() -> Iterator[bytes]:
                hasher = hashlib.sha256()
                done = 0
                with source.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(_CHUNK), b""):
                        hasher.update(chunk)
                        done += len(chunk)
                        if progress is not None:
                            progress(bound, "uploading", done, total)
                        yield chunk
                if f"sha256:{hasher.hexdigest()}" != bound:
                    raise DistError(
                        "blob-digest-mismatch",
                        f"{source} changed while uploading (expected {bound})",
                    )

            return _StreamBody(verified_chunks())

        uploaded = self._upload(fresh_body, digest, total)
        if progress is not None:
            progress(uploaded, "done", total, total)
        return uploaded

    def put_blob_stream(
        self,
        chunks: Iterator[bytes],
        *,
        expected: str,
        size: int,
        progress: "ProgressFn | None" = None,
    ) -> str:
        if DIGEST_PATTERN.fullmatch(expected) is None:
            raise DistError(
                "unsupported-digest", f"{expected!r} is not a sha256 digest"
            )
        if self.has_blob(expected):
            for _ in chunks:
                pass
            return expected
        attempts = 0

        def one_shot_body() -> _StreamBody:
            # the incoming iterator cannot replay; the HEAD and POST above run
            # authenticated first, so the PUT holds a fresh token and a 401
            # here surfaces as the coded re-run refusal, never a stall
            nonlocal attempts
            attempts += 1
            if attempts > 1:
                raise _OneShotDrained()

            def verified() -> Iterator[bytes]:
                hasher = hashlib.sha256()
                total = 0
                for chunk in chunks:
                    hasher.update(chunk)
                    total += len(chunk)
                    if progress is not None:
                        progress(expected, "uploading", total, size)
                    yield chunk
                if f"sha256:{hasher.hexdigest()}" != expected or total != size:
                    raise DistError(
                        "blob-digest-mismatch",
                        f"stream disagreed with {expected} ({size} bytes)",
                    )

            return _StreamBody(verified())

        return self._upload(one_shot_body, expected, size)

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
            "GET", self._url(f"blobs/{digest}"), ok=(200, 404), cap=cap
        )
        if status == 404:
            raise DistError("missing-blob", f"{self.repo} has no blob {digest}")
        assert isinstance(body, bytes)
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
        progress: "ProgressFn | None" = None,
    ) -> None:
        digest = descriptor.require_sha256()
        destination.parent.mkdir(parents=True, exist_ok=True)
        hasher = hashlib.sha256()
        done = 0
        fd, temp_name = tempfile.mkstemp(
            dir=destination.parent, prefix=temp_prefix or ".incoming-"
        )
        temp = Path(temp_name)
        try:
            with os.fdopen(fd, "wb") as out:
                for chunk in self.blob_chunks(descriptor):
                    hasher.update(chunk)
                    out.write(chunk)
                    done += len(chunk)
                    if progress is not None:
                        progress(digest, "downloading", done, descriptor.size or done)
            actual = f"sha256:{hasher.hexdigest()}"
            if actual != digest:
                raise DistError(
                    "blob-digest-mismatch", f"blob {digest} reads back as {actual}"
                )
            temp.chmod(0o644)
            os.replace(temp, destination)
            if progress is not None:
                progress(digest, "done", done, done)
        finally:
            temp.unlink(missing_ok=True)

    # -- manifests and indexes -------------------------------------------------------

    def put_manifest_bytes(self, data: bytes, media_type: str) -> Descriptor:
        """Store manifest bytes VERBATIM by digest (the transfer path: foreign manifests must keep their digests)."""
        digest = f"sha256:{hashlib.sha256(data).hexdigest()}"
        self._request(
            "PUT",
            self._url(f"manifests/{digest}"),
            data_factory=lambda: data,
            actions="pull,push",
            headers={"Content-Type": media_type, "Content-Length": str(len(data))},
            ok=(201,),
        )
        return Descriptor(media_type=media_type, digest=digest, size=len(data))

    def _put_tagged(self, tag: str, data: bytes, media_type: str) -> None:
        self._request(
            "PUT",
            self._url(f"manifests/{urllib.parse.quote(tag, safe='')}"),
            data_factory=lambda: data,
            actions="pull,push",
            headers={"Content-Type": media_type, "Content-Length": str(len(data))},
            ok=(201,),
        )

    def _get_manifest_bytes(self, reference: str) -> tuple[bytes, str]:
        status, headers, body = self._request(
            "GET",
            self._url(f"manifests/{reference}"),
            headers={"Accept": _ACCEPT_MANIFESTS},
            ok=(200, 404),
            cap=_MANIFEST_CAP,
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
        return body, headers.get("content-type", MEDIA_TYPE_MANIFEST)

    def manifest_bytes(self, descriptor: Descriptor) -> bytes:
        """A manifest's verified RAW bytes (the transfer path reads these, never a re-serialization)."""
        data, _ = self._get_manifest_bytes(descriptor.require_sha256())
        return data

    def put_manifest(self, manifest: OciManifest) -> Descriptor:
        descriptor = self.put_manifest_bytes(
            manifest.canonical_bytes(), manifest.media_type
        )
        return descriptor.model_copy(update={"artifact_type": manifest.artifact_type})

    def manifest(self, descriptor: Descriptor) -> OciManifest:
        data = self.manifest_bytes(descriptor)
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

    def put_index_bytes(self, name: str, data: bytes) -> Descriptor:
        """Store index bytes VERBATIM by digest, then tag them `name` (digest first, so a crash never leaves a dangling tag)."""
        descriptor = self.put_manifest_bytes(data, MEDIA_TYPE_INDEX)
        self._put_tagged(name, data, MEDIA_TYPE_INDEX)
        return descriptor

    def put_index(self, name: str, index: OciIndex) -> Descriptor:
        data = index.canonical_bytes()
        descriptor = self.put_index_bytes(name, data)
        return descriptor.model_copy(
            update={"annotations": dict(index.annotations or {}) or None}
        )

    def read_index(self, descriptor: Descriptor) -> OciIndex:
        data = self.manifest_bytes(descriptor)
        try:
            return OciIndex.model_validate_json(data)
        except ValueError as error:
            raise DistError(
                "manifest-invalid",
                f"manifest {descriptor.digest} is not a valid OCI index: {error}",
            ) from error

    def tags(self) -> list[str]:
        """Every tag in this repository (paginated via `last`, so large repos enumerate completely)."""
        tags: list[str] = []
        last = ""
        while True:
            suffix = "tags/list?n=1000" + (
                f"&last={urllib.parse.quote(last)}" if last else ""
            )
            _, _, body = self._request("GET", self._url(suffix), ok=(200,))
            assert isinstance(body, bytes)
            try:
                payload = json.loads(body)
            except ValueError as error:
                raise DistError(
                    "registry-protocol", f"{self.repo} tags/list did not parse: {error}"
                ) from error
            raw_tags = payload.get("tags")
            page_source = cast(
                "list[object]", raw_tags if isinstance(raw_tags, list) else []
            )
            page = [tag for tag in page_source if isinstance(tag, str)]
            tags.extend(page)
            if len(page) < 1000:
                return tags
            last = page[-1]

    def ref(self, name: str) -> Descriptor:
        data, media_type = self._get_manifest_bytes(name)
        return Descriptor(
            media_type=media_type,
            digest=f"sha256:{hashlib.sha256(data).hexdigest()}",
            size=len(data),
        )
