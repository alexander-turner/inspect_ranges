"""S3 evidence backend: conditional-put write-once mapping, read-side ordering, factories.

Everything here runs offline against `botocore.stub.Stubber`; the live off-instance leg (real bucket, watermark lag, cross-machine verify, deny-overwrite policy) is the slice-3 battery in `design/spikes/evidence-v1-s3/`.
"""

# boto3/botocore are untyped-by-nature (the _devbox rationale in
# pyproject.toml, applied per-file)
# pyright: reportMissingTypeStubs=false, reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false

import asyncio
import io
from pathlib import Path
from typing import Any

import pytest
from botocore.response import StreamingBody
from botocore.stub import Stubber
from click.testing import CliRunner
from inspect_ranges._cli.evidencecmd import evidence
from inspect_ranges._evidence.reader import LocalDirStore
from inspect_ranges._evidence.s3 import (
    S3Sink,
    S3Store,
    parse_s3_location,
    sink_for_location,
    store_for_location,
)
from inspect_ranges._evidence.sink import EvidenceWriter, LocalDirSink


def _client() -> Any:
    import boto3

    # fixed fake credentials and region: construction must never consult the
    # host's AWS environment, and the Stubber intercepts before the network
    return boto3.client(
        "s3",
        region_name="us-east-1",
        aws_access_key_id="stub",
        aws_secret_access_key="stub",
    )


@pytest.mark.parametrize(
    ("location", "bucket", "prefix"),
    [
        ("s3://bucket", "bucket", ""),
        ("s3://bucket/", "bucket", ""),
        ("s3://bucket/a/b", "bucket", "a/b"),
        ("s3://bucket/a/b/", "bucket", "a/b"),
    ],
)
def test_parse_s3_location(location: str, bucket: str, prefix: str) -> None:
    assert parse_s3_location(location) == (bucket, prefix)


@pytest.mark.parametrize("location", ["", "bucket/a", "http://bucket/a", "s3://"])
def test_parse_s3_location_rejects(location: str) -> None:
    with pytest.raises(ValueError):
        parse_s3_location(location)


def test_factories_dispatch_on_scheme(tmp_path: Path) -> None:
    assert isinstance(sink_for_location("s3://bucket/p"), S3Sink)
    assert isinstance(store_for_location("s3://bucket/p"), S3Store)
    assert isinstance(sink_for_location(str(tmp_path)), LocalDirSink)
    assert isinstance(store_for_location(str(tmp_path)), LocalDirStore)
    with pytest.raises(ValueError):
        sink_for_location("ftp://bucket/p")
    with pytest.raises(ValueError):
        store_for_location("ftp://bucket/p")


def test_put_is_conditional_and_prefixed() -> None:
    client = _client()
    sink = S3Sink("s3://bucket/pre/fix", client=client)
    stubber = Stubber(client)
    stubber.add_response(
        "put_object",
        {},
        expected_params={
            "Bucket": "bucket",
            "Key": "pre/fix/chunks/host/pcap/dmz/000000.bin",
            "Body": b"data",
            "IfNoneMatch": "*",
        },
    )
    with stubber:
        asyncio.run(sink.put("chunks/host/pcap/dmz/000000.bin", b"data"))
    stubber.assert_no_pending_responses()


def test_precondition_failed_maps_to_file_exists() -> None:
    client = _client()
    sink = S3Sink("s3://bucket/p", client=client)
    stubber = Stubber(client)
    stubber.add_client_error(
        "put_object",
        service_error_code="PreconditionFailed",
        http_status_code=412,
    )
    with stubber:
        with pytest.raises(FileExistsError):
            asyncio.run(sink.put("manifests/host/seal.json", b"{}"))


def test_conditional_conflict_maps_to_file_exists() -> None:
    # 409 is a FOREIGN conditional put racing our key (the writer is
    # single-flight per key): it must map to FileExistsError so the writer
    # takes the explicit write-once-conflict gap. Raising it as a transient
    # would feed the assume-landed branch (409 then 412 reads as "ours
    # landed"), committing our digest over the foreign winner's bytes.
    client = _client()
    sink = S3Sink("s3://bucket/p", client=client)
    stubber = Stubber(client)
    stubber.add_client_error(
        "put_object",
        service_error_code="ConditionalRequestConflict",
        http_status_code=409,
    )
    with stubber:
        with pytest.raises(FileExistsError):
            asyncio.run(sink.put("chunks/host/s/000000.bin", b"x"))


def test_sdk_retries_disabled() -> None:
    # the writer is the ONLY retry layer: an SDK-internal retry would turn
    # "landed but response lost" into a first-attempt 412, misread as a
    # foreign object (falsely gapping delivered data or refusing a landed
    # seal)
    sink = S3Sink("s3://bucket/p")
    retries = sink._s3().meta.config.retries
    # total_max_attempts is the normalized form; 1 means NO hidden retry
    # (botocore turns max_attempts=1 into total_max_attempts=2)
    assert retries is not None and retries.get("total_max_attempts") == 1


def test_sdk_retries_disabled_behaviorally() -> None:
    """Chunk-2 verification finding 4: pin the BEHAVIOR, not just the config dict.

    A retryable 500 must surface after exactly ONE HTTP attempt. The proof is a bait success queued behind the error: a botocore release reinterpreting `total_max_attempts` would consume the bait in a hidden retry and the first put would falsely succeed; with the SDK transparent, the first put raises and the SECOND put consumes the bait.
    """
    client = _client()
    sink = S3Sink("s3://bucket/p", client=client)
    stubber = Stubber(client)
    stubber.add_client_error(
        "put_object", service_error_code="InternalError", http_status_code=500
    )
    stubber.add_response(
        "put_object",
        {},
        expected_params={
            "Bucket": "bucket",
            "Key": "p/chunks/host/s/000000.bin",
            "Body": b"x",
            "IfNoneMatch": "*",
        },
    )
    with stubber:
        with pytest.raises(Exception, match="InternalError"):
            asyncio.run(sink.put("chunks/host/s/000000.bin", b"x"))
        asyncio.run(sink.put("chunks/host/s/000000.bin", b"x"))
    stubber.assert_no_pending_responses()


def test_access_denied_get_reads_as_missing() -> None:
    # without s3:ListBucket, S3 reports a missing key as 403; a restricted
    # verifier credential must get the chunk-missing break, not a traceback
    client = _client()
    store = S3Store("s3://bucket/p", client=client)
    stubber = Stubber(client)
    stubber.add_client_error(
        "get_object", service_error_code="AccessDenied", http_status_code=403
    )
    with stubber:
        with pytest.raises(FileNotFoundError):
            asyncio.run(store.get("chunks/host/s/000000.bin"))


def test_writer_ambiguous_put_composes_with_s3() -> None:
    """Transient failure then 412 on retry is the S3 lost-response shape: the writer treats the chunk as delivered (no gap), per the chunk-1 posture."""

    class FlakyThen412:
        """The chunk's first put loses its response; the retry meets 412. Everything else (manifest parts, seal) succeeds."""

        def __init__(self) -> None:
            self.chunk_calls = 0

        async def put(self, key: str, data: bytes) -> None:
            if not key.startswith("chunks/"):
                return
            self.chunk_calls += 1
            if self.chunk_calls == 1:
                raise ConnectionError("response lost")
            raise FileExistsError(key)

    async def scenario() -> None:
        writer = EvidenceWriter(
            FlakyThen412(), part_interval_s=0, writer="host", retry_wait_s=0.0
        )
        await writer.append("stages", b"evt")
        result = await writer.flush()
        assert result.delivered_chunks == 1
        assert not result.errors

    asyncio.run(scenario())


def test_get_maps_missing_and_returns_bytes() -> None:
    client = _client()
    store = S3Store("s3://bucket/p", client=client)
    stubber = Stubber(client)
    body = b'{"writer":"host"}'
    stubber.add_response(
        "get_object",
        {"Body": StreamingBody(io.BytesIO(body), len(body))},
        expected_params={"Bucket": "bucket", "Key": "p/manifests/host/seal.json"},
    )
    stubber.add_client_error(
        "get_object", service_error_code="NoSuchKey", http_status_code=404
    )
    with stubber:
        assert asyncio.run(store.get("manifests/host/seal.json")) == body
        with pytest.raises(FileNotFoundError):
            asyncio.run(store.get("manifests/driver/seal.json"))


def test_list_sorts_by_key_never_page_order() -> None:
    client = _client()
    store = S3Store("s3://bucket/p", client=client)
    stubber = Stubber(client)
    # two pages, deliberately unsorted within and across pages
    stubber.add_response(
        "list_objects_v2",
        {
            "IsTruncated": True,
            "NextContinuationToken": "token",
            "Contents": [
                {"Key": "p/manifests/host/part-000001.json"},
                {"Key": "p/manifests/driver/seal.json"},
            ],
        },
        # "/"-terminated so a writer named "host" never sweeps in "host2"
        expected_params={"Bucket": "bucket", "Prefix": "p/manifests/"},
    )
    stubber.add_response(
        "list_objects_v2",
        {
            "IsTruncated": False,
            "Contents": [{"Key": "p/manifests/host/part-000000.json"}],
        },
        expected_params={
            "Bucket": "bucket",
            "Prefix": "p/manifests/",
            "ContinuationToken": "token",
        },
    )
    with stubber:
        keys = asyncio.run(store.list("manifests"))
    assert keys == [
        "manifests/driver/seal.json",
        "manifests/host/part-000000.json",
        "manifests/host/part-000001.json",
    ]


def test_cli_verify_rejects_unknown_scheme() -> None:
    result = CliRunner().invoke(evidence, ["verify", "ftp://bucket/p"])
    assert result.exit_code != 0
    assert "unsupported evidence location scheme" in result.output


def test_doctor_s3_probe_stubbed() -> None:
    """The doctor's sink probe is one conditional put plus best-effort delete: denied credentials warn (a stated condition, never a host failure), and a put-only credential is ok with the residue noted."""
    from botocore.stub import ANY, Stubber
    from inspect_ranges._doctor.s3probe import probe_s3_sink

    def client_with(responses: list[tuple[str, bool]]) -> Any:
        client = _client()
        stubber = Stubber(client)
        for op, succeed in responses:
            if succeed:
                stubber.add_response(
                    op,
                    {},
                    {"Bucket": "b", "Key": ANY, "Body": ANY, "IfNoneMatch": "*"}
                    if op == "put_object"
                    else {"Bucket": "b", "Key": ANY},
                )
            else:
                stubber.add_client_error(op, "AccessDenied", "denied", 403)
        stubber.activate()
        return client

    ok = probe_s3_sink(
        "Evidence",
        "s3://b/pre",
        client=client_with([("put_object", True), ("delete_object", True)]),
    )
    assert ok.status == "ok"

    put_only = probe_s3_sink(
        "Evidence",
        "s3://b/pre",
        client=client_with([("put_object", True), ("delete_object", False)]),
    )
    assert put_only.status == "ok"
    assert "residue" in put_only.detail

    denied = probe_s3_sink(
        "Evidence", "s3://b/pre", client=client_with([("put_object", False)])
    )
    assert denied.status == "warn"
    assert "stated condition" in denied.detail
