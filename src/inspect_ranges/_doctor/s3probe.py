"""The doctor's S3 evidence-sink probe, isolated so the boto pragmas stay off `checks.py`.

One conditional put under `.doctor-probe/`, then a best-effort delete: a put-only credential leaves harmless residue there, and an unreachable or credential-less sink is a stated condition (`warn`), never a host failure, because doctor must not require AWS.
"""

# boto3/botocore are untyped-by-nature (the _devbox rationale in
# pyproject.toml, applied per-file)
# pyright: reportMissingTypeStubs=false, reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false

import uuid
from typing import Any

from .result import CheckResult


def probe_s3_sink(group: str, base: str, *, client: Any | None = None) -> CheckResult:
    """Writability probe of an `s3://` sink override under the writer's own client config."""
    from botocore.exceptions import BotoCoreError, ClientError

    from .._evidence.s3 import new_s3_client, parse_s3_location

    try:
        # parsed OUTSIDE the probe's try: a malformed URL is a config error
        # that will disable evidence at run time (fail, fix the URL), not an
        # unreachable sink (warn, stated condition)
        bucket, prefix = parse_s3_location(base)
    except ValueError as error:
        return CheckResult(
            group,
            "sink",
            "fail",
            f"malformed evidence sink location ({error}); the runtime would disable evidence for every sample",
            fix="fix INSPECT_RANGES_EVIDENCE_SINK: s3://bucket[/prefix]",
        )
    try:
        key = f"{prefix}/.doctor-probe/{uuid.uuid4().hex}".lstrip("/")
        s3 = client if client is not None else new_s3_client()
        s3.put_object(Bucket=bucket, Key=key, Body=b"doctor", IfNoneMatch="*")
        residue = ""
        try:
            s3.delete_object(Bucket=bucket, Key=key)
        except (BotoCoreError, ClientError):
            residue = " (probe object not deletable with this credential; harmless residue under .doctor-probe/)"
        return CheckResult(
            group, "sink", "ok", f"conditional put OK at {base}{residue}"
        )
    except (BotoCoreError, ClientError, OSError) as error:
        return CheckResult(
            group,
            "sink",
            "warn",
            f"could not probe {base} ({type(error).__name__}: {error}); no credentials or no network here is a stated condition, not a host failure",
            fix="ensure credentials with s3:PutObject on the sink prefix are available where evals run",
        )
