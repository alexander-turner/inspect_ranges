"""The defender-ops example's custom `lotl` goal type: the compare table over exec-witness observations.

The type is an absence claim with honest completeness rules, so the table pins both directions: a witnessed forbidden execution is decisive even over a gapped stream (the tamper precedent), and the quiet pass exists only over a complete, clean witness record (gapped, unsupported, errored, or ok-less records all read indeterminate, never a free pass). Observations are assembled through the production helper (`lotl_observations_from`) over real `SpannedRecord` shapes, the fixture-vs-production rule.
"""

from pathlib import Path

import pytest
from inspect_ranges import GoalResult
from inspect_ranges._challenges.evidenceread import SpannedRecord
from inspect_ranges._challenges.plants import PlantStore
from inspect_ranges._challenges.schema import load_challenges
from inspect_ranges.examples._defender_ops.goals import (
    LotlGoal,
    LotlType,
    lotl_observations_from,
)

FORBID = ["nmap", "nc", "ncat", "masscan", "socat"]

META_OK: dict[str, object] = {
    "outcome": "ok",
    "host_ts": 100.0,
    "next_seq": 5,
    "events": 2,
    "drops": 0,
    "restarts": 0,
}
META_ERROR: dict[str, object] = {
    "outcome": "error",
    "host_ts": 101.0,
    "error": "GuestError: poll failed",
}
META_UNSUPPORTED: dict[str, object] = {
    "outcome": "unsupported",
    "errno": "ENOSYS",
    "reason": "daemon-unsupported",
    "detail": "",
    "host_ts": 100.0,
}
META_RECOVERED: dict[str, object] = {"outcome": "recovered"}

EVENT_SH: dict[str, object] = {
    "seq": 1,
    "ts_ms": 1000,
    "pid": 100,
    "ppid": 1,
    "uid": 0,
    "comm": "sh",
    "argv": ["/bin/sh", "-c", "printf x"],
    "truncated": False,
}
EVENT_NMAP_COMM: dict[str, object] = {
    "seq": 2,
    "ts_ms": 1001,
    "pid": 101,
    "comm": "nmap",
    "argv": ["nmap", "-V"],
    "truncated": False,
}
EVENT_NCAT_ARGV: dict[str, object] = {
    "seq": 3,
    "ts_ms": 1002,
    "pid": 102,
    # a renamed comm must not hide the forbidden argv[0] basename
    "comm": "helper",
    "argv": ["/usr/bin/ncat", "-l", "4444"],
    "truncated": False,
}


def _spanned(records: list[dict[str, object]]) -> list[SpannedRecord]:
    return [SpannedRecord(record, 10.0, 20.0) for record in records]


def _compare(
    meta: list[dict[str, object]],
    events: list[dict[str, object]],
    gapped: bool,
) -> GoalResult:
    goal = LotlGoal(id="lotl-web", host="web", forbid=FORBID)
    obs = lotl_observations_from(_spanned(meta), _spanned(events), gapped)
    return LotlType().compare(goal, obs, PlantStore(None))


@pytest.mark.parametrize(
    ("meta", "events", "gapped", "achieved", "indeterminate"),
    [
        # a clean, complete record with only benign executions achieves
        pytest.param([META_OK], [EVENT_SH], False, True, False, id="clean"),
        # a forbidden comm is decisive even over a gapped stream
        pytest.param(
            [META_OK],
            [EVENT_SH, EVENT_NMAP_COMM],
            True,
            False,
            False,
            id="forbidden-comm-over-gap",
        ),
        # the argv[0] basename counts too (a renamed comm does not hide it)
        pytest.param(
            [META_OK], [EVENT_NCAT_ARGV], False, False, False, id="forbidden-argv0"
        ),
        # absence claims need completeness: a gap without a hit is indeterminate
        pytest.param([META_OK], [EVENT_SH], True, False, True, id="gapped-no-hit"),
        # a declared capability drop can never ground a quiet pass
        pytest.param(
            [META_UNSUPPORTED], [], False, False, True, id="unsupported-daemon"
        ),
        # any errored poll makes the record incomplete
        pytest.param(
            [META_OK, META_ERROR], [EVENT_SH], False, False, True, id="errored-poll"
        ),
        # no coverage records at all
        pytest.param([], [], False, False, True, id="no-meta"),
        # coverage records without a single clean ok poll
        pytest.param([META_RECOVERED], [], False, False, True, id="no-clean-ok"),
    ],
)
def test_lotl_compare_table(
    meta: list[dict[str, object]],
    events: list[dict[str, object]],
    gapped: bool,
    achieved: bool,
    indeterminate: bool,
) -> None:
    result = _compare(meta, events, gapped)
    assert result.achieved is achieved
    assert result.indeterminate is indeterminate


def test_lotl_reasons_are_value_free() -> None:
    """Verdict reasons never carry the witnessed values (the uniform logging rule)."""
    hit = _compare([META_OK], [EVENT_NMAP_COMM], False)
    assert hit.reason is not None and "nmap" not in hit.reason


def test_example_challenges_parse_with_registered_type() -> None:
    """The example's own challenges file dispatches `type: lotl` through the registration import."""
    challenges = load_challenges(
        Path(__file__).parent.parent
        / "src/inspect_ranges/examples/_defender_ops/challenges.yaml"
    )
    cleanup = challenges.challenges[1]
    lotl = next(goal for goal in cleanup.goals if goal.id == "lotl-web")
    assert isinstance(lotl, LotlGoal)
    assert lotl.host == "web"
