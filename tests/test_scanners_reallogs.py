"""`range_apparatus` against real eval logs and the real consumption seams.

The zero-findings pins run the shared engine over green publish-day logs (2026-10-21) at the engine seam and through scout's own eval-log loader (`transcripts_from` + `scan`); a real fire is pinned on the mh-build log, whose achieved exfiltrate goals genuinely read `corroborated` false. Log-dependent tests skip when the machine-local logs are absent; the synthetic red cases live in `test_scanners_engine.py` and run everywhere.
"""

from pathlib import Path

import pytest
from inspect_ai import Task
from inspect_ai import (
    eval as inspect_eval,  # pyright: ignore[reportUnknownVariableType]
)
from inspect_ai.dataset import Sample
from inspect_ai.log import read_eval_log
from inspect_ranges._scanners.engine import Finding, apparatus_findings
from inspect_ranges.scanners import range_apparatus
from inspect_ranges.schema import load_range
from inspect_scout import as_scorer, scan, scan_results_df, transcripts_from

DMZ_LOG = Path(
    "/tmp/publish-day/logs/dmz-eval/"
    "2026-10-21T02-40-17-00-00_task_LxaAQ9rJN7yuZEwqVucH9z.eval"
)
CYRIS_LOG = Path(
    "/home/USER/inspect_ranges/design/spikes/cyris-build/tmp/logs/eval/"
    "2026-10-21T02-32-13-00-00_task_VZ3PhPfLHRriFV4kW5Rz3b.eval"
)
MH_LOG = Path(
    "/home/USER/inspect_ranges/design/spikes/mh-build/tmp/logs/eval/"
    "2026-10-21T02-47-33-00-00_task_2iBgpWyCbJkvqU5uwBdLkG.eval"
)
DMZ_RANGE = Path(__file__).parent.parent / "examples" / "dmz-pivot" / "range.yaml"


def findings_for(log_path: Path, range_yaml: Path | None) -> dict[str, list[Finding]]:
    spec = load_range(range_yaml) if range_yaml is not None else None
    log = read_eval_log(str(log_path))
    assert log.status == "success"
    return {
        str(sample.id): apparatus_findings(
            sample.events, sample.messages, sample.metadata, spec
        )
        for sample in log.samples or []
    }


@pytest.mark.skipif(
    not DMZ_LOG.exists(), reason="publish-day dmz log not on this machine"
)
def test_green_dmz_publish_log_yields_zero_findings() -> None:
    """The 2026-10-21 dmz-pivot publish eval, scanned WITH its real range spec (every detector family armed)."""
    by_sample = findings_for(DMZ_LOG, DMZ_RANGE)
    assert by_sample == {"crown-jewels": []}


@pytest.mark.skipif(
    not CYRIS_LOG.exists(), reason="publish-day cyris log not on this machine"
)
def test_green_cyris_publish_log_yields_zero_findings() -> None:
    """The 2026-10-21 cyris publish eval (four samples), scanned without a spec."""
    by_sample = findings_for(CYRIS_LOG, None)
    assert set(by_sample) == {
        "cross-segment-recon",
        "firewall-pivot",
        "forensics-triage",
        "local-privesc-flag",
    }
    assert all(findings == [] for findings in by_sample.values())


@pytest.mark.skipif(
    not MH_LOG.exists(), reason="mh-build spike log not on this machine"
)
def test_mh_log_fires_the_uncorroborated_segments_hint() -> None:
    """A real fire: the mh exfiltrate goals achieved with `corroborated` false across the board."""
    by_sample = findings_for(MH_LOG, None)
    findings = by_sample["exfiltrate-critical-data"]
    assert [finding.detector for finding in findings] == [
        "scoring/uncorroborated-segments"
    ]


@pytest.mark.skipif(
    not DMZ_LOG.exists(), reason="publish-day dmz log not on this machine"
)
def test_scout_scan_over_the_green_log_reads_zero(tmp_path: Path) -> None:
    """The native after-the-fact path: scout's eval-log loader feeds the same engine and reads zero findings."""
    status = scan(
        [range_apparatus(range_spec=DMZ_RANGE)],
        transcripts_from(str(DMZ_LOG)),
        scans=str(tmp_path),
        display="none",
        max_processes=1,
    )
    assert status.complete
    results = scan_results_df(status.location)
    frame = results.scanners["range_apparatus"]
    # pandas is untyped here; the ignores are scoped to the frame reads
    assert list(frame["value"]) == [0]  # pyright: ignore[reportUnknownArgumentType]
    assert list(frame["explanation"]) == ["no findings"]  # pyright: ignore[reportUnknownArgumentType]


def test_as_scorer_runs_online(tmp_path: Path) -> None:
    """The online seam: the scanner rides the scorer list through `as_scorer` and lands a 0/no-findings score on a healthy mockllm sample."""
    task = Task(
        dataset=[Sample(input="say hi", target="hi")],
        scorer=as_scorer(range_apparatus()),
    )
    log = inspect_eval(
        task, model="mockllm/model", display="none", log_dir=str(tmp_path)
    )[0]
    assert log.status == "success"
    sample = (log.samples or [])[0]
    assert sample.scores is not None
    score = sample.scores["range_apparatus"]
    assert score.value == 0
    assert score.explanation == "no findings"
