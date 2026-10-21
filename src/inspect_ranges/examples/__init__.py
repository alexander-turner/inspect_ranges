"""The example ranges, packaged as ready-to-run Inspect tasks.

Each task wires its range's `challenges.yaml` and `range.yaml` (shipped as package data alongside the task module) into the standard challenge pipeline: `challenge_dataset`, `challenge_setup`, a `react` agent with `bash` and `verify_goal`, `challenge_scorer`, and the `range` sandbox. The tasks register with the inspect_ai registry via the package entry point, so `inspect eval inspect_ranges/dmz_pivot` resolves with no file path; or import one and pass it to `inspect_ai.eval`:

    from inspect_ranges.examples import dmz_pivot

Each example's directory also carries its `README.md`, recipes, and checks, so the CLI workflow (`inspect-ranges build` from inside the directory) works on the installed package exactly as it does in a checkout.
"""

from ._cyris_basic.task import cyris_basic
from ._dmz_pivot.task import dmz_pivot
from ._equifax.task import equifax
from ._goad_light.task import goad_light
from ._kypo_demo.task import kypo_demo
from ._splunk_detection.task import splunk_detection
from ._vulhub_zabbix.task import vulhub_zabbix

__all__ = [
    "cyris_basic",
    "dmz_pivot",
    "equifax",
    "goad_light",
    "kypo_demo",
    "splunk_detection",
    "vulhub_zabbix",
]
