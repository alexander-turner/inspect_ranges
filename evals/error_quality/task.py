"""Error-quality eval: can a model fix a broken `range.yaml` given only the validator's output?

Each sample is a deliberately broken fixture. The solver loop shows the model the current file plus the rendered `ValidationReport`, takes back a corrected full file, and re-validates, up to `max_iterations` times. The score is whether the file validated within budget; `iterations` (mean iterations to green over solved samples) is the error-quality metric this eval exists to track: better validator output means fewer round trips.

Run manually (not part of pytest/CI):

    uv run inspect eval evals/error_quality/task.py --model <model>
"""

import re
import tempfile
from pathlib import Path

from inspect_ai import Task, task
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.model import get_model
from inspect_ai.scorer import (
    Metric,
    SampleScore,
    Score,
    Scorer,
    Target,
    accuracy,
    metric,
    scorer,
)
from inspect_ai.solver import Generate, Solver, TaskState, solver
from inspect_ranges.schema import validate_range

FIXTURES = sorted((Path(__file__).parent / "fixtures").glob("broken-*.yaml"))

PROMPT = """You are fixing a `range.yaml` cyber range definition that failed validation.

Current file:

```yaml
{yaml}
```

Validator output:

```
{report}
```

Return the complete corrected file in a single ```yaml code fence. Fix every reported issue with the smallest possible change, and preserve everything that is not implicated.
"""


def _validate(text: str) -> tuple[bool, str]:
    """Validate YAML text, returning validity and the rendered report."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "range.yaml"
        path.write_text(text)
        report = validate_range(path)
        return report.valid, report.render()


def _extract_yaml(completion: str) -> str | None:
    """Pull the last fenced YAML block out of a model completion."""
    blocks = re.findall(r"```(?:yaml)?\n(.*?)```", completion, flags=re.DOTALL)
    return blocks[-1] if blocks else None


@solver
def fix_loop(max_iterations: int) -> Solver:
    """Iteratively repair the sample's YAML using only validator output as feedback."""

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        model = get_model()
        text = state.input_text
        valid, rendered = _validate(text)
        iterations = 0
        while not valid and iterations < max_iterations:
            result = await model.generate(PROMPT.format(yaml=text, report=rendered))
            text = _extract_yaml(result.completion) or text
            iterations += 1
            valid, rendered = _validate(text)
        state.store.set("valid", valid)
        state.store.set("iterations", iterations)
        state.store.set("final", text)
        return state

    return solve


@metric
def iterations() -> Metric:
    """Mean iterations to green over solved samples (lower is better validator output)."""

    def compute(scores: list[SampleScore]) -> float:
        solved = [
            score.score.metadata["iterations"]
            for score in scores
            if score.score.metadata is not None and score.score.value == 1.0
        ]
        return sum(solved) / len(solved) if solved else float("nan")

    return compute


@scorer(metrics=[accuracy(), iterations()])
def fixed_within_budget() -> Scorer:
    """Score 1.0 when the file validated within the iteration budget."""

    async def score(state: TaskState, target: Target) -> Score:
        valid = bool(state.store.get("valid"))
        count = int(state.store.get("iterations", 0))
        return Score(
            value=1.0 if valid else 0.0,
            answer=f"{count} iteration{'s' if count != 1 else ''}",
            metadata={"iterations": count},
        )

    return score


@task
def error_quality(max_iterations: int = 5) -> Task:
    """Fix seeded-broken range.yaml fixtures given only validator output."""
    samples = [Sample(id=path.stem, input=path.read_text()) for path in FIXTURES]
    return Task(
        dataset=MemoryDataset(samples),
        solver=fix_loop(max_iterations),
        scorer=fixed_within_budget(),
    )
