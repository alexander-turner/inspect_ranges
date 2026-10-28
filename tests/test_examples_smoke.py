"""The examples smoke task: one eval spanning the Linux example ranges through per-sample sandboxes."""

from inspect_ai._util.registry import registry_lookup
from inspect_ai.util import SandboxEnvironmentSpec
from inspect_ranges._challenges.dataset import CHALLENGE_METADATA_KEY
from inspect_ranges.examples import examples_smoke
from inspect_ranges.examples._smoke.task import EXAMPLES, LINUX_EXAMPLES


def test_each_sample_boots_its_own_examples_range() -> None:
    """One sample per Linux example by default, ids prefixed with the example, each naming its example's range as its sandbox while the task declares none."""
    task = examples_smoke()
    samples = list(task.dataset)
    assert task.sandbox is None
    assert [str(sample.id).partition(":")[0] for sample in samples] == list(
        LINUX_EXAMPLES
    )
    for name, sample in zip(LINUX_EXAMPLES, samples, strict=True):
        assert sample.sandbox == SandboxEnvironmentSpec(
            "range", str(EXAMPLES / f"_{name}" / "range.yaml")
        )
        assert CHALLENGE_METADATA_KEY in (sample.metadata or {})


def test_per_example_all_takes_every_challenge_with_unique_ids() -> None:
    samples = list(examples_smoke(per_example="all").dataset)
    assert len(samples) == 10  # 3 + 1 + 1 + 4 + 1
    assert len({sample.id for sample in samples}) == len(samples)
    assert len(list(examples_smoke(per_example=2).dataset)) == 7


def test_smoke_task_is_registered_under_the_package_name() -> None:
    assert registry_lookup("task", "inspect_ranges/examples_smoke") is not None
