"""Per-sample variable draws (variable-draws-v0.md).

A variable marked `draw: boot` gets a per-sample value drawn here, deterministically from a recorded seed, and delivered to guests as a JSON file in each Linux guest's cloud-init seed (`DRAWS_GUEST_PATH`). Draws never participate in planning, builds, or build keys: the build substitutes defaults, and a drawn value exists only in the sample's rendered bundle, its handle, and its evidence record. The draw domain always excludes the declared default (validation guarantees it is non-empty), so a drawn variable never realizes the checked-in value.

Determinism contract: `draw_variables` is a pure function of (variables, seed). The seed is recorded with the drawn values on the `draws` evidence stream, so a recorded sample's draws are reproducible post-hoc; changing the algorithm breaks that reproduction, so treat it as a wire-format-class contract.
"""

import random
from collections.abc import Mapping

from ..types import Variable

DRAWS_GUEST_PATH = "/etc/inspect-ranges/draws.json"
"""Where the draws file lands in every Linux guest except the agent's foothold: a JSON mapping of variable name to drawn value, written by cloud-init `write_files` from the rendered seed. Range-authored boot units read it to apply draws. The foothold is excluded because a drawn value is often a challenge's expected answer, and a readable file on the agent's own box would hand it over."""


def draw_variables(
    variables: Mapping[str, Variable], seed: str
) -> dict[str, int | str]:
    """Draw a value for every `draw: boot` variable, deterministically from `seed`.

    Each variable draws from its own `random.Random` seeded with `seed` and the variable's name, so adding or removing one variable never shifts another's draw. `port` and `int` draw uniformly from `Variable.draw_bounds` and `choice` uniformly from `choices`, in every case excluding the declared default. Variables without `draw: boot` are absent from the result.

    Args:
        variables: The spec's declared variables (validated, so drawn variables satisfy the drawability rules).
        seed: The recorded per-sample seed the draws derive from.

    Returns:
        Drawn values by variable name; empty when nothing declares `draw: boot`.
    """
    drawn: dict[str, int | str] = {}
    for name in sorted(variables):
        variable = variables[name]
        if variable.draw != "boot":
            continue
        rng = random.Random(f"{seed}:{name}")
        if variable.type == "choice":
            assert variable.choices is not None  # validated
            candidates = [c for c in variable.choices if c != variable.default]
            drawn[name] = rng.choice(candidates)
        else:
            assert isinstance(variable.default, int)  # validated
            low, high = variable.draw_bounds()
            if low <= variable.default <= high:
                value = low + rng.randrange(high - low)
                drawn[name] = value + 1 if value >= variable.default else value
            else:
                drawn[name] = low + rng.randrange(high - low + 1)
    return drawn
