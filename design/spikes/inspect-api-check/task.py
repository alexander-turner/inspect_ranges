"""Smoke task for the API checkpoint: asserts sandbox resolution inside a real eval."""

from inspect_ai import Task, task
from inspect_ai.dataset import Sample
from inspect_ai.scorer import includes
from inspect_ai.solver import Generate, TaskState, solver
from inspect_ai.util import sandbox

from provider import ApiCheckSandboxEnvironment, record


@solver
def probe():
    async def solve(state: TaskState, generate: Generate) -> TaskState:
        default = sandbox()
        web = sandbox("web")
        # inspect hands solvers a proxy around the provider's environment;
        # unwrap to reach provider attributes
        inner_default = getattr(default, "_sandbox", default)
        inner_web = getattr(web, "_sandbox", web)
        record(
            "solver",
            proxy_type=type(default).__name__,
            default_guest=getattr(inner_default, "guest", None),
            web_guest=getattr(inner_web, "guest", None),
            distinct=inner_default is not inner_web,
        )
        state.output.completion = "resolved"
        return state

    return solve


@task
def api_check() -> Task:
    return Task(
        dataset=[Sample(input="probe", target="resolved")],
        solver=probe(),
        scorer=includes(),
    )
