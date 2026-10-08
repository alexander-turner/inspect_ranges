"""Runs the slice 0 API checkpoint: both config forms, hook order, discovery, log round-trip.

Run from the repo root: `uv run python design/spikes/inspect-api-check/run_check.py`. Writes its JSONL evidence to design/spikes/inspect-api-check/tmp/.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

SPIKE = Path(__file__).parent
sys.path.insert(0, str(SPIKE.parent))

LOG = SPIKE / "tmp" / "api-check.jsonl"
os.environ["API_CHECK_LOG"] = str(LOG)

from inspect_ai import Task, eval as inspect_eval  # noqa: E402
from inspect_ai.dataset import Sample  # noqa: E402
from inspect_ai.log import read_eval_log  # noqa: E402
from inspect_ai.scorer import includes  # noqa: E402

from inspect_ranges.types import (  # noqa: E402
    Attacker,
    Host,
    Interface,
    Network,
    Os,
    RangeMeta,
    RangeSpec,
)

sys.path.insert(0, str(SPIKE))
from provider import ApiCheckSandboxEnvironment  # noqa: E402, F401
from task import probe  # noqa: E402


def events() -> list[dict[str, object]]:
    if not LOG.exists():
        return []
    return [json.loads(line) for line in LOG.read_text().splitlines()]


def reset() -> None:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    LOG.write_text("")


def make_task(sandbox_config: object) -> Task:
    return Task(
        dataset=[Sample(input="probe", target="resolved")],
        solver=probe(),
        scorer=includes(),
        sandbox=("libvirt_range", sandbox_config),  # type: ignore[arg-type]
        name="api_check",
    )


def spec() -> RangeSpec:
    return RangeSpec(
        meta=RangeMeta(name="api-check", description="API checkpoint range."),
        networks=[Network(name="lab", cidr="10.10.10.0/24", mode="isolated")],
        hosts=[
            Host(
                name="web",
                os=Os(type="linux"),
                image="acme/web-golden",
                interfaces=[Interface(network="lab")],
            )
        ],
        attacker=Attacker(interfaces=[Interface(network="lab")], entry="external"),
    )


def check(name: str, ok: bool, detail: str = "") -> bool:
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))
    return ok


def hook_order(evts: list[dict[str, object]]) -> list[object]:
    order = [e["event"] for e in evts if e["event"] != "config_files"]
    return order


results: list[bool] = []

# 1. file-path config form
reset()
yaml_path = str(SPIKE / "range.yaml")
logs = inspect_eval(make_task(yaml_path), model="mockllm/model", log_dir=str(SPIKE / "tmp" / "logs"))
evts = events()
results.append(check("path-config eval completes", logs[0].status == "success"))
results.append(
    check(
        "hook order (path form)",
        hook_order(evts)[:3] == ["task_init", "sample_init", "solver"]
        and hook_order(evts)[-2:] == ["sample_cleanup", "task_cleanup"],
        str(hook_order(evts)),
    )
)
results.append(
    check(
        "config passed through as str",
        any(str(e.get("config", "")).startswith("str:") for e in evts if e["event"] == "sample_init"),
    )
)

# 2. typed RangeSpec config form
reset()
logs = inspect_eval(make_task(spec()), model="mockllm/model", log_dir=str(SPIKE / "tmp" / "logs"))
evts = events()
results.append(check("typed-config eval completes", logs[0].status == "success"))
results.append(
    check(
        "config passed through as RangeSpec",
        any(e.get("config") == "RangeSpec:api-check" for e in evts if e["event"] == "sample_init"),
        str([e.get("config") for e in evts if e["event"] == "sample_init"]),
    )
)
solver_evt = next((e for e in evts if e["event"] == "solver"), None)
results.append(
    check(
        "named sandbox resolution",
        solver_evt is not None
        and solver_evt["web_guest"] == "web"
        and solver_evt["default_guest"] == "attacker"
        and solver_evt["distinct"] is True,
        "no solver event recorded" if solver_evt is None else "",
    )
)

# 3. eval-log round trip of the typed config: the reread config must BE a
# RangeSpec equal to the original, and config_deserialize must have fired
log_file = logs[0].location
reread = read_eval_log(log_file)
sb = reread.eval.sandbox
deserialized = any(e["event"] == "config_deserialize" for e in events())
results.append(
    check(
        "typed config survives the eval log",
        sb is not None
        and sb.type == "libvirt_range"
        and isinstance(sb.config, RangeSpec)
        and sb.config == spec()
        and deserialized,
        f"type={type(sb.config).__name__ if sb else None} deserialize_fired={deserialized}",
    )
)

# 4. config_files declared
results.append(
    check(
        "config_files",
        ApiCheckSandboxEnvironment.config_files() == ["range.yaml"],
    )
)

# 5. entry-point discovery: inspect_ai imports inspect_ranges._registry in a
# fresh process without any explicit import from user code
probe_code = (
    "import inspect_ai._util.entrypoints as ep; ep.ensure_entry_points(); "
    "import sys; print('inspect_ranges._registry' in sys.modules)"
)
out = subprocess.run(
    [sys.executable, "-c", probe_code], capture_output=True, text=True
)
results.append(
    check(
        "entry-point discovery imports _registry",
        out.stdout.strip() == "True",
        (out.stdout + out.stderr).strip()[:200],
    )
)

# 6. end to end: a provider registered ONLY by an entry-point module is
# discovered by a fresh eval process that never imports it. A throwaway
# dist-info supplies the entry point; the shim module imports the stub.
import shutil  # noqa: E402

site = SPIKE / "tmp" / "ep-site"
shutil.rmtree(site, ignore_errors=True)
dist_info = site / "apicheck_ep-0.0.0.dist-info"
dist_info.mkdir(parents=True)
(dist_info / "METADATA").write_text(
    "Metadata-Version: 2.1\nName: apicheck-ep\nVersion: 0.0.0\n"
)
(dist_info / "entry_points.txt").write_text("[inspect_ai]\napicheck_ep = apicheck_ep\n")
(site / "apicheck_ep.py").write_text(
    f"import sys\nsys.path.insert(0, {str(SPIKE)!r})\nimport provider  # noqa: F401  registers libvirt_range\n"
)
eval_script = site / "run_eval.py"
eval_script.write_text(
    "from inspect_ai import Task, eval as inspect_eval\n"
    "from inspect_ai.dataset import Sample\n"
    "from inspect_ai.solver import generate\n"
    f"task = Task(dataset=[Sample(input='x')], solver=generate(), sandbox=('libvirt_range', {str(SPIKE / 'range.yaml')!r}), name='ep_check')\n"
    f"log = inspect_eval(task, model='mockllm/model', log_dir={str(SPIKE / 'tmp' / 'logs')!r}, log_level='warning')[0]\n"
    "print('STATUS:' + log.status)\n"
)
ep_log = SPIKE / "tmp" / "ep-check.jsonl"
ep_log.unlink(missing_ok=True)
env = dict(os.environ, PYTHONPATH=str(site), API_CHECK_LOG=str(ep_log))
out = subprocess.run(
    [sys.executable, str(eval_script)], capture_output=True, text=True, env=env
)
ep_events = (
    [json.loads(line) for line in ep_log.read_text().splitlines()]
    if ep_log.exists()
    else []
)
results.append(
    check(
        "entry-point-registered provider drives a fresh eval",
        "STATUS:success" in out.stdout
        and any(e["event"] == "sample_init" for e in ep_events),
        (out.stdout + out.stderr).strip()[-200:],
    )
)

print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
