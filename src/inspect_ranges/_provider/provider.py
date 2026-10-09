"""`LibvirtRangeSandboxEnvironment`: the Inspect sandbox provider for libvirt ranges.

Lifecycle per provider-v1.md: boot per sample (per-sample render with a leased CID base, explicit project name, `up` in a worker thread), environments keyed by guest name with the attacker first (the first key is Inspect's default sandbox), teardown deferred to `task_cleanup` for interrupted samples (the Docker convention; an interrupted range stays booted but hypervisor-isolated and egress-controlled until run end), `cleanup=False` honored by leaving ranges up with the recovery commands logged, and `cli_cleanup` driving entirely from on-disk state in a fresh process. Teardown and cleanup paths never retry; acquisition (render plus up) gets one layer-3 respin with a FRESH project name on transient stages.

The op surface (`exec`, `read_file`, `write_file`) lands in slice 3 of the phase; until then the methods raise `NotImplementedError`.
"""

import asyncio
import logging
import shutil
from pathlib import Path
from typing import Any, Literal, cast, overload

from inspect_ai.util._sandbox.environment import (
    SandboxConnection,
    SandboxEnvironment,
    SandboxEnvironmentConfigType,
)
from inspect_ai.util._sandbox.registry import sandboxenv
from inspect_ai.util._subprocess import ExecResult
from pydantic import BaseModel
from typing_extensions import override

from .._compiler.plan import ResolvedPlan, resolve_plan
from .._runtime.ownership import (
    list_projects,
    read_owner,
    remove_project,
    write_owner,
)
from .._runtime.up import UpError, UpOptions, UpResult
from ..schema import load_range, revalidate_range
from ..types import RangeSpec
from .admission import default_max_sandboxes
from .naming import sample_project
from .ops import provider_exec, provider_read_file, provider_write_file
from .state import ProviderRuntime, SampleHandle, provider_runtime

logger = logging.getLogger("inspect_ranges.provider")

TRANSIENT_UP_STAGES = frozenset({"range-container", "guest-boot", "readiness"})
"""Acquisition stages worth one respin: docker and boot flakes, and the readiness timeout (the one re-boot). Verification and preparation failures are permanent (a bad bundle or missing image never improves on retry)."""


def _resolve_spec(config: SandboxEnvironmentConfigType | None) -> RangeSpec:
    """The sample's `RangeSpec` from either config form, revalidated at this consumer boundary."""
    if isinstance(config, str):
        return load_range(Path(config))
    if isinstance(config, RangeSpec):
        return revalidate_range(config)
    if isinstance(config, BaseModel):
        raise TypeError(
            f"libvirt_range config must be a RangeSpec or a range.yaml path, "
            f"got {type(config).__name__}"
        )
    raise ValueError(
        "libvirt_range requires a config: a range.yaml path or a RangeSpec object"
    )


def _default_guest(spec: RangeSpec) -> str:
    """The default sandbox: the attacker's foothold host, or the attacker box itself."""
    return spec.attacker.host or spec.attacker.name


@sandboxenv(name="libvirt_range")  # pyright: ignore[reportUntypedClassDecorator]
class LibvirtRangeSandboxEnvironment(SandboxEnvironment):
    """One guest of one sample's range, driven over the vsock channel."""

    def __init__(self, guest: str, handle: SampleHandle) -> None:
        super().__init__()
        self._guest = guest
        self._handle = handle

    # -- config ---------------------------------------------------------------

    @classmethod
    @override
    def config_files(cls) -> list[str]:
        # "range.yaml" only: no compose.yaml here, so is_docker_compatible()
        # stays False and config_deserialize is never bypassed
        return ["range.yaml"]

    @classmethod
    @override
    def config_deserialize(cls, config: dict[str, Any]) -> BaseModel:
        # load-bearing for the typed config's eval-log round trip
        return RangeSpec.model_validate(config)

    @classmethod
    @override
    def default_concurrency(cls) -> int | None:
        return default_max_sandboxes()

    # -- lifecycle ------------------------------------------------------------

    @classmethod
    @override
    async def task_init(
        cls, task_name: str, config: SandboxEnvironmentConfigType | None
    ) -> None:
        """Validate the config once and resolve the plan so a broken range fails at startup, not per sample."""
        runtime = provider_runtime()
        if isinstance(config, (str, RangeSpec)):
            spec, plan = runtime.resolve_config(config, lambda: _resolve_spec(config))
        else:
            spec = _resolve_spec(config)
            plan = resolve_plan(spec, runtime.plan_options())
        del spec
        logger.info(
            "task_init %s: range %s (%d guests, %d vCPUs, %d MiB)",
            task_name,
            plan.range.name,
            plan.totals.guests,
            plan.totals.cpus,
            plan.totals.memory_mb,
        )

    @classmethod
    @override
    async def sample_init(
        cls,
        task_name: str,
        config: SandboxEnvironmentConfigType | None,
        metadata: dict[str, str],
    ) -> dict[str, SandboxEnvironment]:
        runtime = provider_runtime()
        # inspect-ai injects int ids for default datasets: always stringify
        sample_id = str(metadata.get("__sample_id__", "sample"))
        cache_key = config if isinstance(config, (str, RangeSpec)) else None
        if cache_key is not None:
            spec, plan = runtime.resolve_config(
                cache_key, lambda: _resolve_spec(config)
            )
        else:
            spec = _resolve_spec(config)
            plan = resolve_plan(spec, runtime.plan_options())

        await runtime.admission.acquire(plan.totals)
        handle: SampleHandle | None = None
        try:
            handle = await cls._acquire_range(runtime, spec, plan, task_name, sample_id)
        except BaseException:
            await runtime.admission.release(plan.totals)
            raise
        handle.admission_charged = True

        try:
            assert handle.channel is not None
            for guest in handle.guest_cids:
                await handle.channel.ping(guest)
                # the per-guest session id pin lands with the protocol's
                # session field (slice 4); the ping stands as the provider's
                # own liveness confirmation until then
        except BaseException as failure:
            # the ping diagnosis stays primary; a teardown failure chains
            # underneath it, never substitutes
            try:
                await cls._destroy(runtime, handle)
            except Exception as teardown_error:
                raise failure from teardown_error
            raise

        default = _default_guest(spec)
        ordered = [default, *(name for name in handle.guest_cids if name != default)]
        return {name: cls(name, handle) for name in ordered}

    @classmethod
    async def _acquire_range(
        cls,
        runtime: ProviderRuntime,
        spec: RangeSpec,
        plan: ResolvedPlan,
        task_name: str,
        sample_id: str,
    ) -> SampleHandle:
        """Lease, render, and boot one range; one respin with fresh identity on transient stages.

        On every failure path the attempt's lease, staging, registry entry, and any
        partially created project are unwound before the error (or the respin) proceeds.
        """
        attempts = max(1, runtime.retry_config.up_attempts)
        last_error: UpError | None = None
        for attempt in range(1, attempts + 1):
            project = sample_project(spec.meta.name, sample_id)
            # the allocator takes a blocking cross-process flock: off the loop.
            # A cancellation landing between this lease and the registry line
            # below leaves only the lease on disk; cli_cleanup recovers it
            # (leases are a provider-origin marker by construction).
            lease = await asyncio.to_thread(
                runtime.allocator.lease, project, plan.totals.guests
            )
            staging = runtime.staging_root() / project
            handle = SampleHandle(
                project=project,
                task_name=task_name,
                staging=staging,
                totals=plan.totals,
                cid_base=lease.base,
                retry=runtime.retry_config,
            )
            # registered before anything renders or boots: a crash from here on
            # is findable by task_cleanup (registry) and cli_cleanup (lease)
            runtime.registry[handle.project] = handle
            unwound = False

            async def unwind_once(target: SampleHandle = handle) -> None:
                # default-bound (B023): the closure must act on THIS
                # iteration's handle even though respins rebind the name
                nonlocal unwound
                if not unwound:
                    unwound = True
                    await cls._unwind_attempt(runtime, target)

            try:
                # render runs in a worker thread and is not abortable either:
                # drain it on cancellation the same way as the boot below
                render = asyncio.ensure_future(
                    asyncio.to_thread(
                        runtime.render_fn,
                        spec,
                        staging / "bundle",
                        runtime.plan_options(cid_base=lease.base),
                    )
                )
                boot: asyncio.Future[UpResult] | None = None
                try:
                    await asyncio.shield(render)
                    boot = asyncio.ensure_future(
                        asyncio.to_thread(
                            runtime.up_fn,
                            staging / "bundle",
                            UpOptions(
                                project=project,
                                image_cache=runtime.image_cache,
                                state_dir=runtime.state_dir,
                            ),
                        )
                    )
                    result: UpResult = await asyncio.shield(boot)
                except asyncio.CancelledError:
                    # neither thread can be aborted and both keep creating
                    # resources; drain them (up is internally bounded) so the
                    # unwind sees everything the attempt created, then
                    # propagate the cancellation. The drain itself tolerates a
                    # second cancellation: the unwind must still run exactly
                    # once.
                    pending = [
                        cast("asyncio.Future[object]", f)
                        for f in (render, boot)
                        if f is not None
                    ]
                    try:
                        await asyncio.shield(
                            asyncio.gather(*pending, return_exceptions=True)
                        )
                    except asyncio.CancelledError:
                        pass
                    finally:
                        await unwind_once()
                    raise
            except asyncio.CancelledError:
                raise  # already unwound above; never unwind twice
            except UpError as error:
                await unwind_once()
                if error.stage in TRANSIENT_UP_STAGES and attempt < attempts:
                    last_error = error
                    logger.warning(
                        "acquisition respin: project=%s stage=%s error=%s "
                        "(fresh identity for attempt %d/%d)",
                        project,
                        error.stage,
                        error,
                        attempt + 1,
                        attempts,
                    )
                    continue
                raise
            except BaseException:
                await unwind_once()
                raise
            handle.booted = True
            try:
                handle.guest_cids = {state.name: state.cid for state in result.guests}
                handle.channel = runtime.channel_factory(handle.guest_cids, project)
                cls._mark_provider_owned(runtime, handle, sample_id)
            except BaseException as failure:
                # the range is BOOTED: a post-boot failure destroys it rather
                # than leaving it running until task_cleanup while the sample's
                # admission charge is already refunded
                try:
                    await cls._destroy(runtime, handle)
                except Exception as teardown_error:
                    raise failure from teardown_error
                raise
            return handle
        raise last_error if last_error is not None else AssertionError("unreachable")

    @classmethod
    def _mark_provider_owned(
        cls, runtime: ProviderRuntime, handle: SampleHandle, sample_id: str
    ) -> None:
        """Enrich the owner record `up` wrote with provider-origin fields (fresh-process cleanup reads them)."""
        record = read_owner(runtime.state_dir, handle.project)
        if record is None:
            return
        write_owner(
            runtime.state_dir,
            record.model_copy(
                update={
                    "origin": "provider",
                    "sample_id": sample_id,
                    "cid_base": handle.cid_base,
                }
            ),
        )

    @classmethod
    async def _unwind_attempt(
        cls, runtime: ProviderRuntime, handle: SampleHandle
    ) -> None:
        """Unwind one failed acquisition attempt: project (best effort), lease, staging, registry."""
        try:
            # up tears its own project down on failure; this is belt-and-braces
            # for crashes between resource creation and up's own cleanup
            await asyncio.to_thread(runtime.down_fn, handle.project, runtime.state_dir)
        except Exception as error:
            logger.warning(
                "unwind: down of failed attempt %s failed (left for task_cleanup): %s",
                handle.project,
                error,
            )
            return  # keep lease and registry so the sweep can still find it
        await asyncio.to_thread(runtime.allocator.release, handle.project)
        shutil.rmtree(handle.staging, ignore_errors=True)
        runtime.registry.pop(handle.project, None)

    @classmethod
    async def _destroy(cls, runtime: ProviderRuntime, handle: SampleHandle) -> None:
        """Tear one sample down: single attempt, no retry.

        Leases, the registry entry, and the admission charge are released only AFTER a successful teardown: a failed `down` means the VMs still hold their CIDs and resources, so freeing them would hand live CIDs to the next sample. A failed handle stays findable (registry for `task_cleanup`, lease plus the provider-marked owner record for `cli_cleanup`).
        """
        await asyncio.to_thread(runtime.down_fn, handle.project, runtime.state_dir)
        await asyncio.to_thread(runtime.allocator.release, handle.project)
        shutil.rmtree(handle.staging, ignore_errors=True)
        runtime.registry.pop(handle.project, None)
        if handle.admission_charged:
            handle.admission_charged = False
            await runtime.admission.release(handle.totals)

    @classmethod
    @override
    async def sample_cleanup(
        cls,
        task_name: str,
        config: SandboxEnvironmentConfigType | None,
        environments: dict[str, SandboxEnvironment],
        interrupted: bool,
    ) -> None:
        runtime = provider_runtime()
        handles = {
            env._handle.project: env._handle  # pyright: ignore[reportPrivateUsage]
            for env in environments.values()
            if isinstance(env, LibvirtRangeSandboxEnvironment)
        }
        for handle in handles.values():
            if interrupted:
                # deferred to task_cleanup (the Docker convention): the range
                # stays booted but hypervisor-isolated and egress-controlled
                # until run end, so interrupted samples never stall cancellation
                handle.deferred = True
                logger.info(
                    "sample interrupted: teardown of %s deferred to task_cleanup",
                    handle.project,
                )
                continue
            await cls._destroy(runtime, handle)

    @classmethod
    @override
    async def task_cleanup(
        cls, task_name: str, config: SandboxEnvironmentConfigType | None, cleanup: bool
    ) -> None:
        runtime = provider_runtime()
        remaining = list(runtime.registry.values())
        if not cleanup:
            for handle in remaining:
                logger.warning(
                    "range %s left up (--no-sandbox-cleanup); remove it with: "
                    "inspect-ranges down %s  (or: inspect sandbox cleanup libvirt_range %s)",
                    handle.project,
                    handle.project,
                    handle.project,
                )
            return
        failures: list[str] = []
        for handle in remaining:
            try:
                await cls._destroy(runtime, handle)
            except Exception as error:
                failures.append(f"{handle.project}: {error}")
        if failures:
            raise RuntimeError(
                "task_cleanup could not tear down every range (retry with "
                "'inspect sandbox cleanup libvirt_range'):\n  " + "\n  ".join(failures)
            )

    @classmethod
    @override
    async def cli_cleanup(cls, id: str | None) -> None:
        """Fresh-process cleanup from on-disk state: provider-origin projects only.

        Provider origin is the union of the CID lease registry (written before anything boots, so it covers crash windows) and owner records marked `origin="provider"`.
        """
        runtime = provider_runtime()  # fresh process: the fallback runtime, real seams
        leased = set(await asyncio.to_thread(runtime.allocator.leased_projects))
        marked = {
            project
            for project in list_projects(runtime.state_dir)
            if (record := read_owner(runtime.state_dir, project)) is not None
            and record.origin == "provider"
        }
        targets = sorted(leased | marked)
        if id is not None:
            targets = [project for project in targets if project == id]
        failures: list[str] = []
        for project in targets:
            try:
                await asyncio.to_thread(runtime.down_fn, project, runtime.state_dir)
            except Exception as error:
                failures.append(f"{project}: {error}")
                continue
            await asyncio.to_thread(runtime.allocator.release, project)
            remove_project(runtime.state_dir, project)
            shutil.rmtree(runtime.staging_root() / project, ignore_errors=True)
        # no blanket prune: leases outside `targets` may belong to a
        # concurrently running eval (or to an entry this version cannot
        # parse); successful targets were released individually above and
        # failed ones must stay findable
        if failures:
            raise RuntimeError(
                "cli_cleanup could not tear down every project:\n  "
                + "\n  ".join(failures)
            )

    # -- the op surface (slice 3) ---------------------------------------------

    @override
    async def exec(
        self,
        cmd: list[str],
        input: str | bytes | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        user: str | None = None,
        timeout: int | None = None,
        timeout_retry: bool = True,
        concurrency: bool = True,
    ) -> ExecResult[str]:
        """Run `cmd` in this guest over the channel.

        `timeout` is enforced in-guest (the daemon's process-tree kill), so a timed-out command genuinely timed out; `timeout_retry` is therefore advisory and ignored, the inspect_k8s_sandbox stance: re-running a command that hit its deadline is destructive in a range, and the transient-infrastructure class Docker's re-run ladder exists for is handled by the provider's layered retry instead. `concurrency` applies to local sandboxes only and is ignored. Transient infrastructure failures retry with fresh request ids; per the k8s caveat quoted in `retry.py`, a command that partially executed before such a failure may run again.
        """
        del timeout_retry, concurrency  # advisory; see the docstring
        return await provider_exec(
            self._handle, self._guest, cmd, input, cwd, env, user, timeout
        )

    @override
    async def write_file(self, file: str, contents: str | bytes) -> None:
        """Write `contents` to `file` (relative paths join the per-sample working directory); parent directories are created."""
        await provider_write_file(self._handle, self._guest, file, contents)

    @overload
    async def read_file(self, file: str, text: Literal[True] = True) -> str: ...

    @overload
    async def read_file(self, file: str, text: Literal[False]) -> bytes: ...

    @override
    async def read_file(self, file: str, text: bool = True) -> str | bytes:
        """Read `file` (capped at the per-call `MAX_READ_FILE_SIZE`); strict UTF-8 decode in text mode."""
        data = await provider_read_file(self._handle, self._guest, file)
        return data.decode("utf-8") if text else data

    @override
    async def connection(self, *, user: str | None = None) -> SandboxConnection:
        raise NotImplementedError(
            "libvirt_range provides no interactive connection yet (a console "
            "command is a recorded follow-up in provider-v1.md)"
        )
