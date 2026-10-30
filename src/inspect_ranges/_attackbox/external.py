"""An attack-box provider that is a separate program: `<program> attackbox boot|teardown|probe`, protocol version 1.

The program owns the box. This side imports none of its code: each verb is one subprocess whose stdin carries one JSON request and whose stdout carries one JSON reply, and the tap fds cross through `pass_fds` at the numbers the request names. Every reply is untrusted input, so anything but exactly one JSON object carrying `"protocol": 1` refuses.
"""

import asyncio
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from .._channel.vsock import HybridEndpoint
from .backend import AttackBoxHandle, FootholdAttachment

PROTOCOL_VERSION = 1

DEFAULT_TIMEOUT_S = 600.0
"""The bound on `teardown` and `probe`; `boot` is bounded by the realizer's readiness timeout instead."""

_STDERR_TAIL = 2000


class ExternalBoxError(RuntimeError):
    """A refusal from or about the external program, in the shape of the protocol's error object."""

    def __init__(
        self,
        cause: str,
        *,
        remedy: str | None = None,
        report_url: str | None = None,
        hint: str | None = None,
    ) -> None:
        self.cause = cause
        self.remedy = remedy
        """The exact command that closes a host gap (for example the runtime's `sudo ... setup` line), when there is one."""
        self.report_url = report_url
        """Where to report a state only a bug in the program can reach."""
        self.hint = hint
        """A last line naming the caller's own way out (the built-in box), absent where none applies."""
        super().__init__("\n".join([*self.detail_lines(), *([hint] if hint else [])]))

    def detail_lines(self) -> list[str]:
        """The cause, then the remedy and the report URL when present."""
        lines = [self.cause]
        if self.remedy:
            lines.append(f"remedy: {self.remedy}")
        if self.report_url:
            lines.append(f"report this bug at: {self.report_url}")
        return lines

    def with_hint(self, hint: str) -> "ExternalBoxError":
        """The same refusal with `hint` as its last line."""
        return ExternalBoxError(
            self.cause, remedy=self.remedy, report_url=self.report_url, hint=hint
        )


def parse_reply(text: str, verb: str) -> dict[str, Any]:
    """One verb's stdout as a protocol reply.

    Raises:
        ExternalBoxError: The text is not exactly one JSON object, or its `protocol` is not 1.
    """
    try:
        decoded: Any = json.loads(text)
    except json.JSONDecodeError as error:
        raise ExternalBoxError(
            f"`attackbox {verb}` did not print exactly one JSON object ({error.msg})"
        ) from error
    if not isinstance(decoded, dict):
        raise ExternalBoxError(
            f"`attackbox {verb}` printed a JSON {type(decoded).__name__}, not an object"
        )
    reply = cast(dict[str, Any], decoded)
    version: Any = reply.get("protocol")
    # `type(...) is int` because `True == 1` in Python
    if type(version) is not int or version != PROTOCOL_VERSION:
        raise ExternalBoxError(
            f"`attackbox {verb}` speaks protocol {version!r}; inspect-ranges "
            f"speaks protocol {PROTOCOL_VERSION} only"
        )
    return reply


def _optional_str(error: dict[str, Any], key: str) -> str | None:
    value = error.get(key)
    if value is None or isinstance(value, str):
        return value
    raise ExternalBoxError(f"the error object's {key!r} is not a string or null")


def _error_from(reply: dict[str, Any], verb: str) -> ExternalBoxError:
    """The reply's error object as an exception (a malformed one is itself the refusal)."""
    raw: Any = reply["error"]
    malformed = ExternalBoxError(
        f"`attackbox {verb}` replied with a malformed error object: {raw!r}"
    )
    if not isinstance(raw, dict):
        return malformed
    error = cast(dict[str, Any], raw)
    cause: Any = error.get("cause")
    if not isinstance(cause, str):
        return malformed
    try:
        return ExternalBoxError(
            cause,
            remedy=_optional_str(error, "remedy"),
            report_url=_optional_str(error, "report_url"),
        )
    except ExternalBoxError as malformed:
        return malformed


class ExternalProgramProvider:
    """An `AttackBoxProvider` that runs `<program> attackbox <verb>` for each lifecycle step.

    `program` resolves the executable when a verb first needs it, never at construction, so a factory that builds this stays cheap; it raises `ExternalBoxError` when no usable program exists.
    """

    def __init__(
        self,
        program: Callable[[], Path],
        *,
        builtin_hint: str,
        timeout_s: float = DEFAULT_TIMEOUT_S,
    ) -> None:
        self._program = program
        self._builtin_hint = builtin_hint
        self._timeout_s = timeout_s

    async def boot(self, attachment: FootholdAttachment) -> AttackBoxHandle:
        """Boot the box behind the attachment's taps; the program owns the fds from this call on.

        Raises:
            ExternalBoxError: The program is unavailable, refused, or replied outside the protocol; the message ends with the way back to the built-in box.
        """
        fds = tuple(interface.tap_fd for interface in attachment.interfaces)
        if any(fd < 3 for fd in fds):
            raise ExternalBoxError(
                f"tap fds {fds} include a standard stream number, which the "
                "program's stdin, stdout, and stderr already hold"
            )
        request = {
            "protocol": PROTOCOL_VERSION,
            "project": attachment.project,
            "guest_name": attachment.guest_name,
            "cid": attachment.cid,
            "cpus": attachment.cpus,
            "memory_mb": attachment.memory_mb,
            "seed_dir": str(attachment.seed_dir) if attachment.seed_dir else None,
            "interfaces": [
                {
                    "segment": interface.segment,
                    "bridge": interface.bridge,
                    "fd": interface.tap_fd,
                    "mac": interface.mac,
                    "ip": str(interface.ip),
                    "prefixlen": interface.prefixlen,
                    "gateway": str(interface.gateway) if interface.gateway else None,
                }
                for interface in attachment.interfaces
            ],
        }
        try:
            program = await asyncio.to_thread(self._program)
            # the realizer bounds boot (and cancels on its timeout), so no
            # second bound here
            reply = await self._call(program, "boot", request, fds, timeout_s=None)
            return _handle_from(reply)
        except ExternalBoxError as error:
            raise error.with_hint(self._builtin_hint) from error

    async def teardown(self, project: str, reclaim_token: str) -> None:
        """Tear down every box of `project`; a box that is absent is success.

        Raises:
            ExternalBoxError: The program is unavailable, refused, or replied outside the protocol.
        """
        program = await asyncio.to_thread(self._program)
        # no guest_name: the protocol then tears down every box of the project,
        # which is what a teardown with no boot facts (an empty token) needs
        request = {
            "protocol": PROTOCOL_VERSION,
            "project": project,
            "reclaim_token": reclaim_token,
        }
        await self._call(program, "teardown", request, (), timeout_s=self._timeout_s)

    def probe(self) -> None:
        """Whether this host can boot a box now; starts no VM. Blocking: call it off the event loop.

        Raises:
            ExternalBoxError: The program is unavailable, or answered that this host cannot boot a box (with the program's cause, remedy, and report URL).
        """
        program = self._program()
        asyncio.run(self._call(program, "probe", None, (), timeout_s=self._timeout_s))

    def doctor_probe(self) -> str | None:
        """`probe` in the doctor shape: `None` when healthy, else the failure detail."""
        try:
            self.probe()
        except ExternalBoxError as error:
            return "; ".join(error.detail_lines())
        return None

    @staticmethod
    async def _call(
        program: Path,
        verb: str,
        request: dict[str, Any] | None,
        fds: tuple[int, ...],
        *,
        timeout_s: float | None,
    ) -> dict[str, Any]:
        """Run one verb and return its success reply; any error object, exit failure, or protocol breach raises."""
        try:
            process = await asyncio.create_subprocess_exec(
                str(program),
                "attackbox",
                verb,
                stdin=asyncio.subprocess.PIPE
                if request is not None
                else asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                pass_fds=fds,
            )
        except OSError as error:
            raise ExternalBoxError(
                f"`{program} attackbox {verb}` did not start: {error}"
            ) from error
        data = json.dumps(request).encode() if request is not None else None
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(data), timeout=timeout_s
            )
        except TimeoutError as error:
            raise ExternalBoxError(
                f"`{program} attackbox {verb}` did not answer within {timeout_s}s"
            ) from error
        finally:
            # a timeout or a cancellation must not leave the verb running
            # behind a caller that has moved on (a boot racing its teardown)
            if process.returncode is None:
                process.kill()
                await process.wait()
        status = process.returncode
        try:
            reply = parse_reply(stdout.decode(errors="replace"), verb)
        except ExternalBoxError as error:
            if status == 0:
                raise
            # the program's own words lead: a release that predates the
            # protocol says here that `attackbox` is not one of its commands
            tail = stderr.decode(errors="replace")[-_STDERR_TAIL:].strip()
            raise ExternalBoxError(
                f"{tail or '(no stderr)'} (`{program} attackbox {verb}` exited "
                f"{status} with no protocol reply)"
            ) from error
        if "error" in reply:
            raise _error_from(reply, verb)
        if status != 0:
            raise ExternalBoxError(
                f"`{program} attackbox {verb}` exited {status} without an error object"
            )
        if verb == "probe" and reply.get("ok") is not True:
            raise ExternalBoxError(
                f"`attackbox probe` answered ok={reply.get('ok')!r} with no error object"
            )
        return reply


def _handle_from(reply: dict[str, Any]) -> AttackBoxHandle:
    """The boot reply as the seam's handle.

    Raises:
        ExternalBoxError: A field is missing or has the wrong shape.
    """
    socket_path: Any = reply.get("exec_socket")
    uid: Any = reply.get("exec_uid")
    token: Any = reply.get("reclaim_token")
    if not isinstance(socket_path, str) or not Path(socket_path).is_absolute():
        raise ExternalBoxError(
            f"`attackbox boot` replied exec_socket={socket_path!r}, not an absolute path"
        )
    if type(uid) is not int or uid < 0:
        raise ExternalBoxError(f"`attackbox boot` replied exec_uid={uid!r}, not a uid")
    if not isinstance(token, str):
        raise ExternalBoxError(
            f"`attackbox boot` replied reclaim_token={token!r}, not a string"
        )
    return AttackBoxHandle(
        exec_endpoint=HybridEndpoint(Path(socket_path), uid), reclaim_token=token
    )
