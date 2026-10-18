"""The transfer UX: every long transfer renders the docker-pull shape (ratified 2026-10-17).

One line per blob keyed by short digest with explicit states (`Waiting`, `Downloading`/`Uploading` with a bar plus bytes, `Verifying`, `Complete`, and `Already exists` for dedup hits, which makes the layer-sharing economics visible), and a final `name@digest` line naming what was materialized. On a TTY the active line redraws in place; non-TTY contexts (CI logs, the provider's suspended display) degrade to periodic plain-text lines. Transfers in this codebase run sequentially, so lines appear in order; the concurrent-line rendering arrives with parallel streams if a later slice adds them. Failures are the caller's coded refusals, never a traceback under a half-drawn bar.

The event surface is deliberately tiny: stores and materialization call `BlobProgress` with a digest, a state, and byte counts; everything about rendering lives here.
"""

import sys
import time
from typing import Protocol, TextIO

__all__ = ["BlobProgress", "TransferDisplay"]


class BlobProgress(Protocol):
    """The event sink transfers call: `state` is one of `waiting`, `downloading`, `uploading`, `verifying`, `exists`, `done`."""

    def __call__(self, digest: str, state: str, done: int, total: int) -> None: ...


_BAR_WIDTH = 24
_PLAIN_INTERVAL_S = 5.0


def _human(count: int) -> str:
    size = float(count)
    for unit in ("B", "kB", "MB", "GB"):
        if size < 1000:
            return f"{size:.1f}{unit}" if unit != "B" else f"{int(size)}B"
        size /= 1000
    return f"{size:.1f}TB"


class TransferDisplay:
    """A sequential docker-pull-shaped renderer over the `BlobProgress` events."""

    def __init__(self, out: "TextIO | None" = None) -> None:
        self._out: TextIO = out if out is not None else sys.stderr
        self._tty = self._out.isatty()
        self._active: str | None = None
        self._last_plain = 0.0
        self._line_open = False

    def __call__(self, digest: str, state: str, done: int, total: int) -> None:
        short = digest.removeprefix("sha256:")[:12]
        if state == "exists":
            self._finish_line()
            self._out.write(f"{short}: Already exists\n")
            self._out.flush()
            return
        if state in ("downloading", "uploading"):
            label = "Downloading" if state == "downloading" else "Uploading"
            if self._tty:
                filled = int(_BAR_WIDTH * done / total) if total else _BAR_WIDTH
                bar = "=" * filled + ">" + " " * (_BAR_WIDTH - filled)
                self._out.write(
                    f"\r{short}: {label} [{bar}] {_human(done)}/{_human(total)}"
                )
                self._out.flush()
                self._active = short
                self._line_open = True
            else:
                now = time.monotonic()
                if now - self._last_plain >= _PLAIN_INTERVAL_S or done >= total:
                    self._last_plain = now
                    self._out.write(
                        f"{short}: {label} {_human(done)}/{_human(total)}\n"
                    )
                    self._out.flush()
            return
        if state == "done":
            self._finish_line()
            self._out.write(f"{short}: Complete\n")
            self._out.flush()
            return
        if state == "verifying" and self._tty:
            self._out.write(f"\r{short}: Verifying" + " " * (_BAR_WIDTH + 24))
            self._out.flush()
            self._line_open = True

    def _finish_line(self) -> None:
        if self._tty and self._line_open:
            self._out.write("\n")
            self._line_open = False

    def final(self, line: str) -> None:
        """The closing `name@digest` line."""
        self._finish_line()
        self._out.write(f"{line}\n")
        self._out.flush()
