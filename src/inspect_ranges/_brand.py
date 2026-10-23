"""The in-guest brand token (one knob): every artifact the harness lands inside a guest carries this name.

Why a brand at all: the first real-model fleet pass caught an agent reading `/opt/inspect-ranges` off its own foothold (fleet-pass-2026-10.md, finding 8), a string-level eval-awareness tell baked into every guest. The token is deliberately boring and generic (a guest daemon named like a guest daemon), never mimicry of a real product, and the posture is honest renaming, not hiding: an AF_VSOCK listener remains findable by any agent that looks, and the rename is recorded in the open design docs.

Host-side names (cache directories, CLI verbs, project prefixes, artifact and bundle file names, evidence paths) deliberately keep the `inspect-ranges` identity: they never land inside a guest.
"""

GUEST_BRAND = "guestd"
"""The token: the control daemon's binary, unit, and service name, and the prefix of every harness-owned in-guest directory."""

GUEST_OPT_LINUX = f"/opt/{GUEST_BRAND}"
"""The Linux in-guest home: the control daemon binary and the activities directory live under it."""

GUEST_ETC_LINUX = f"/etc/{GUEST_BRAND}"
"""The Linux in-guest config directory (the per-sample draws file lands here via cloud-init)."""

GUEST_HOME_WINDOWS = f"C:\\{GUEST_BRAND}"
"""The Windows control daemon's home (sources, compiled binary, work directory)."""

GUEST_PROGRAMDATA_WINDOWS = f"C:\\ProgramData\\{GUEST_BRAND}"
"""The Windows in-guest home for harness-owned content (activity scripts)."""
