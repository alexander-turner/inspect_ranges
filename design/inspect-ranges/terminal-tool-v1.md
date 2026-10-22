# Decision: the terminal tool (tmux sessions for agents)

Status: accepted (user-ratified plan, 2026-10-22). Built on branch `terminal-tool-v1`.

## The question

Opus eval transcripts showed agents hand-building session layers from bash alone: the kypo run wrote four iterations of telnetlib wrappers before attacking, and the equifax run died at its message cap mid-chain with channel plumbing consuming budget. tmux, screen, and pexpect were already on the attack image and went unused: agents use what the tool surface advertises, not what is quietly installed. The reverse-shell workflow (a listener that persists across tool calls, then keystrokes into the caught shell) and msfconsole are effectively unreachable from one-shot bash. Should the package ship a session tool, and in what shape?

## The decision

One agent-facing tool, `terminal()`, exported from `inspect_ranges`: named tmux sessions on the foothold guest, driven through the public `SandboxEnvironment` surface only (`exec` for control verbs, `exec_remote` streaming for capture), with a per-call screen snapshot in the transcript viewer and a full-fidelity asciicast assembled at finalize. Opt-in task wiring, never a default: adding the tool changes measured difficulty, so tasks adopt it deliberately and results are read accordingly.

The design ports the session mechanics of terminal-bench's Terminus agent (Apache-2.0; attribution in [LICENSES.md](LICENSES.md)): the `; tmux wait -S done` completion signal for blocking sends (no prompt detection), the previous-buffer delta heuristic with its honest two-label output ("New Terminal Output" when the delta is determinable, "Current Terminal Screen" when it is not), the 160x40 pane with `history-limit 50000` and `pipe-pane` capture, output clipping before the model sees it, and the keystrokes/duration/poll grammar with tmux key names. What Terminus does not have and this tool adds: multiple named sessions (listener and trigger concurrently), a shell-only guard on blocking mode, the viewer snapshot, and the evidence integration. Terminus's agent loop (JSON protocol, summarization) is not ported: react and native tool calling own the loop here.

## The surface

One tool with an `action` parameter (`open`, `send`, `read`, `close`); models handle action-dispatch tools well, and one schema keeps the model-facing docstring in one place.

- `open(session)`: create the named session, idempotent. Starts the capture leg.
- `send(session, keystrokes, duration, block, timeout)`: keystrokes verbatim, tmux key names for control sequences (`C-c`). Default is send then wait `duration` (empty keystrokes with a duration is the poll idiom). `block=True` appends the completion signal and waits for it under `timeout`; it is refused unless `#{pane_current_command}` is a shell, because the appended text executes wherever the pane's input goes: inside a caught reverse shell or msfconsole that is the target, not tmux.
- `read(session)`: the delta since the last read, clipped (~10 KB, truncation marked), labeled per the heuristic's confidence.
- `close(session)`: stop capture, kill the session. Results name the open sessions so the model can track them.

Every non-happy path returns a string to the agent, never raises (the `verify_goal` discipline).

**Transcript views.** inspect_ai binds a tool call's view before execution and never recomputes it after the result, so a view cannot carry its own call's after-screen. The design leans into that instead of fighting it (user decision, in preference to the computer tool's `model_input` filtering): the tool result is a plain string, exactly the delta the model sees, and at the end of every execution the tool writes the post-action screen to the store (`inspect_ranges:terminal_screen`, keyed by session). The `viewer=` hook reads that store entry, so the view bound to a call renders the screen as it stood when the model issued the call: the transcript reads "screen the model saw, keystrokes it chose, delta that came back" per call, with no `model_input` hook and no content filtering. The final call's after-screen has no following view; `close` returns the final screen as its result and the cast carries the full record. Two pins: the tool declares `parallel=False` (a stateful session tool must serialize anyway, and the view's offset-by-one semantics depend on it), and the viewer's store read is wrapped so a storeless invocation context degrades to an args-only view.

## Capture and playback

Per session, one streaming `exec_remote` tails the `pipe-pane` sink; each output event is timestamped host-side on arrival. inspect_ai's base class implements `exec_remote` over `exec`, so the provider needs no new code; a native channel-backed implementation is a recorded follow-up if the generic cadence proves too coarse. Each tool call drops a timestamp marker (the Terminus trick), so playback can jump decision to decision. At close or sample finalize (a producer registered via `EvidenceSession.register_producer`), the chunks and markers assemble into an asciicast v2 file beside the eval log, and the raw stream mirrors to a `terminal/<session>` evidence stream, making the operator's terminal record tamper-evident alongside pcap and consoles.

## Recorded exceptions and boundaries

- The tool reaches the evidence session via `sample_handle_for(sandbox())` inside its own closure, touching only `handle.evidence`. This is a deliberate exception to the "never expose the handle to solver-visible surfaces" rule: the handle never reaches the agent; only tool-internal capture uses it. Outside a range sandbox the tool degrades: sessions and snapshots work anywhere `sandbox().exec` does, capture and evidence are quietly off.
- Bare `sandbox()` is the foothold (the provider registers only the foothold guest), so the tool needs no sandbox name.
- Reverse-shell reachability is a topology fact the tool does not change: same-segment shells always work; cross-segment ones need the ACL to admit target-to-attacker flows (equifax declares exactly that). The attack image's zero-listener invariant is a build-time image property; agent-started listeners at runtime trip nothing.
- Upstreaming: the session core and tool code against only public inspect_ai surfaces, so they can move to inspect_ai later; the evidence adapter stays here.

## Exit and follow-ups

Exit: unit suite green, two fresh-context adversarial review rounds (round 1 with named probes, round 2 verifying fixes plus flow cuts), then live acceptance on a built range: catch and drive a reverse shell through the tool, drive msfconsole in a second session, snapshot renders in `inspect view`, cast assembles and plays, `terminal/<session>` stream seals.

Follow-ups, recorded not built: the kypo/equifax A/B at a fixed message cap (user-triggered; model spend), a native channel-backed `exec_remote`, upstreaming the core to inspect_ai, and seamless in-viewer cast playback (the viewer bundles an asciinema player, but the log-side hook may be human-agent-specific; until confirmed, the cast is a file beside the log playable anywhere).
