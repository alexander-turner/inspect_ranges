---
type: analysis
title: "Challenges and goals: survey of public objective and scoring formats"
status: draft
tags: [inspect-ranges, challenges, goals, survey, scoring]
timestamp: 2026-10-14
---

# Challenges and goals: survey of public objective and scoring formats

*Backing research for the [challenges-and-goals reviewer document](../challenges-overview.qmd). It records how public cyber ranges, simulators, and benchmarks define objectives and decide success, and how each maps onto the goal types and scoring posture proposed there. The reviewer document carries the design; this carries the lineage.*

We surveyed how public ranges, simulators, and benchmarks define objectives and decide success. (A general CTF-benchmark pass was interrupted, but its main formats, `inspect_cyber`, CVE-Bench, BountyBench, and Cybench, are covered.) The findings that shaped the design:

- The built-in types cover the observed objective space. Across KYPO, CyRIS, MHBench/Incalmo, CybORG/CAGE, CyberBattleSim, NetSecGame, NASim/PenGym, Splunk BOTS, GOAD/Ludus, CALDERA, Locked Shields, and the LLM benches (Cybench, PACEbench, AgentCyberRange, AutoPenBench, CAIBench, the UK AISI ranges, OpenAI's cyber range), the recurring success types (flag/answer, randomized secret, fact answer, data-exfiltrated, host-owned/privilege, coverage, milestones, availability/SLA, integrity, detection, stealth, PoC-replay) each map to a built-in goal type or a scoring mode.
- The strongest formats already use our rule. Where a benchmark needs to trust that an agent owned a host, the robust ones turn it into knowledge of a grader-randomized secret, a grader-side replay observed from outside, or an external active probe (KYPO APG, PACEbench dynamic flags, AgentCyberRange's PoC replay, Locked Shields' active functional checks). The weaker ones (marker files under `/tmp`, log-inferred success) are what the cost rule and per-sample tokens tighten.
- Milestones and per-instance randomization are baseline expectations: KYPO's gated level ladder, the UK AISI 32-step/9-milestone range, and CAGE's phase weights all need them, so they are first-class in the design.
- The Inspect-native format translates cleanly. `inspect_cyber`'s `eval.yaml` (prompt, sandbox, files, setup, flag, ordered `checkpoints`, first-class `variants`) maps onto ours: `flag` to `flag`/`answer`, checkpoints to `milestones` with the same progress-fraction partial credit, and the same Inspect `Dataset`/`Sample` construction. Its scoring reads the agent's transcript for flags, and its one environment-reading checkpoint is unimplemented, which is the host-side verification the design fills.
- A real grader's categories fall inside our type set. CVE-Bench grades 8 outcome categories (DoS, file/DB access, code execution, DB modification, admin login, privilege escalation, outbound request) using per-sample canaries plus a grader that reads environment state directly, which is our model; they map to `availability`/impact, `exfiltrate`/`flag`, `execute`, integrity, and `control`. One difference is relevant to the posture: its grader runs co-resident with the target, where ours reads from outside every VM through the oracle.
- The single-host CTF benches confirm the floor and add two mechanisms. NYU CTF, 3CB, and ctfcli/CTFd are static-or-regex flag-and-answer submission (host-anchored; ctfcli's dynamic-decay scoring and prerequisite gating are human-scoreboard concerns we leave out). Two are worth absorbing: CyberGym verifies a differential PoC replay (effect on the vulnerable build but not the fixed one), the host-anchored shape the `execute` and `patch` checks take, and CyberSecEval grades some tasks with an LLM judge and others with a continuous 0–1 programmatic score, carried by the `judge` mechanism and `GoalResult.partial` respectively.
