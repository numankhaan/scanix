# Autonomous roadmap checkpoint

## Current stage: Phase 4B — implementation in draft PR #12

Owner authorizes autonomous PR review/merge only after completion, current base,
required green checks and no review blockers. Do not mark the existing design-only
draft ready or merge until real implementation and controlled lab evidence exist.
No force-push, branch deletion, public scans or history cleanup.

- Main: `3e57881a8e03e3d4b5b0a58835714cb3a652d483`, Phase 4A #11 merged.
  Latest main CodeQL `39338314167`, Tests `39338314100`, Native `39338314108`,
  Security `39338314099`: all passed, including minimum Rust 1.85 CI.
- Branch/worktree: `phase4b/native-syn-design`, sibling `scanix-phase4b`.
  Starting head `2136ee572feea1f6f8dbb0639df81586ec3f8794`; current HEAD via Git.
  PR: https://github.com/numankhaan/scanix/pull/12 (draft, base main).
- All previous branches preserved. Original unrelated UDP edit checksum unchanged.
  Required security/regression ruleset remains active. Historical privacy cleanup
  remains pending owner decision; raw findings remain private.

Acceptance: Linux IPv4 native SYN, independent send/receive, strict packet/ICMP
correlation, correct resets, bounded pacing/retries/state/queues/cooldown/session,
accurate counters/drop metrics, cancellation/partial reports, exclusions/preview,
separate enrichment, explicit unsupported backends. IPv6 native SYN unsupported;
existing Python IPv6 raw and native IPv6 connect remain available. Synthetic tests,
MSRV/security/regressions and isolated namespace ground-truth+capture validation
must pass. No parity/performance claim without measurements.

Plan: pure packet builder/parser and fixtures; Linux transport; bounded scheduler;
protocol-2 Python adapter/CLI; isolated lab and capture checks/measurements; docs,
focused validated commits, push/update #12; inspect latest CI, ready/review/merge
only when complete, post-merge checks, then Phase 4C. Privileged macOS/BPF remains
incomplete and is not waived.

Precise next action: implement pure IPv4 SYN packet module and synthetic tests;
then build Linux transport against primary packet/raw socket documentation.
Uncommitted: this intentional checkpoint only. No Phase 4B code claimed delivered.
Private evidence pointer: `/tmp/scanix-security-session`. Reconcile git/GitHub before
repeating any commit/push/PR/merge on resume. Later: 4C, 5A, 5B, 5C, 6.


## Packet boundary milestone

Added pure IPv4 SYN builder/checksums and reply/quoted-ICMP classifier, with reset
construction, strict endpoint/ACK validation, malformed/truncated/fragment rejection,
wraparound and deterministic malformed-input fixtures. This module is currently
compiled for tests only; no native SYN capability is advertised yet.
`cargo test --locked --manifest-path native/Cargo.toml`: 12 passed.
`cargo fmt` and Clippy --all-targets -D warnings passed. No network scan run.
Next: Linux raw sender + non-promiscuous AF_PACKET capture preflight, independent
bounded receive task; then protocol-2 SYN scheduler and deterministic timing tests.
PR #12 remains draft. Main/old branches and unrelated UDP edit are unchanged.
