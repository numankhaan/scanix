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


## SYN engine implementation milestone (live validation pending)

Packet commit `e0d0842b8ed94b5035e6f232a3a7d37b65b5e34a` is local, not yet pushed.
Added independent paced raw sender/AF_PACKET capture tasks, bounded deterministic
round-robin work state, retry/final window/drain/cancel, actual-send/drop metrics,
source/interface/capture preflight and protocol 2/engine 0.4.1 Python integration.
Explicit native SYN Linux/IPv4 failures precede traffic; Python remains default.
No privileged native SYN execution performed yet; do not mark #12 ready.

Actual local validation: `cargo test --locked --manifest-path native/Cargo.toml`
17 passed; release build passed. Mac Clippy passed; Linux aarch64 cross-compile and
strict Clippy passed using installed rustup stable compiler (not Linux execution).
`python -B validation/native_ci.py`: 143 run, 140 passed/three skips (two privileged,
one Linux-only preflight case). `python -m unittest discover -s security/tests -v`:
19 passed. Bandit passed. Earlier strict lint caught Tokio AsyncFd::new deprecation;
used documented unsafe register API with OwnedFd lifetime guarantees, no suppression.

Current uncommitted files are intended native I/O/state/driver, protocol/model/CLI,
adapter/fixtures and support docs. No generated captures/reports or unrelated edits.
Next: commit reviewed implementation, push to existing draft #12 after verifying
remote head, inspect CI; implement and dispatch controlled native SYN namespace lab
with independent capture validation, measurements and cancellation/exclusion cases.
Fix actual failures before ready/review/merge. Then post-merge CI and Phase 4C.
