# Autonomous roadmap checkpoint

## Current stage: Phase 4C — implementation

Autonomous implementation/PR/merge authorized after completion, current base and passing
required checks. No force push, bypass, branch deletion, public scans, rewritten history
or public release/package publishing. Preserve security gates and unrelated UDP edit.

- Main: `66f0455e6d69c0807de04e84f9c391dbd07776c5`, Phase 4B #12 merged.
- Phase 4B PR: https://github.com/numankhaan/scanix/pull/12; reviewed head
  `58a618e926cbee73a638f808414dd72a0d525e4d`. Latest push/PR Security, CodeQL,
  seven regression jobs and native/MSRV all passed before merge. Linux Rust 21,
  other platforms 19; Python 145/job with explicit platform/privileged skips.
- Phase 4B Linux namespace/capture run 39342284692 passed all 25 native checks
  at runtime source d181e1b; final head only added tests/comments/docs. Measurements
  and limits: validation/NATIVE_SYN_RESULTS.md. Privileged macOS/BPF incomplete.
- Main post-merge CI: Security 39343940342, CodeQL 39343940329,
  Native 39343940313, Tests 39343940358 queued/running at branch creation, not passes.
- Worktree: sibling `scanix-phase4c`; branch `phase4c/durable-streaming` from main.
  HEAD initially 66f0455. No Phase 4C PR yet. All prior branches retained.
- Completed: phases 1–3, security #8, 4A #11, 4B #12. Remaining 4C, 5A/B/C, 6.
- Original unrelated UDP edit hash verified unchanged; do not stage it. Historical
  privacy cleanup awaits owner decision; no allowlist/rewrite. Main nine required
  security/CodeQL/regression contexts remain enabled with strict base updating.

## Phase 4C acceptance and plan

1. Versioned private durable checkpoint with exact configuration/resolved-scope/
   implementation compatibility, fail before traffic on mismatch, single writer,
   crash-safe completed records and explicit at-least-once unfinished-probe semantics.
2. Bounded streaming result path without retaining every result; preserve aggregate
   exports/default Python behavior. Explicitly separate service enrichment.
3. Stable target-major work IDs, deterministic optional shards, completed-work skips
   enforced by the engine, coverage/duplicate/cancellation tests.
4. Actual coverage/loss/throughput and CPU/RSS limits; reproducible isolated loopback
   resume/stream baseline; optimize only measured problems, no parity claims.
5. Meaningful Python/Rust/local and latest CI validation, reviewed separate PR, merge
   only when acceptance is met and required checks pass; verify main and continue.

## Precise next action

First increment implemented: protocol 3/engine 0.4.2, deterministic shard/completed-ID
selection enforced by both schedulers, bounded callback/non-retention and duplicate
bitmap. Local Rust 21 passed; Python native fixtures 26 run, 20 pass/six real-engine
skips. Private checkpoint tests plus native fixtures: 33 run, 27 pass/six skips.
Checkpoint storage is uncommitted pending CLI/integration/robustness validation.
Next: finish CLI resume/streaming and separate enrichment, real native loopback tests,
controlled measurements, full regression/security validation, then PR.
Reconcile post-merge Phase 4B checks. Current uncommitted work includes the checkpoint storage module and its synthetic tests,
kept separate from the validated selection increment.
Private audit/lab evidence pointer: `/tmp/scanix-security-session`; never publish raw
reports/captures or personal metadata. No new Phase 4C external blocker identified.
