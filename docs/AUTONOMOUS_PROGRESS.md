# Autonomous roadmap checkpoint

## Current stage: 4A native foundation — in progress

Acceptance: real opt-in Rust TCP-connect scanning; Python remains default; protocol-1
NDJSON preflight/target registration/run/result/diagnostic/done/cancel frames;
bounded frames, targets, ports, channels, workers and timing; strict validation,
explicit unsupported/version/backend errors and no engine fallback; cancellation
retains completed results; existing scope/exclusions/preview/typed exports;
deterministic tests, loopback baseline benchmark, CI, reviewed PR and verified merge.

Plan: implement Rust engine/contract; Python adapter and CLI; tests/benchmark/docs;
review/commit/push PR; wait for current-head/base CI, merge, verify main; start 4B.

## Completed stages and verified base

Phases 1–3 verified in main 3a98cda708546bc0a84ea7f9dca42b8e3fe7db5c.
Phase 2 recovery #7: ad61a834210b79ac955e675fd1cbf9af0f57797b; Phase 3 #6: 3a98cda.
Main CI 39297271185: all seven jobs passed (115 tests each; Linux/macOS 113 pass +
2 privileged skips; Windows 112 pass + 3 skips). No open PRs; no AGENTS.md/template.
Remaining: 4A, 4B native asynchronous SYN, 4C resume/performance, 5A plugins,
5B remote OS evidence, 5C SQLite history, 6 release validation. None claimed complete.

## Workspace and preservation

Branch phase4a/native-foundation; worktree /Users/nouman/Downloads/scanix-phase4a.
Starting HEAD 3a98cda. Current HEAD: use git rev-parse HEAD (checkpoint cannot embed
its own commit SHA); latest implementation/tested SHAs and PR/run IDs recorded below.
No PR yet. Original /Users/nouman/Downloads/scanix remains on phase1 with its sole
unrelated UDP edit preserved: SHA-256
880894f38bc74007b1ad0d94609964f136667fe8be865e7466cb37535056893c.
Never stage that edit, force-push, delete branches, bypass checks or scan public targets.

## Commands/outcomes and environment

Initial: git fetch origin via HTTPS URL mapping; main ancestry/tree verified;
gh pr list --state open returned []; latest main CI success. rustc/cargo 1.91.1;
macOS arm64 host. Python regression venvs /tmp/scanix-phase2-venv (Scapy 2.8.0),
/tmp/scanix-minscapy-venv (2.6.1). No new tests/benchmarks run yet.
Privileged macOS/BPF validation remains incomplete. Linux privileged validation
must use an isolated lab/hosted workflow; earlier Linux results are historical only.
No current blocker for 4A. Later stages must not be marked complete without validation.

## Resume exactly here

Inspect git/GitHub for already-completed operations before repeating any commit,
push, PR or merge. Next: verify Rust/Tokio/Python subprocess APIs against primary
docs, inspect existing scan/report/export hooks, implement native contract and engine.
Uncommitted files: this checkpoint, intentionally pending the first coherent 4A
implementation commit. Update this record after milestones and before long operations.

### 4A engine increment (uncommitted)
Rust protocol validation, bounded stdio, asynchronous connect scheduler and unit
fixtures implemented in native/. No native SYN backend is claimed. Next operation:
first cargo test (dependency download/build may take minutes), then implement and
test Python adapter. Cargo.lock will be committed; native/target is ignored.

### 4A validated implementation milestone

Local Rust: cargo test --locked --manifest-path native/Cargo.toml: **6 passed**;
cargo clippy --locked --manifest-path native/Cargo.toml --all-targets -- -D warnings:
passed; cargo fmt --check: passed; release build passed (Rust 1.91.1).
Python: SCANIX_NATIVE_ENGINE=<debug binary> /tmp/scanix-phase2-venv/bin/python -B
-m unittest discover -s scanix/tests -q: **126 run, 124 passed, 2 privileged skips**
(12.895 s). Release-binary validation/native_ci.py also passed; see next checkpoint
for exact elapsed/log verification. Native tests include real IPv4/IPv6 connect,
Python agreement, exclusions, cancellation and trusted TLS/SNI enrichment.

Implemented: protocol-1 Rust TCP connect engine, schema-4 Python adapter/CLI/exports,
strict scope/diagnostic validation, bounded queues, watchdogs and no fallback;
workflow builds native on Linux/macOS/Windows; documentation and baseline driver.
Remaining acceptance: execute/record release baseline, review full diff, commit/push
PR, inspect latest-head/base cross-platform CI, resolve blockers, merge and verify.
No PR/CI runs for 4A yet. Next: commit this coherent implementation, run the
baseline at that known SHA, then update measured results/checkpoint and open PR.
Uncommitted: intended implementation/tests/docs/workflow and Cargo.lock only;
build output ignored. Original UDP edit is outside this worktree and unchanged.
