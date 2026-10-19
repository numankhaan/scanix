# Phase integration record

## Verified starting state

- Main: `ece9bd01ec99c99c49f44a8f2963e7bb88cb98f2`, the merge of PR #4.
- Phase 2: `3dbad9c9c01f50c459424d61b1904a597b2a8a6d`. PR #5 merged it into
  phase1/tcp-connect-reliability, not main. Its head was not an ancestor of main.
- Shared ancestor: `fb0277f`; direct main-to-Phase-2 diff: 31 files,
  2,876 insertions and 302 deletions. Missing work includes correlated SYN/UDP,
  IPv4/IPv6 target scopes and exclusions, discovery, timing, tests and lab evidence.
- PR #6 initially targeted phase2/scanning-accuracy at head `44843e0`.
- No equivalent open Phase 2 integration PR existed. No applicable AGENTS.md,
  PR template, main protection or main ruleset requirements were present.

## Phase 2 recovery candidate

`integration/phase2-to-main` starts at updated main and normally merges the existing
Phase 2 head as `7427f70`. No conflicts occurred; its tree before these progress
updates exactly matched the Phase 2 tree. The only new edits are progress records.
There is no cherry-pick duplication or history rewrite.

Local regression: Python 3.14.3, each of Scapy 2.8.0 and 2.6.1: **82 run, 80 passed,
2 optional privileged skips**. Synthetic packets and loopback only. CI results and
final merge identifiers are recorded in the integration PR; queued/running jobs
are not passing checks. Full Linux Python 3.10–3.14 and macOS/Windows 3.14 matrices
must pass, with no unresolved review blockers, before merge.

## Phase 3 integration sequence

After Phase 2 recovery reaches main, retarget PR #6 to main and normally merge the
new main into its branch. Review its resulting diff to ensure it contains only
Phase 3 and necessary integration documentation, then rerun regression tests and
wait for checks on the latest head and base. Verify both implementations and
post-merge CI on main. Do not start Phase 4.

## Preserved scope and validation limits

The original worktree still has its unrelated UDP edit, SHA-256
`880894f38bc74007b1ad0d94609964f136667fe8be865e7466cb37535056893c`.
All integration work uses an isolated worktree. No branch is deleted, no force-push
is used and no checks are bypassed.

The optional privileged Phase 2 driver and previous hosted Linux namespace/pcap
results remain intact. They are not a fresh integration-time privileged run.
**Privileged macOS/BPF validation remains incomplete.** No public targets are scanned.
See [Phase 2 evidence](validation/RESULTS.md) and [lab instructions](validation/README.md).
