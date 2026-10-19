# Phase integration record

## Integrated implementation and delivery

The integrated tree contains completed Phase 1 TCP connect reliability, Phase 2
SYN/UDP/scope/discovery/timing, and Phase 3 service/TLS identification with the
versioned probe registry. Phase 4 has not started.

- [PR #4](https://github.com/numankhaan/scanix/pull/4) merged Phase 1 into main.
- [Integration PR #7](https://github.com/numankhaan/scanix/pull/7) restored completed
  Phase 2 to main at `ad61a834210b79ac955e675fd1cbf9af0f57797b`.
- [PR #6](https://github.com/numankhaan/scanix/pull/6) delivers Phase 3 against main.
  This record travels with that integration. The PR records its authoritative
  final merge commit and post-merge main CI outcomes, distinct from the
  pre-merge validation checkpoints below.

## Verified starting state

Main was `ece9bd0`, the merge of #4. Phase 2 head `3dbad9c` was not its ancestor:
#5 had merged into phase1/tcp-connect-reliability. Shared ancestor was `fb0277f`;
the direct tree diff was 31 files, 2,876 insertions and 302 deletions. Missing work
included raw scans, target scopes/exclusions, discovery, timing, tests and lab
evidence. No equivalent open integration PR existed. PR #6 initially targeted
phase2/scanning-accuracy at `44843e0`.

## Phase 2 recovery and review

Recovery started from updated main and normally merged the existing Phase 2 head
as `7427f70`. No conflicts occurred; before progress updates, the resulting tree
exactly matched Phase 2. Progress-only commit `f859a41` records that recovery.
PR #7 merged only after all 14 check runs succeeded, the expected head/base were
verified, and there were no unresolved review threads or requested changes.

Local Python 3.14.3 regression with each of Scapy 2.8.0 and 2.6.1: **82 run,
80 passed, 2 optional privileged skips**. CI at f859a41 passed all seven jobs in
[push run 39296415602](https://github.com/numankhaan/scanix/actions/runs/39296415602)
and [PR run 39296471501](https://github.com/numankhaan/scanix/actions/runs/39296471501).
Each ran 82 tests: Linux/macOS passed 80 with 2 skips; Windows passed 79 with 3,
including the pre-existing POSIX subprocess SIGINT skip.
Post-merge main verification is [run 39296678424](https://github.com/numankhaan/scanix/actions/runs/39296678424).
It completed successfully with all seven jobs passing at ad61a83; this is a
separate verified post-merge outcome, not an inference from pre-merge checks.

## Phase 3 synchronization and review

After #7 merged, #6 was explicitly retargeted to main. Normal merge `32e5e2d`
includes main at ad61a83 without rewriting history. This unified the merge base:
the synchronization changed only progress records and left all Phase 3 application
files exactly equal to the delivered 44843e0 tree. The final diff against main
contains Phase 3 changes and integration documentation, without reintroducing
Phase 2-only target/discovery/raw implementations or changing the CI workflows.

Local regressions on that updated base ran 115 tests with each of Scapy 2.8.0
and 2.6.1: 113 passed, two privileged skips (9.126 / 9.074 seconds). All four
real CLI loopback HTTP/TLS lab cases passed, including trusted SNI, self-signed
rejection and explicit insecure inspection. The latest integration head's matrix and review state are checked
again before merging #6. Final local/CI counts and post-merge verification are
recorded in #6, preserving the distinction between local tests and hosted CI.

## Preservation, policy and limits

No applicable AGENTS.md, PR template, main protection or main ruleset requirements
were present. Nevertheless all seven matrix jobs are required by this workflow;
queued/running checks are never treated as passes. There is no administrator
bypass, force-push, branch deletion or cherry-pick duplication.

The original worktree's unrelated UDP edit remains unchanged and excluded, SHA-256
`880894f38bc74007b1ad0d94609964f136667fe8be865e7466cb37535056893c`.
Only synthetic packets and local lab endpoints are used; no public targets scanned.

The optional privileged Phase 2 driver and previous hosted Linux namespace/pcap
results remain intact, but are not a fresh integration-time privileged run.
**Privileged macOS/BPF validation remains incomplete.** Broader interoperability,
HTTP/2, FTP TLS, exhaustive cipher discovery and virtual-host enumeration remain
outside the documented initial coverage. See [Phase 2 evidence](validation/RESULTS.md),
[service evidence](validation/SERVICE_RESULTS.md) and [service semantics](docs/SERVICE_DETECTION.md).
