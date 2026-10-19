# Autonomous checkpoint — Phase 4A

Phase 4A is implemented and locally validated; PR #11 is open for review.
**Do not merge this PR or start Phase 4B.**

## Acceptance and implementation

Real opt-in Rust IPv4/IPv6 TCP connect scanning; Python remains the default.
Protocol 1 bounded NDJSON requests/results/diagnostics; strict compatibility, scope,
work-ID/state/coverage/exit validation; cancellation retains completed results;
paced bounded workers/timeouts; schema-4 typed exports and separate service stage.
Native raw SYN/UDP/discovery and durable resume are not implemented here.
Rust streams; Python compatibility exports still aggregate up to the pair ceiling.

## Repository and preservation

- Base: main `ef1c3dc0ecabf4ee101bb018922006668c47fe86` (#8 merged).
  Main Security `39335020364`, Tests `39335020577`, CodeQL `39335020611`: passed.
- Branch/worktree: `phase4a/native-foundation-reviewed`, sibling
  `scanix-phase4a-reviewed`; current HEAD: `git rev-parse HEAD`.
  PR: https://github.com/numankhaan/scanix/pull/11 (base main; leave open).
- Commits: `322516d` enforced checks/privacy review; `40f5e3` Rust engine;
  `50322ab` Python/CLI/export/tests/workflow integration; `05204cc` measured baseline.
  This final documentation commit adds PR/CI reconciliation; inspect its SHA on resume.
- Existing native branch/head `phase4a/native-foundation` / `d08659e` preserved.
  Its old checkpoint has a personal path; implementation was reused in fresh commits
  without inheriting or allowlisting that history. No rewrite or force-push.
- Original worktree retains only its unrelated UDP edit, checksum verified unchanged.
  Reviewed worktree was clean before this checkpoint-only update; only this intended
  doc awaits commit. Build/cache/generated raw records are ignored or outside Git.

## Security review and policy

Verified active main ruleset `25438618`: nine GitHub Actions security/CodeQL/regression
contexts, strict up-to-date base, no bypass actors. Follow-up historical privacy
inventory exited 1: 112 email candidates, 24 home-path occurrences, 13 bytecode flags.
Locations/references in SECURITY_AUDIT.md; no values published, silent allowlist or
cleanup. Owner decision on historical cleanup remains pending. Passing scanners do
not guarantee privacy/security. Private evidence pointer: `/tmp/scanix-security-session`.

## Commands and actual local outcomes

- `cargo test --locked --manifest-path native/Cargo.toml`: 8 passed.
- `cargo fmt --manifest-path native/Cargo.toml --check`, release build and
  `cargo clippy --locked --manifest-path native/Cargo.toml --all-targets -- -D warnings`: passed.
- `python -B validation/native_ci.py`: 138 run, 136 passed/two privileged skips.
- `python -B -m unittest discover -s scanix/tests -q` without native env:
  138 run, 131 passed/seven skips (five native, two privileged).
- `python -B -m unittest discover -s security/tests -v`: 19 passed.
- `python security/check.py tree`, staged, range --base origin/main --head HEAD,
  and history --secrets-only passed. Existing exact synthetic TLS key exceptions only.
- `python security/run.py` bandit/workflows/dependencies/rust: passed; zero
  findings/advisories/warnings. CLI help verified native flags.
- At clean `50322ab61e8031525d4be16918fd6de00177ab8a`, benchmark driver ran
  --ports 32/128 --samples 5 with release binary. All expected open counts matched.
  Median completions/s Python 409.4/417.2; native 300.6/307.1. Native was slower.
  Apple M4, 16 GiB, 10 logical CPUs, macOS arm64/Python 3.14.3/Rust 1.91.1.
  Exact reproduction, timing/resource boundaries: validation/NATIVE_BASELINE.md.

## CI at initial PR head 05204cc

The following are observations at checkpoint preparation, not transferred passes
for this documentation commit. PR #11 holds final latest-head outcomes.
- pull_request CodeQL: `39336558595`, in_progress, pending.
- pull_request Native foundation: `39336558574`, in_progress, pending.
- pull_request Security: `39336558347`, in_progress, pending.
- pull_request Tests: `39336558509`, in_progress, pending.
- push CodeQL: `39336470421`, completed, success.
- push Native foundation: `39336470495`, in_progress, pending.
- push Security: `39336470449`, in_progress, pending.
- push Tests: `39336470533`, completed, success.

## Precise next action

Commit/push only this checkpoint, inspect all eight latest-head push/PR workflow runs
(Security, CodeQL, Tests, Native foundation), investigate actual failures and update
PR #11 with exact SHA/run outcomes. Retain private final reconciliation beside audit
evidence to avoid endless CI-status-only commits. Reconcile remote/local HEAD and main
on resume before repeating any operation. Review final diff and leave PR open for owner.

Privileged macOS/BPF remains incomplete. Local measurements are loopback-only, no
packet-loss/SYN speed or parity claim; minimum Rust 1.85 is declared, not tested.
No account-wide setting changes or public scans performed. Later roadmap stages wait.
