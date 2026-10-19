# Autonomous roadmap checkpoint

## Current stage: Phase 4B — final review/CI before ready and merge

Owner authorizes autonomous stage PRs and merges after completion, latest required
checks, current base and resolved review blockers. No routine merge confirmation.
No force-push, bypass, branch deletion, public scans, history rewrite or release publishing.

- Main: `3e57881a8e03e3d4b5b0a58835714cb3a652d483`, Phase 4A #11 merged.
  Post-merge CodeQL 39338314167, Tests 39338314100, Native 39338314108,
  Security 39338314099 all passed; declared Rust 1.85 minimum tested.
- Completed stages: 1–3, security #8 and 4A #11. Remaining: 4B final merge, 4C,
  5A plugins, 5B remote OS evidence, 5C optional SQLite history, 6 release validation.
- Branch/worktree: `phase4b/native-syn-design`, sibling `scanix-phase4b`.
  PR: https://github.com/numankhaan/scanix/pull/12 (base main; still draft).
  Current HEAD: `git rev-parse HEAD`. Latest fully runtime-tested head:
  `d181e1b1eee2ea1cd71c8bb8f9db112576bac67d`.
- Commits: `e0d0842` packet fixtures, `05422a9` SYN/protocol-2 integration,
  `59f61a4` retry/cancellation evidence fix, `d181e1b` controlled lab/resource metrics.
  This final follow-up adds Linux-only IPC tests and measured/support documentation.
  Production runtime is unchanged from the live-tested head (test code/comments only).
- All old branches preserved. Original unrelated UDP edit verified unchanged; never
  stage it. Main required security/CodeQL/regression ruleset remains active. Historical
  privacy cleanup still awaits owner decision; no new allowlist or rewrite.

## Acceptance and actual implementation

Linux numeric IPv4 native SYN: independent paced transmitter/receivers, source/route/
privilege/capture preflight, strict TCP/quoted-ICMP correlation and reset cleanup,
bounded global/per-host work, retries, windows/cooldown/session and actual send/drop
metrics. Cancellation preserves positive/error evidence without counting unsent retries.
Protocol 2/engine 0.4.1, report schema 4; Python default/connect and exporters retained;
service enrichment remains separate. Native IPv6 SYN/UDP/discovery unsupported explicitly.
Rust streams, Python export aggregation remains bounded to the pair ceiling (4C later).

## Actual validation and exact commands

- `cargo test --locked --manifest-path native/Cargo.toml`: 19 passed locally before
  this test-only follow-up; Linux/non-Linux counts will differ with two new IPC tests.
- `cargo fmt --manifest-path native/Cargo.toml --check`, strict Clippy and release
  build passed. Linux aarch64 cross-Clippy passed using rustup stable compiler;
  cross-build is not execution. New IPC tests compile, awaiting Linux CI execution.
- `python -B validation/native_ci.py`: initial 143 run, 140 pass/three macOS skips.
  At d181e1b CI: 145/job; native Linux 143 pass/two skips, macOS 142/three,
  Windows 141/four. Ordinary jobs 137/eight, Windows 136/nine (six native cases
  explicitly unavailable, plus privileged/POSIX cases). No skipped case counted pass.
- Six SYN wire tests passed locally, including invalid evidence, drop metrics,
  setup cancellation and retry-failure preservation. 19 security-gate tests passed.
- d181e1b all push/PR workflows passed, logs checked:
  Security 39342280858/39342285880; CodeQL 39342280892/39342285865;
  Tests 39342280871/39342286055; Native/MSRV 39342280864/39342285903.
  Security had three zero-finding gates and 19 tests. Historical privacy jobs skipped
  on push/PR, not passed; their separate historical inventory remains unresolved.
- `gh workflow run privileged-lab.yml --ref phase4b/native-syn-design` dispatched
  exactly once at d181e1b. Run **39342284692 passed**: 25 native SYN checks plus
  existing Phase 2 namespace/capture/loopback regression. No public traffic.
- `python -m scanix scan -t 127.0.0.1 -p 19000 --engine native --syn --rate 20
  --retries 1 --syn-cooldown .2 --preview`: verified offline policy/CLI, no child.
- Local macOS privileged-lab preflight exited 2/unavailable, not pass. Privileged
  macOS/BPF remains incomplete; native SYN explicitly supports Linux only.

## Measured Linux evidence

Source d181e1b, 4-core x86_64 GitHub Ubuntu runner, ~15.6 GiB RAM, isolated veth
namespaces/no external default route. All four expected states and Python agreement
passed. Five SYN sends (one retry), one reset, four attempted/completed pairs,
three matched replies, one timeout, kernel/userspace/capture drops zero. Minimum
captured explicit gap .050554 s at ceiling 20/s. Native session 1.602965 s,
CPU .014989 s; getrusage RSS high-water 93,597,696 bytes is an upper bound that may
include the pre-exec Python image, not isolated Rust workload memory. Single small
correctness case dominated by silence/cooldown, not throughput/scalability/parity.
Actual topology, counts, capture digests and resource boundaries:
validation/NATIVE_SYN_RESULTS.md. Raw captures stayed private/ephemeral, no upload.

## Precise next action

Commit intended final Linux IPC tests/docs/checkpoint; push after GitHub head/base
check. Inspect all latest-head Security/CodeQL/Tests/Native/MSRV jobs and run the new
nonprivileged Linux IPC tests in CI. Fix actual failures. Live runtime remains the
already tested d181e1b; final diff must show only test/documentation follow-up.
Review final PR diff/reviews/required checks, mark ready only when acceptance passes,
merge #12 normally at exact reviewed SHA without deleting branch, then verify main
and post-merge CI. Update checkpoint on a new Phase 4C branch and continue roadmap.

Current uncommitted files: intended Linux IPC tests and measured/support docs only.
Private evidence pointer: `/tmp/scanix-security-session`. On any resume inspect
Git/GitHub before repeating push/dispatch/ready/merge. Historical cleanup and
privileged macOS/BPF remain explicitly unresolved. No new external blocker for 4B.
