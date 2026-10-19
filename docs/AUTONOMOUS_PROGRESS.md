# Autonomous checkpoint — Phase 4A

Current stage: finish/review native foundation; **do not merge its PR** or start 4B.
Acceptance: opt-in real Rust connect scanning; Python default; versioned, bounded
subprocess requests/results; explicit diagnostics/compatibility and no fallback;
cancellation/partial exports; scope/resource validation; tests and measured baseline;
security gates and passing latest-head CI; open PR with known limitations.

## Reconciled state

- Main/security #8 merge: `ef1c3dc0ecabf4ee101bb018922006668c47fe86`.
  Main Security `39335020364`, Tests `39335020577`, CodeQL `39335020611`: passed.
  Nine required GitHub Actions checks now enforced by active main ruleset
  `25438618`, strict/up-to-date base, no bypass actors. Verified through readback.
- Historical privacy inventory remains failing: 112 email candidates, 24 home-path
  occurrences, 13 bytecode flags. No raw values published, allowlist or rewrite.
  Locations and owner decision documented in SECURITY_AUDIT.md.
- Old native work is preserved at `phase4a/native-foundation` / `d08659e`.
  Its historical checkpoint includes a personal path. Reuse its implementation on
  clean `phase4a/native-foundation-reviewed` from main; do not inherit/allowlist that
  historical commit in this PR. This creates new commits, not a history rewrite.
- Worktree: sibling `scanix-phase4a-reviewed`; HEAD: `git rev-parse HEAD`.
  No Phase 4A PR yet. Original worktree's unrelated UDP edit remains untouched.

## Current milestone / exact next action

Reused native source/adapter/tests/docs; preserved merged security changes and
resolved .gitignore/roadmap overlap. Native workflow now SHA-pinned with no persisted
checkout credentials. Currently uncommitted intended Phase 4A files only; no raw
reports/captures/build products should be staged.

Next: strengthen malformed-wire/handshake and bounded-registration tests, run Rust
fmt/Clippy/tests and all Python/security regressions, review diff, focused commits;
run release loopback baseline at known clean SHA, document measured data, push/open
PR, inspect all latest-head CI. Keep this checkpoint current at each milestone.

Private audit/evidence pointer: `/tmp/scanix-security-session`. Never commit raw
findings. Privileged macOS/BPF remains incomplete. No public network scan allowed.
Do not merge this PR. Preserve old branches and all unrelated edits.

## Native engine milestone

Reused and reviewed engine: `cargo fmt --manifest-path native/Cargo.toml`,
`cargo test --locked --manifest-path native/Cargo.toml` (8 passed),
`cargo clippy --locked --manifest-path native/Cargo.toml --all-targets -- -D warnings`
and release build passed. Twelve adapter wire tests also passed, including explicit
16-level JSON nesting rejection; an earlier development test exposed differing
Python parser depth behavior and was fixed with an explicit bound, not an assertion
change. Native source is ready for its focused commit. Adapter/CLI/tests/docs/workflow
remain intended uncommitted work awaiting full regressions and release baseline.

## Python integration milestone

Engine commit `40f5e377a493e5288dea37583c96eb81e3a9370d` follows security/rules
review `322516d`. Full real-release-subprocess command
`python -B validation/native_ci.py`: 138 run/136 passed/two privileged skips.
`python -B -m unittest discover -s scanix/tests -q` without native configuration:
138 run/131 passed/seven skips (five native, two privileged).
`python -B -m unittest discover -s security/tests -v`: 19 passed.
`python security/check.py tree` and `python security/run.py` with bandit, workflows,
dependencies and rust: all passed (zero reported findings/advisories/warnings).
`python -m scanix scan --help` verified engine, native-binary, engine-timeout,
preview and service-detect flags. Two-port/one-sample benchmark smoke passed; this
is a driver check, not published performance evidence. Rust dependency licenses
were inspected using `cargo metadata --locked --manifest-path native/Cargo.toml`.

Next: commit reviewed adapter/CLI/exports/tests/workflow/docs and benchmark driver;
run release benchmarks at that clean known SHA (32/128 ports, five samples each),
record measured data/hardware and limitations, then push/open PR and inspect CI.
Native stage remains unmerged. No public scans or privileged operations performed.

## Measured baseline / ready to push

Integration commit `50322ab61e8031525d4be16918fd6de00177ab8a` validated locally.
At that clean SHA, release benchmark commands above ran 32 and 128 ports, five
samples/engine/size. All expected open counts matched. Median completions/s:
32 ports Python 409.4/native 300.6; 128 ports Python 417.2/native 307.1.
Apple M4/16 GiB/10 logical CPUs/macOS arm64; exact measurements and boundaries in
validation/NATIVE_BASELINE.md. Native was slower; no speed/parity claim or inferred
bottleneck. Raw generated timing records remain outside Git.

Next: commit only the aggregate baseline and these documentation updates, run
outgoing range/full-history secret gates, push reviewed branch once, open PR against
main (do not merge), inspect latest-head Security/CodeQL/Tests/Native workflows.
No PR/CI yet for this new branch; main ef1c3dc core checks are passing. After push,
record PR/run IDs and pending/final outcomes. Original UDP edit remains unchanged.
