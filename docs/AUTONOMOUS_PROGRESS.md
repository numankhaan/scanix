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
