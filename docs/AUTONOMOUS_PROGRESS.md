# Autonomous roadmap checkpoint

## Current stage: Phase6 — PR17 must remain draft

Remote PR17 https://github.com/numankhaan/scanix/pull/17 is OPEN/DRAFT, base main
51288fe75298fb29bab9cc88903ff0ff35fabc8d; remote head22af3c5651e09ae7111cc4ed40eb264d5e9491ec.
Worktree scanix-phase6, branch phase6/release-validation. New documentation prepared
locally per owner steering; hold its documentation-only commit locally to avoid
restarting passed CI. Do not push merely for status. PR body carries reviewable policy
and license comparison now; batch source docs in a later appropriate authorized push.

Latest owner instructions:keep PR17 draft until remaining CI passes and licensing
is decided. No license addition, merge, publication or history rewrite now.
Privileged macOS Python raw SYN/UDP/ICMP/ARP/ND are experimental and unverified;
no supported privileged-operation claim. Tested unprivileged macOS Python/native
connect,TCP discovery,TLS/plugins,preview,exports,continuation/history retained.
Native SYN remains Linux-only. Raw validation remains a coverage gap, not a claim
that unprivileged macOS is unsupported. No code/platform guards changed.

## Completed and validation provenance

Phases1–5C/security8 merged. PR16 merge51288fe7 exact reviewed955d5b09 tree verified;
all8 final-head and4 postmerge workflows passed (CodeQL39474664273,Tests39474663922,
Native39474664070,Security39474664219). All earlier branches/worktrees retained.
Phase6 code8940b35, audit74f522f, offline-build68fe29c, docs22af3c5 already pushed.
Python default; native0.4.2/wire3,report5/history1/checkpoint1 unchanged.
Local3 release tests,3120 deterministic mutation inputs,1 native structured corpus,
8 final offline packaging checks(52 runtime files),20 security tests passed.
Bandit0,actionlint/workflow0,pip-audit runtime/build/env0,cargo audit0/warnings0 and
fmt/Clippy passed. Actual commands/source in validation/RELEASE_RESULTS.md.
One synthetic SQLite baseline at8940b35:256 rows,3 samples,median801.23 saved
observations/sec. No network throughput/streaming-memory claim. Runtime SHA
1e9e1d186438e6a69b917c853982f6a63ca2ec45a38151c264bdd6bafedb73a6 unchanged.
Do not repeat passed regression/lab/benchmarks for documentation. Only changed-doc
link/diff/staged secret/privacy checks warranted now; preserve all security hooks.

## CI on remote22af3c5

Seven workflows passed. Remaining Tests PULL_REQUEST39476580289 attempt2 queued
at initial reconciliation. Correct event mapping:PR CodeQL39476580095,Security39476580394,
Native39476580105,Tests39476580289;PUSH CodeQL39476570007,Security39476570099,
Native39476570067,Tests39476569982. Earlier progress/PR prose mislabelled the events;
correct it without changing the actual outcomes. Historical privacy jobs skipped, not passes.
Attempt1 macOS was cancelled before tests:hosted Runner did not acquire job after
multiple attempts; other6 jobs passed, no assertion failure/log. One targeted retry
already issued for job118813979242, private marker6-macos-retry-issued.json; budget1.
Inspect state before any retry; no indefinite loop, weakening or runner/platform removal.

## Precise next action / preservation

Finish concise license-options and macOS policy docs, commit intended docs only
locally (no push/CI restart), update PR body from current remote text. Poll remaining
job at >=60s intervals; retain draft even if green while license undecided. No new
license grant, package metadata license, merge, publishing or rewrite authorized.
License comparison considers MIT/BSD,Apache2,GPL2-only/or-later,GPL3-only and actual
optional in-process Scapy GPL2-only/native subprocess distribution. No option chosen;
review ownership/distribution boundary/dependency notices before selection.
Next resume:read checkpoint, inspect local vs remote heads and PR/CI before action;
do not duplicate committed local docs or the already issued infrastructure retry.
Uncommitted checkpoint status notes only after local docs commit; preserve them
without status-only commits. Generated build artifacts ignored; private raw logs,
license source copies/captures remain outside Git. Historical privacy cleanup owner-pending.
Original unrelated UDP edit preserved/excluded SHA256
880894f38bc74007b1ad0d94609964f136667fe8be865e7466cb37535056893c.
