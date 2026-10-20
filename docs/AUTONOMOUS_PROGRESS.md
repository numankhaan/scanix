# Autonomous roadmap checkpoint

## Current stage: Phase 5A — reviewed implementation, prepare PR/CI

- Authorized: focused feature branches/commits/PRs/normal merges after current base,
  required/latest checks and resolved review blockers. No force push, bypass, branch
  deletion, public scans, history rewrite or public release/package publishing.
- Completed: phases 1–3, security #8, 4A #11, 4B #12, 4C #13. Main is
  5d393f03240014dbcc2c9acb8823e1f8db76ff87; post-merge CodeQL39404598231,
  Tests39404598222, Native39404598243, Security39404598339 all passed.
- Current branch:phase5a/enumeration-plugins; sibling worktree scanix-phase5a.
  Feature commit:d0182965abaa81fef36529b2412d9764cad0d2c8. Documentation commit
  follows; resolve current HEAD with git before resuming. No Phase5A PR/push yet.
- Main retains nine strict required checks, secret scanning/push protection and
  reviewed local hooks. Original unrelated UDP edit remains excluded and unchanged:
  SHA256 880894f38bc74007b1ad0d94609964f136667fe8be865e7466cb37535056893c.

## Phase5A acceptance and implemented behavior

Versioned trusted builtin API1/registry1.0.0; working HTTP HEAD, direct TLS metadata,
passive SSH identification and minimal correlated UDP DNS, including unusual ports.
No auth, exploitation, arbitrary module loading or sandbox claim. Only observed open
selected numeric endpoints, matching transport, printer exclusions and declared
intrusive opt-in (no intrusive builtin shipped). Fixed worker argv, bounded IPC,
parent-paced operation tokens, deadlines/kill/reap, bounded pending endpoint workers.
Schema5 JSON/CSV/HTML/NDJSON, separate plugin evidence/status/counters, no port-state
changes. Native durable enrichment upserts, completed outcome retention and retry of
missing/interrupted outcomes. Compatibility hashes include configuration, schema,
production Python/plugin code; schema4 checkpoints require a new scan.

Acceptance still pending: final-head full platform CI/security, review blockers,
normal PR merge, main post-merge CI. Do not mark complete or merge while pending.

## Actual validation and review

- Consolidated code/export/checkpoint/privacy/documentation review completed before
  initial push. JSON tuple round-trip defect found and fixed; focused export tests pass.
- Full local discovery initially188 tests:two export failures, three expected skips;
  corrected tuple serialization validated without repeating full discovery.
- SCANIX_NATIVE_ENGINE=<existing unchanged Phase4C binary> python -B -m unittest
  scanix.tests.test_plugins scanix.tests.test_scanix.ExportTests
  scanix.tests.test_checkpoint.ResumeLoopbackTests:30 tests passed.
- Subsequent focused actual CLI HTTP IPv4/IPv6 test:1 passed. scan --help:success;
  new flags/examples verified against parser and owned loopback listeners.
- python -B -m unittest discover -s security/tests:20 passed;
  python -B security/run.py bandit:zero findings; git diff --check:passed;
  staged secret/privacy + prospective metadata gate:passed (no findings).
- Tests include malformed/oversized/duplicate/API/token worker failures, cancellation,
  TLS trusted/self-signed/mismatch, scope/exclusions/intrusive contract, paced calls,
  concurrency, output escaping and actual native aggregate/stream/resume.
- Full final-head matrix is delegated to CI (expected189 tests/job, platform skips).
  No new dependency or security exception. No raw results/captures/reports committed.
- No packet scheduler/transport changes:existing isolated lab39400801059 at6612372
  remains33 passed checks, not a claim of a new-head lab. Existing benchmark source
  66123724901cf85848a433bb2795b992c4a46ebd; later exporter/docs/resume guard and this
  opt-in plugin stage were not rebenchmarked. No plugin throughput claim.

## Limitations and precise next action

Historical privacy cleanup awaits owner decision; no rewrite/allowlist. Privileged
macOS/BPF remains incomplete. Plugins are trusted same-user processes, no OS sandbox
or hard RSS quota. HTTP plugin is plaintext, TLS plugin direct only; existing Phase3
STARTTLS/HTTPS remain separate. Unknown/timeouts/errors are terminal enrichment
outcomes for a checkpoint; port coverage does not imply successful enrichment.

Commit reviewed docs; scan outgoing snapshots/metadata, push once, open/reuse Phase5A
PR into main, record URL/head/run IDs here. Batch CI queries >=60s apart; use detailed
logs only for failures. Resolve correctness/security blockers without scope expansion,
then final diff/base/checks review and normal merge. Verify main/post-merge CI; carry
this checkpoint into Phase5B (remote packet OS evidence), then5C history and6 RC.
Current uncommitted files:reviewed documentation/checkpoint awaiting documentation
commit only; feature code committed. Keep live CI status updates uncommitted until
carried with a substantive milestone; no status-only commit. Private evidence pointer
/tmp/scanix-security-session (never publish raw contents).
