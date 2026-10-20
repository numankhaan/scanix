# Autonomous roadmap checkpoint

## Current stage: Phase 4C — final PR checks/review

Owner authorizes autonomous stage implementation, focused commits, push, PR review
and merge after completion/current base/passing required checks/no review blockers.
No force push, bypass, branch deletion, public scans, history rewrite or public release.

- Main: `66f0455e6d69c0807de04e84f9c391dbd07776c5`, Phase 4B #12 merged.
  Post-merge Security 39343940342, CodeQL 39343940329, Native 39343940313 and
  Tests 39343940358 all passed. Branches retained, strict security/regression rules intact.
- Completed: phases 1–3, security #8, 4A #11, 4B #12. Remaining: 4C merge,
  5A informational plugins, 5B remote OS evidence, 5C SQLite history, 6 release validation.
- Worktree: sibling `scanix-phase4c`; branch `phase4c/durable-streaming` from main.
  PR https://github.com/numankhaan/scanix/pull/13 (base main; draft until final acceptance).
  Recorded implemented HEAD: `10df427316d9c630ba75f60dae55794a628a9a9a`.
  This final docs/gate-envelope follow-up is subsequent; inspect `git rev-parse HEAD`.
- Commits: 0d29468 protocol/selection, 90d3f37 durable streaming, cfc3eed Windows/
  CodeQL fixtures, 75ce1ed batching, fbbee23 sparse flush, c41a46f compatibility/schema,
  e117a76 cached terminal cursors, 6612372 artifact prevention, 10df427 inline-export guard.
- Original unrelated UDP edit remains in original worktree, never stage it. Expected
  SHA-256: 880894f38bc74007b1ad0d94609964f136667fe8be865e7466cb37535056893c.
  Historical privacy cleanup still awaits owner decision; no new allowlist/rewrite.

## Acceptance and implemented behavior

Protocol 3/engine 0.4.2, report schema 4, checkpoint/NDJSON format 1. Python default
and aggregate workflows retained. Native connect (IPv4/IPv6) and Linux IPv4 SYN support
exact compatible continuation, target-major IDs/modulo shards and engine-enforced
completed skips. Hashes cover config, resolved associations/order/exclusions, native
binary, production Python/probe bytes and explicit CA content. No fallback or migration.

Private SQLite FULL/exclusive-writer fixed-schema checkpoints, at most 64-record batches
(default16), .25s sparse flush target, commit before emission, cancellation/final flush;
crash replay is at least once for uncommitted/in-flight/queued work. Unknown old counters
stay unknown; known loss is sticky. Bounded NDJSON upserts/replay; zero retained report
result objects. Inline JSON/CSV/HTML writers reject nonretained summaries before writing.
Separate paced/limited enrichment preserves port states. Source/record/file/queue limits
and actual supported/unsupported methods are documented in docs/CONTINUATION.md.

Security extension is additive: forbid NDJSON/SQLite sidecars, recognize renamed stream
headers; synthetic negative/redaction tests, no exception/permission/severity weakening.

## Actual validation

- Local `python -B validation/native_ci.py`: **169 run, 166 passed, three skips**
  (two optional privileged cases and Linux-only native SYN preflight on macOS).
  Real loopback: cancel/resume, unchanged completed-connection counts, shard union,
  completed replay without child, CLI, service-state preservation, stream write failure.
  Deterministic: batch deadlines/atomicity, crash, schema collisions, scope/config/
  binary/Python/registry/CA compatibility, bounded bitmaps, output rejection.
- `cargo test --locked --manifest-path native/Cargo.toml`: **22 passed locally**.
  fmt, release build, strict Clippy and Linux aarch64 cross-Clippy passed; cross-build
  is not execution. Source 6612372 CI: Linux/MSRV **24**, macOS/Windows **22** Rust.
- Security tests **20 passed**, Bandit zero findings, workflow policy/actionlint,
  tree/staged/outgoing secret/privacy gates passed. Final envelope test aligns valid
  stream headers with the complete bounded frame size; do not count tests not run.
- At 66123724901cf85848a433bb2795b992c4a46ebd all eight push/PR workflows passed:
  Security 39400797219/39400802966; CodeQL 39400797180/39400802968;
  Tests 39400797179/39400803028; Native/MSRV 39400797147/39400803142.
  Python 168/job: native Linux166/two skips, macOS165/three, Windows164/four;
  ordinary Linux/macOS153/15, Windows152/16. Skips are not passes.
  Subsequent inline-export test adds one; final-head CI must be checked separately.
  Historical privacy jobs are separately skipped on push/PR, not resolved/passed.
- Earlier 90d3f37 Windows failures were test connection leaks (WinError32 cleanup).
  Explicit fixture closure fixed them. CodeQL permissive synthetic fixture was replaced
  with mocked unsafe metadata plus no-open assertion; no suppression/assertion weakening.
- Isolated privileged Linux run **39400801059** at 6612372 passed **33 native checks**
  plus retained Phase 2 lab/optional loopback coverage. Captures prove resume skips
  completed SYN ports and completed replay sends no probes. Six captures, measured
  drops zero, all expected states. Earlier fbbee23 run39399173545 also passed.
  The exporter/gate/docs follow-up changes no packet/scheduler/checkpoint algorithm.
- Source6612372 clean loopback baseline, 128 listeners, three workers/mode/batch:
  stream batch1 median2.208202s (128 commits/2.011454s); batch16 .523470s
  (eight/.124700s). Aggregate .412–.415s, still faster. Zero retained report rows,
  small-case traced/RSS overhead higher; no large-scan memory/speed or parity claim.
  Exact hardware, boundaries, CPU/RSS, captures and reproduction:
  validation/CONTINUATION_RESULTS.md. Raw artifacts stayed private; none uploaded.
- Actual CLI help and README shard preview verified; checkpoint CLI exercised with
  controlled local listeners. `--preview` performs no checkpoint/hash/child/probe activity.

## Precise next action

Commit/push intended final docs and stream-gate envelope test. Inspect all latest-head
Security/CodeQL/Tests/Native/MSRV outcomes; queued/running is not pass. Update PR #13
body with final head/results. Review whole diff, effective required checks, current base,
reviews/threads and server branch-retention setting. Ready/merge only when complete and
all latest checks pass; no bypass/delete. Verify main/post-merge CI, then branch Phase5A
from updated main and replace this checkpoint with its concrete acceptance/next action.

Current uncommitted files: final README/roadmap/native/continuation/measurement/checkpoint
docs and targeted security header-envelope test only. No raw reports/captures staged.
Private evidence pointer: `/tmp/scanix-security-session`. Reconcile Git/GitHub before
repeating any push, dispatch, ready or merge. Privileged macOS/BPF remains incomplete;
native IPv6 SYN/UDP/discovery unsupported. No new external blocker for Phase4C.

## Final-head reconciliation

955a861a81b77b0883a0d92ac7a6328519157ffe was pushed; all eight latest-head workflows
passed (Security39402955006/39402960791, CodeQL39402954978/39402960727,
Tests39402955374/39402960825, Native39402955391/39402961189). Native Python169/job,
Rust Linux/MSRV24/non-Linux22; security20 tests. Main is still66f0455; required nine
contexts/strict base verified, no branch deletion, one resolved review thread/no blockers.
Final review found the resume guard skipped sessions with zero completed rows despite
possible previous sends. Fixed guard for every resumed nonempty session; deterministic
wait/decreased-budget regression added. Local native170 run,167 passed/three skips.
Commit/push this focused fix, inspect replacement latest checks, update PR body, merge
normally only when green, then verify main/post-merge and continue Phase5A. Prior final
commit/push operations succeeded; do not repeat them. No scanning algorithm/data scope
or measured baseline claim changed; the new case is a pre-send pacing edge condition.
