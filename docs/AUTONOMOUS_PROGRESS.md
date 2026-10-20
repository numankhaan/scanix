# Autonomous roadmap checkpoint

## Current stage: Phase 5C — final review before first push

Main/base:50e620f8200bb064bec4582dc3e12caaf9c70329, Phase 5B PR15 merged.
Main post-merge CodeQL39410692746, Tests39410692760, Native39410692787 and
Security39410692763 all passed; reverified on resume. Completed phases1–5B and
security8; remaining5C and6. PR14/15 implementations/measurements documented in
PLUGINS.md, OS_EVIDENCE.md and validation reports; branches retained.

Branch:phase5c/scan-history; worktree:scanix-phase5c. Two local commits already exist:
484d589cc2915b9fbc98c115759b803f7efe3b4e literal SQLite reserved prefix validation;
1ad69592a40788837a678e06d131aee0117835b8 UTF8 encoded-byte checkpoint limits.
Feature/CLI/tests/docs uncommitted while final review completes. No remote branch or
Phase5C PR at reconciliation; open PRs9/10 are independent dependency updates.

## Acceptance and implementation

Optional private SQLite schema1/report5 history, configuration/completion/evidence/
all version provenance, initial migration only and explicit unknown-schema rejection.
Aggregate and bounded native NDJSON upserts; invalid/crashed/interrupted saves partial.
Offline list/show/diff/delete/prune; actual observation changes only, absent rows never
imply removal/closure, service claims remain unauthenticated. Explicit retention,
private artifacts ignored/gated, no new dependency, no raw findings/artifacts uploaded.
Implemented history API, optional lazy backend, CLI persistence, bounded comparisons,
export preservation/type-only diagnostics, docs/HISTORY.md and tests. Schema-hidden
objects and encoded-byte safety guards also applied to existing native checkpoints.
No packet/scheduler changes; no privileged lab or benchmark repeat justified.

## Actual local validation

Trusted Python3.14.3/SQLite3.52, Scapy2.8.0; native0.4.2 binary from phase4c worktree.
`python -B -m unittest scanix.tests.test_history scanix.tests.test_checkpoint.ResumeLoopbackTests`:
32 passed at prior implementation milestone. Subsequent focused runs:3 encoded-byte
safety tests,1 optional-backend test and3 migration/version/tamper tests passed.
`python -B -m unittest discover -s security/tests`:20 passed. Suites overlap; not cumulative coverage.
Earlier12 checkpoint/schema-safety regressions passed. Bandit0 and diff check clean.
Full final platform matrix belongs to CI after consolidated push, currently not run.

## Preservation, limitations and precise next action

Original UDP edit preserved/excluded; SHA256
880894f38bc74007b1ad0d94609964f136667fe8be865e7466cb37535056893c.
History private, unauthenticated/not encrypted; logical deletion not secure erasure.
Postscan persistence does not recover a pre-save Python process crash. Native stream
supports that separate workflow. Privileged macOS/BPF remains incomplete; Linux lab
is not macOS validation. Historical privacy cleanup pending owner decision, no rewrite.
Prior native performance measured source66123724901cf85848a433bb2795b992c4a46ebd;
no new storage throughput claim. Phase5B15 OS capture checks passed as documented.

Next:finish consolidated code/export/checkpoint/privacy/docs review, verify actual help,
focused static/gates, commit intended feature then substantive docs. Scan outgoing
range+metadata before first push; push once/open PR with actual local results and
pending CI. Batch CI polls >=60s; inspect failures only, fix blockers without weakening
tests. Review current base/final diff/required9 checks/reviews before normal merge.
Verify main/post-merge CI and continue Phase6; no status-only commits or branch deletion.
Private raw logs/checkpoint backups remain outside repository, never publish them.

Final documentation/help review:scan --help, history --help and diff --help exit0;
actual flags/positions verified. Bandit history tree0 findings; no runtime changes
since focused passing migration/version/byte-limit tests. Diff check clean.
