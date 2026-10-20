# Autonomous checkpoint: first Git release candidate

## Current task / acceptance
Prepare v1.0.0rc1 from main through a focused release-readiness PR; merge only after
current-base required CI/review acceptance. Then create/push one annotated tag with
verified noreply tagger identity and exact main commit. Never move an existing tag.
No GitHub Release, packages, binaries, v1.0.0, history rewrite or branch deletion.

## State and completed operations
Worktree scanix-rc1; branch release/1.0.0rc1; base/main
09b51052e395730ca264611efadbc1b6dcf2e324. No release PR/commit/tag yet.
Main's CodeQL39490752269/Tests39490749867/Native39490749882/Security39490749826
all passed. PR17 merged after all8 final-head workflows/all9 strict checks passed.
Package/CLI1.0.0rc1, native0.4.2/wire3 independently versioned. Remote tags only
v0.1.0/v0.2.0; local v1.0-base retained and will not be pushed. RC tag absent.
Added consolidated CHANGELOG, source-package inclusion, actual distribution-version
assertion and changelog source-byte check; corrected stale candidate status.
No runtime packet/scheduler changes; reuse prior exact-source Linux labs, native
source-build/license review, parser/security regressions and benchmarks.

## Private historical exposure review
Fresh `security/check.py history --privacy-only` on123 locally available commits
exit1:112 email-review,24 home-path,13 forbidden bytecode flags. Historical
metadata, PHASE2_PROGRESS/PHASE3_PROGRESS, preserved native checkpoint and13 old
bytecode blobs remain unresolved; two old annotated tags also reviewed privately.
Retained secret inventory only identified two documented disposable TLS test keys,
not production credentials. No raw identities/patterns/findings enter Git or PRs.
New tag will point to already public main ancestry, not additional historical
branches. New tagger is verified public noreply; proposed message contains version/
validation/limitation text only. Confirm tag/outgoing range gate before push.
No finding is silently accepted or cleaned; unresolved history remains available.
Unavailable/deleted remote objects, expired artifacts, forks/clones/caches and
unsupported binary semantics are not newly covered by this focused release review.

## Actual validation / next action
4 focused licensing/package tests passed; license gate22crates/30notices passed;
isolated package acceptance all9 checks passed,52runtime files,version1.0.0rc1.
Exact commands in validation/RELEASE_RESULTS.md; raw logs private. Extra focused
Bandit helper review:2 existing LOW B404/B603 advisories manually triaged as
controlled shell-free/bounded build subprocesses, no suppression or confirmed defect.
Next: review scope/links/version/source delivery, staged and outgoing gates.
Commit intended files, push once/open readiness PR, use CI fullplatform matrix.
Poll in batches>=60s. After strict checks/currentbase/review pass, normal exacthead
merge, verify main/postmerge CI, then create/check/push annotated v1.0.0rc1 once.
No unrelated test, privileged-lab or benchmark repetition.

## Preservation / limits
Original unrelated UDP edit stays in original worktree, SHA256
880894f38bc74007b1ad0d94609964f136667fe8be865e7466cb37535056893c, excluded.
Prior phase6 live checkpoint preserved there. Intended uncommitted files are only
this release increment/checkpoint; private evidence remains outside Git.
Privileged macOS raw SYN/UDP/ICMP/ARP/ND experimental/unverified, tested unprivileged
Mac retained. Native SYN LinuxIPv4-only. Python/OpenSSL bundles not cleared byGPL2
review. No public-network traffic, publication or parity/security guarantee.
