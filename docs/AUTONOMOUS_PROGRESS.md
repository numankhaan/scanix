# Autonomous roadmap checkpoint

## Current stage: Phase6 — applying owner-selected GPL-2.0-only

Worktree scanix-phase6; branch phase6/release-validation; localHEAD0f1aefa18ba1a89076fd8615f908ea83cb36f326
(held docs, reviewed8 Markdown files). Remote PR17 OPEN/DRAFT targets main51288fe7,
remoteHEAD22af3c5651e09ae7111cc4ed40eb264d5e9491ec. No new push yet. User now
selects GPL-2.0-only subject to provenance/dependency compatibility, authorizes one
coherent update including held docs, readiness/normal merge after acceptance and
required final-head CI. No publishing/releases/history rewrite/force push/deletion.

## Provenance and compatibility actually reviewed

121 locally available commits; GitHub main110/PRbranch114 all owner-associated,
repository nonfork, contributors one/no other human.138 introduction records mapped
to owner-associated commits except held local doc author matching verified identity.
No tracked binary/document asset. Available code attribution review found no unexplained
third-party provenance; Git metadata is not proof of legal title, raw inventory private.
Owner authorization is licensing decision, no individual copyright holder/year invented.
All22 locked Rust archives checked against Cargo.lock; selected authentic MIT text
matches archive and cache. unicode-ident also Unicode3.0. Actual pinned Rust1.91.1
library notices MIT/Apache alternatives with BSD2/Unicode portions retained.30 full
notice files; no secret/privacy exception. Scapy2.8.0 GPL2-only checked primary tag/
metadata. Existing original CC0 data remains independent, not relicensed. Python
metadata GPL-2.0-only AND CC0-1.0; native own crate GPL-2.0-only; complete GPL copies.
Current pure Python wheel does not bundle interpreter/Scapy/OpenSSL/native code.
Actual PythonTLS runtime OpenSSL3.6.1 is Apache2, not GPL2-compatible. No material
conflict found in currently bundled code under selected terms; frozen/interpreter/
OpenSSL bundles expressly NOT cleared, require separate system-library/combination
permissions review. No third-party exception granted. Native binary linkage inspected,
no OpenSSL. Scope/source obligations documented in docs/LICENSING.md/root notices.

## Implemented, uncommitted increment

LICENSE/nativeLICENSE, authentic third_party notices/checksummed inventory; package/
Cargo metadata, source packaging, offline notice/primary-archive gate and native CI
fetch all locked platform sources then check offline; focused negative tests; license/
provenance/corresponding-source/build documentation. Data license fields unchanged.
All uncommitted changes are this intended increment and live checkpoint, no raw data.
Held0f1aefa macOS experimental/unverified raw policy retains tested unprivileged support.
No production packet/scheduler/runtime changes; measured runtime SHA1e9e1d186438e6a69b917c853982f6a63ca2ec45a38151c264bdd6bafedb73a6
and benchmark source8940b35 retained, no benchmark/privileged-lab rerun justified.

## Actual focused validation

4 licensing/package negative/scope tests passed; validation/licensing.py --cached:
22 primary archives/30 notices checked; package_smoke.py:9 checks passed,52 runtime
files, full wheel GPL/notices/License-Expression and source metadata/build/license
payload equality validated; actual installed unprivileged loopback/plugin/history
and reinstall checks passed.20 security tests passed; Bandit0,actionlint/policy0.
Cargo package --offline --locked --allow-dirty --list includesLICENSE; native release
build passed Rust1.91.1; native binarySHA d4c0cbfbc6e958aad8ab4f9fb6b86c972df3fcc5b9121ee70cfc488096ae1ae5.

## Precise next action / preservation

Finish offline vendored native source build verification and consolidated licensing/
package/export/privacy/docs review, outgoing gates, focused commit then ONE push to
PR17 including existing held doc commit. Update PR to final scope/actual tests. Old
remote-head PR Tests39476580289 attempts1/2 were hosted-macOS-runner acquisition
failures before tests; other6 jobs and7 other workflows passed. Do not retry old head
just before new push. After new push inspect required final-head CI, retry only a
proven runner-blocked macOS job where possible, bounded no platform bypass. Poll>=60s.
Review current base, all9 strict requirements, latest full native/security/regression/
CodeQL and review blockers before readiness/normal merge. Verify main/postmerge CI.
PR16 merge51288fe7 all8 final-head/all4 postmerge passed; phases1–5C/security8 merged.
Only now licensing/docs/build changes, no new features. No package/release publishing.
Historical privacy cleanup owner-pending, no rewrite/allowlist. Original unrelated UDP
edit preserved/excluded SHA256880894f38bc74007b1ad0d94609964f136667fe8be865e7466cb37535056893c.
Private raw logs/provenance/license-source copies stay outside Git. Retain branches.

Consolidated local validation complete:4 final licensing/package tests passed,
22 archive checks/30 notices verified,9 final package smoke checks passed. Native
release build/source LICENSE check and offline vendored corresponding-source build
passed; upstream Rust library metadata matches declaredMIT/BSD2/Unicode scope.
Final workflow actionlint/policy0,20 security tests/Bandit0, no gate exemptions.
Production import roots inspected:Scapy plus optional fallback Colorama outside stdlib/project. No benchmark/lab
repeat. Next:finaldiff/link/privacy review, stage intended files, commit once, outgoing
range gate, one push including held0f1aefa, PR update and new final-head CI.

Consolidated import review also checked optional Colorama0.4.6 (BSD3), primary
published-wheel checksum/license verified; complete authentic notice retained. No
new runtime dependency added; standard-library fallback unchanged. Total notices30.

Final source review:30 notices, optionalColorama0.4.6 primaryBSD3 verified (fallback
unchanged), Python requirement/metadata hashes bound to license policy.4 focused
tests,22 primary archives,9 package checks passed. Windows-style CRLF checkout
simulation caught nativeCargo metadata conversion; explicit attributes now preserve
LF/checksum files and authentic upstream bytes. Default license policy/all9 package
checks pass in simulated checkout. Two exact upstream notices retain trailing
spaces via per-file Git whitespace diagnostics only; no security exception.
Ready for one final licensing commit/push after outgoing gates; previous attempt
stopped before commit on upstream whitespace, no duplicate commit was made.
