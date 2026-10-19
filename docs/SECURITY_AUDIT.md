# Sanitized security/privacy audit

Security work is proposed in [PR #8](https://github.com/numankhaan/scanix/pull/8),
base main `3a98cda`. The PR remains unmerged and Phase 4 is paused pending review.
Raw evidence stays outside Git in access-controlled local storage. Passing checks
cannot guarantee security or privacy.

## Actual scope

- Initial fetched history: 63 reachable commits/505 objects across available
  branches and three tag refs; full author/committer metadata and messages.
  Two annotated tags were separately inspected. Preventive checks now include
  nested tag messages/taggers and historical binary ASCII-string views, because
  Git patch output omits binary bodies. No history was rewritten.
- Current tracked/index content, original staged/unstaged edits, progress records,
  workflows, examples, fixtures and local Git configuration. The unrelated UDP
  modification remains untouched; no raw reports or captures are tracked.
- Untracked files were audited privately: eight non-cache files initially;
  follow-up inventory of 4,797 dependency/build/cache entries, 4,793 read and 3,371
  unique content inputs scanned. Four non-regular interpreter links were not read.
  Source/binary strings were examined, not arbitrary binary semantics.
- Local object integrity passed. Three additional unreachable commits, ten blobs
  and six trees were inventoried; available content and metadata were scanned.
- Eight accessible PR/issue descriptions, two comments, zero review comments;
  decoded text secret/privacy scans passed. No attachment links were present.
- All five accessible Actions artifacts: 108 extracted members, including nine
  pcaps decoded offline using system tcpdump. ASCII text views were secret-scanned
  without relying on binary filename handling. No raw evidence was reuploaded.
- Manual review covered packet/ICMP correlation, bounded parsers/registry, numeric
  service connections/TLS, targets, subprocesses, paths/atomic exports,
  HTML/terminal/CSV output, cancellation, privileged I/O and workflow trust.
  Enumeration plugin modules remain placeholders.
- The paused native branch received a RustSec lock audit, formatting, Clippy and
  six Rust tests. This main-based PR contains no native feature implementation;
  its CodeQL workflow analyzes Python, not the unmerged Rust branch.

## Findings and fixes

| Category/severity | Sanitized location/reference | Disposition |
| --- | --- | --- |
| Dependency, medium | `requirements.txt`; [GHSA-cq46-m9x9-j8w2](https://github.com/advisories/GHSA-cq46-m9x9-j8w2) | Previously permitted Scapy 2.6.x is affected by local session/pickle loading. Pinned 2.8.0; audit returned no advisory for that pin. This is not evidence of remote Scanix exploitation. |
| CSV injection, medium | `scanix/output/save_csv.py`, `5abb5a4` | Formula-like text cells receive an apostrophe; actual CSV export regression added. JSON retains original evidence. |
| Utility option handling, medium | `scanix/modules/traceroute.py`, `5abb5a4` | Validate targets/hops, resolve a fixed executable, enforce process timeout and Windows hop limit; no shell. |
| TLS policy, high tool severity | `scanix/service/transport.py:111` and `validation/service_lab.py:39` at `3f0aa86` | CodeQL identified reliance on context defaults. Explicit TLS 1.2 floor enforced at handshake boundaries in `4e3a00a`; verification opt-out does not enable obsolete protocols. No query suppression. |
| Terminal controls, low | `scanix/core/utils.py`, `5abb5a4` | Shared printing removes control/format characters. Existing HTML escaping retained. |
| Current progress privacy review | `PHASE3_PROGRESS.md:6/12` at `3a98cda` | Removed an unnecessary public noreply address and a personal absolute path. |
| Historical privacy review | 48 initial commits, one non-noreply personal identity; two annotated tags; includes `d08659e` | Future repository-local email verified through a signed account-associated GitHub commit. Existing metadata unchanged; owner review/cleanup decision required. |
| Historical path exposure | Older progress records and `scanix/**/__pycache__/*.pyc` | Thirteen bytecode blobs contain personal home-path strings; absent from current main tree but still in history. Separate cleanup plan prepared, not executed. |
| Synthetic private keys | `scanix/tests/fixtures/tls/{ca,server}-TEST-ONLY.key:1`, introduced at `3c33b791767c` | Public disposable fixtures. Only exact path/content/rule exceptions; no fixture-directory exclusion. Never use these keys outside tests. |
| Local environments | Initial audit pip 26.0; older project venv pip 25.3/Scapy 2.6.1 | Upgraded to pip 26.2.1/Scapy 2.8.0. Verified 846 package-record hashes and no unrecorded source before updating the older venv. Both environment audits then passed; unrelated packages/source edits preserved. |

No production credential was identified. GitHub's accessible secret-alert list was
empty. No credential was used, revoked or rotated. Any subsequently confirmed real
credential needs owner-led rotation/revocation, regardless of history cleanup.

Historical privacy inventory remains **failing**, not clean: 110 email candidates,
24 home-path occurrences and 13 bytecode review flags. Seven unreachable-object
email candidates are a separate local inventory. Public GitHub-generated identities
and reserved fixture domains are distinguished from personal candidates.

Local dependency/build/cache patterns yielded 16,982 path, 990 email, seven URL and
one phone candidates. These include compiler paths, public package authorship and
examples. URL/phone candidates were package documentation or controlled test data.
The sole secret candidate was the known synthetic token in generated test bytecode,
verified against the constructed fixture without displaying it. No new exception
was added: caches remain ignored, and forced additions are blocked. Individual
ownership of every third-party/binary email candidate was not exhaustively verified.

## Validation and CI

Tools: Gitleaks 8.30.1 (MIT), pip-audit 2.10.1/Bandit 1.9.4 (Apache-2.0),
actionlint 1.7.12 (MIT), cargo-audit 0.22.2 (Apache-2.0/MIT), CodeQL action v4
with security-extended. Official documentation/licensing references are in SECURITY.md.
Local Python 3.14.3/macOS arm64; no public targets or privileged networking used.

- Full-history secret gate, including commit/tag metadata and binary ASCII views:
  passed, with only the two documented synthetic key exceptions.
- **19 security tests passed**, including index-vs-working content, intermediate
  and merge-only secrets, nested-tag push ranges, binary secrets, metadata,
  missing scanners/history/Git context, invalid event bases and input boundaries,
  private patterns, long input, export shapes, environment containers and SARIF
  redaction. Rejected synthetic values are asserted absent from output.
- **121 regressions: 119 passed/two privileged skips**, including in the remediated
  older project venv. Bandit found zero; actionlint/workflow policy passed;
  pinned runtime and tool/project environments returned no dependency advisories.
- Paused native branch: RustSec zero advisories/warnings; fmt/Clippy passed;
  six Rust tests passed. No claim of Rust CodeQL coverage.
- At `22a95dea32cd0d24f7649a311b40cf56c1e6c672`, all push/PR workflows passed:
  Security `39305925933`/`39305934391`; Tests `39305925967`/`39305934230`;
  CodeQL `39305925905`/`39305934034`. All seven test-matrix jobs passed.
  Linux/macOS: 119 passed/two skips; Windows: 118 passed/three skips, including
  the existing POSIX-only interrupt case.
- Final resume follow-up adds environment-name coverage, nested-tag event tests,
  explicit binary-string secret views and private Git-failure handling. It has the
  local results above; its new-head CI must be checked after push. The PR records
  the latest exact tested SHA/run results; earlier passes do not transfer to it.

Earlier failures are retained accurately: first isolated test run lacked Scapy
(90 tests, six import/setup errors); installing audited Scapy resolved it. Initial
pip/Scapy audits failed before upgrades. CodeQL on `3f0aa86` failed two TLS findings
(push `39303305044`, PR `39303359667`); fixed without suppression. The first new
TLS fixture omitted operation_timeout and was pushed before that local failure
was checked: Tests `39304016584`/`39304056633` failed. `9f6caee` supplied the missing
budget; no assertion was weakened. Later full test matrices passed. The binary
regression also exposed scanner binary-file handling during development; explicit
text views now detect that case. No failing attempt is counted as passing.

## Remaining actions and limits

Secret scanning/push protection were verified enabled. Main is unprotected and has
no rulesets. Dependabot alert API returned 403 reporting disabled; security updates
were also disabled. Private vulnerability reporting was verified disabled. Owner
setup is documented in SECURITY.md. Version-update workflows/config activate on
the default branch only after review/merge; this PR has not configured protection.
Historical privacy review is separately failing weekly/manually, not silently
baselined. No raw SARIF/database/capture uploads are enabled by these workflows.
Uploaded CodeQL alert messages were verified to use the fixed redacted text.

Deleted/inaccessible remote objects, forks/clones/caches, inaccessible/expired
artifacts, general remote run logs and external files/link targets are not covered.
Binary views inspect printable ASCII, not complete format semantics, encrypted data
or every encoding. No LFS pointers or tracked submodules were found; future ones
need separate handling. Private local patterns are not automatically available to
public CI. Detectors and advisory data have false positives/negatives and change.

Privileged macOS/BPF remains incomplete. Before Phase 4 resumes after security
review, synchronize approved security changes, sanitize the paused native branch's
progress text and pin its native workflow. No feature work resumed. The separate
history-cleanup plan requires authorization; no rewrite, force-push, branch/evidence
deletion or account-wide configuration change was performed.
