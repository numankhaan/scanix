# Sanitized privacy/security audit

Feature roadmap paused. Security branch based on main `3a98cda`; no security merge
is authorized. Initial snapshot included the separately pushed Phase 4A `d08659e`.
No AGENTS.md or PR template was present. Raw evidence is retained privately outside
Git; this document contains no raw scanner matches, personal values or captures.
A clean scanner result cannot guarantee security or privacy.

## Actual initial scope

- Fetched origin branches/tags, 63 locally reachable commits, 505 objects, all
  available author/committer identities and messages; current tracked files,
  original staged/unstaged changes, and all worktree untracked inventories.
- 4,793 installed-dependency/build/cache files inventoried but not content-scanned;
  eight other untracked files scanned privately (security work-in-progress included).
  Two generic-key candidates were hashes in the new fixture-exception configuration,
  not credentials; the data structure was changed to keep default detection intact.
- Seven accessible PR/issue records, one comment, zero review comments. Text was
  scanned for secrets and narrow privacy patterns without reproducing values.
- All five accessible Actions artifacts, 108 extracted members, nine binary members;
  secret/pattern scans found no credential or home-path candidate. These were
  controlled lab artifacts. Binary strings are only partial metadata coverage.
- Thirteen historical bytecode blobs inspected as bytes/strings, never executed or
  unmarshalled; all contain embedded personal home-path strings. No binary document
  formats or LFS pointer objects were present; no tracked submodules were present.
- Python AST/Bandit analysis and manual review of packet/quote correlation, bounded
  parsers/registry, numeric service connections/TLS, targets, atomic file output,
  HTML/terminal/CSV output, subprocesses, privileged transport and workflow trust.
  Plugin modules are placeholders, not an implemented plugin execution boundary.
- Paused Rust branch lockfile audited against RustSec. Rust formatting,
  Clippy and unit validations are separately identified below; no native feature
  changes were made by this audit.

## Findings and remediation

| Severity/category | Sanitized location/reference | Result |
| --- | --- | --- |
| Medium: dependency advisory | `requirements.txt`; GHSA-cq46-m9x9-j8w2 | Previous range allowed affected Scapy 2.6.0/2.6.1 (local session/pickle loading, not proof of remote Scanix exploitation). Pinned 2.8.0; no advisory returned for this pin. |
| Medium: spreadsheet injection | `scanix/output/save_csv.py` | Formula-like text cells now prefixed with apostrophe; JSON retains original evidence. Real CSV export regression added. |
| Medium: system utility options | `scanix/modules/traceroute.py` | Reject option/control-bearing targets, validate hops, resolve fixed utility path, use bounded process timeout and Windows hop limit. No shell. |
| Low: terminal controls | `scanix/core/utils.py` | Shared printing strips control/format characters while preserving line/tab formatting. Existing HTML escaping retained. |
| Privacy review: current documentation | `PHASE3_PROGRESS.md`, initial lines 6/12 at `3a98cda` | Removed unnecessary commit email and personal absolute path. |
| Privacy review: historical metadata | 48 commits, one non-noreply personal identity; includes `d08659e` | Future repository-local email changed only after signed GitHub/account association verified. History unchanged; owner decision required. GitHub-generated public noreply identities are intentional. |
| Privacy review: history/bytecode | `scanix/**/__pycache__/*.pyc`, older progress records, paused `docs/AUTONOMOUS_PROGRESS.md` at `d08659e` | Raw details retained privately. Bytecode already absent from main; historical copies remain. Paused branch needs documentation sanitation before its next push. Cleanup plan prepared, not executed. |
| Informational: synthetic private keys | `scanix/tests/fixtures/tls/{ca,server}-TEST-ONLY.key:1`, introduced in `3c33b791767c` | Two public disposable fixture keys; exact file/content/rule exceptions only. Never use outside tests. No production-key rotation indicated by these findings. |
| Workflow hardening | `.github/workflows/` | Existing actions SHA-pinned; credentials not persisted; no automatic raw lab artifact uploads; added least-privilege gates, redacted CodeQL and Dependabot configuration. |
| Local tool environment | Initial pip 26.0 | Advisory scan failed; upgraded to 26.2.1 and re-audited successfully. Not a Scanix runtime dependency. |

Initial Bandit produced five low findings: optional color initialization, a boolean
probe-correlation field and fixed traceroute subprocess usage. These were manually
triaged. Error handling/validation was improved; remaining individual annotations
explain fixed executable/no-shell behavior and the boolean field. Final Bandit
reported zero findings; no broad rule skips or finding baseline added.

## Validation recorded so far

Tools: Gitleaks 8.30.1, pip-audit 2.10.1, Bandit 1.9.4, actionlint 1.7.12,
cargo-audit 0.22.2. Python 3.14.3 on macOS arm64; no public scans or privileged
network tests were run for this audit.

- Initial full-history Gitleaks: exit 1, two synthetic test-key findings, no other
  detected secret. PR/comment, original working changes, metadata/message and
  accessible artifact scans: exit 0. This does not establish absence of secrets.
- Scapy 2.6.0/2.6.1 dependency audits: exit 1, same advisory; pinned 2.8.0: exit 0.
  Updated audit tool environment: exit 0. RustSec lock audit: exit 0, zero
  advisories/warnings on paused native branch.
- Gate tests: fourteen passed, proving staged-vs-working bytes, intermediate/merge
  commits, new branches/deletions, event base/head ranges, merge-resolution secrets, metadata/message secrets, unavailable scanner,
  shallow clones, precise fixture exceptions, private patterns and SARIF redaction.
  Rejected synthetic samples are asserted absent from gate output.
- First isolated regression attempt: 90 tests, six import/setup errors because
  Scapy was absent from the new audit virtualenv; this was not a passing run.
  After installing audited Scapy: 119 tests, 117 passed/two privileged skipped.
  With the additional end-to-end CSV regression: **120 tests, 118 passed and two
  privileged skips**, exit 0. Hardened gate tests: **fourteen passed**, exit 0.
- Bandit, actionlint/workflow policy and pinned runtime/tool-environment audits passed locally after fixes.
- Historical privacy inventory: exit 1 (expected unresolved history): 108 email
  candidates, 24 home-path occurrences and 13 bytecode-file review flags. These
  remain visible and separate from new-change gates; no credential baseline.
- Paused native branch: `cargo fmt --check`, `cargo clippy --locked --all-targets
  -- -D warnings`, `cargo test --locked`: exit 0; six Rust tests passed. No native
  feature changes.
- First security head `3f0aa86`: push Security `39303305067` and Tests
  `39303305082` passed; PR Security `39303359676` and Tests `39303359675` passed.
  All seven platform/Python test jobs passed on each event. CodeQL push
  `39303305044` and PR `39303359667` failed with two `py/insecure-protocol`
  findings (tool severity high), at `scanix/service/transport.py:111` and
  `validation/service_lab.py:39`. These relied on context defaults; an explicit
  TLS 1.2 floor is now enforced at handshake boundaries without rule suppression.
  Verification opt-out does not enable obsolete protocols. A transport regression
  was added. TLS fix pushed as `4e3a00a`. Its local 121-test run had one new fixture
  error (missing operation_timeout); it was pushed before that result was checked.
  The fixture is corrected in the follow-up; this failed run is not a pass.
- GitHub's API confirmed uploaded alert messages use the fixed redacted message,
  not the original finding text. No raw SARIF/database was uploaded.

## Coverage limits and owner actions

Deleted/inaccessible remote Git objects, forks/clones/caches, expired/inaccessible
artifacts and unenumerated remote refs are not covered. Accessible artifacts were
scanned as bytes/strings; comprehensive semantic packet/binary metadata privacy
review is not claimed. General Actions run logs, account secrets/settings, external
private files, installed/build/cache content and arbitrary encoded/encrypted data
were not scanned. No assurance covers unsupported formats, detector blind spots or
new advisories. No LFS/submodules existed in the enumerated tree/history; future
ones require separate handling. Private regex patterns cannot be enforced by public
CI unless safely made available; local configuration is explicitly external.

GitHub reports secret scanning/push protection enabled. No rulesets/main protection
were verified; Dependabot security updates and some secret options need owner setup.
Version-update configuration is added, activation after merge still needs checking.
No production credential was detected, so no specific rotation is prescribed;
any subsequently confirmed credential must be rotated by its owner. Historical
cleanup and private reporting setup are owner decisions. See SECURITY.md and the
separate history plan. Privileged macOS/BPF validation remains explicitly incomplete.

TLS fixture follow-up: full local rerun **121 tests, 119 passed/two privileged
skips**, and all 14 then-current gate tests passed. Missing test budget fixed;
no assertions weakened. The earlier failed run remains recorded above.

Additional prevention: Scanix JSON/CSV/HTML export shapes are detected regardless
of filename, common credential containers/environment directories are flagged,
email candidate matching is bounded and malformed scanner results fail safely.
A one-megabyte adversarial-text regression checks scanner progress. Gates now have
16 tests. Local hooks accept an explicit Python launcher override for Windows.

TLS-floor CI at `4e3a00a`: CodeQL push `39304016664` and PR `39304056735`
passed; Security push `39304016596` and PR `39304056684` passed. Tests push
`39304016584` and PR `39304056633` failed on the recorded incomplete test budget.
The subsequent fixture correction is local `9f6caee`, with the passing rerun above.

## Final coverage follow-up

Local `git fsck --full --no-reflogs --unreachable` passed. Its additional three
commits, ten blobs and six trees were inventoried; available content/metadata
secret scanning returned zero findings, with seven historical email review
candidates retained privately. Local Git configuration secret scan passed.
Three tag refs include two annotated tag objects: secret scan passed; two personal
email candidates remain historical exposure. No PR attachment links were present.
Nine artifact pcaps were decoded **offline** with system tcpdump, all successful;
this does not establish that arbitrary payloads contain no private/encoded data.

Prevention now also checks path text and annotated/nested tag metadata/messages,
including outgoing tags with no new commit. Gate tests: **18 passed**; full-history
secret gate including tags passed. No new secret exception was introduced.

At `f02cf86610fac0bd4d9c4ea6b50a1c49a807f85d`, all push and PR workflows passed:
Security `39304666932`/`39304679135`, CodeQL `39304666952`/`39304679123`,
Tests `39304666938`/`39304679100`. Final path/tag coverage follow-up CI will run
on its new head; do not transfer earlier results to an untested SHA.

Before Phase 4 resumes, synchronize these reviewed security changes into the
paused native branch, sanitize its current progress text and pin its native
workflow actions. That branch is intentionally not merged/modified here. CodeQL
coverage here is Python; the unmerged Rust branch received RustSec/Clippy/unit
checks, not a Rust CodeQL analysis. Historical exposure still needs owner review.

Final history inventory including tags: exit 1 as expected for unresolved privacy,
110 email candidates, 24 home-path occurrences and 13 bytecode review flags.
The seven unreachable-object email candidates are a separate local inventory.
At f02cf86 each CI platform ran 121 regressions: Linux/macOS 119 passed/two
privileged skips; Windows 118 passed/three skips (including the existing POSIX-only
interrupt test). These skips are not successful privileged validation.
