# Phase 3 progress

## Repository and integration verification

- No applicable AGENTS.md or PR template was present.
- Origin: git@github.com:numankhaan/scanix.git; default branch main. SSH transport
  was unavailable; fetch/push used the same origin repository's HTTPS URL.
- PR #4 is merged into main, with passing CI.
- PR #5 originally merged into phase1/tcp-connect-reliability. Main at ece9bd0
  lacked Phase 2, confirmed by ancestry and tree diffs. Recovery PR #7 has now
  merged Phase 2 into main as ad61a83, resolving that dependency.
- Isolated worktree: /Users/nouman/Downloads/scanix-phase3, branch
  phase3/service-identification. It started from updated main and normally merged
  Phase 2 as 3bf9831, preserving existing commit ancestry.
- PR #6: https://github.com/numankhaan/scanix/pull/6, retargeted to main after
  PR #7 merged. Normal merge 32e5e2d synchronizes Phase 3 with main at ad61a83.
  It changed only progress records; application files exactly match delivered
  Phase 3 head 44843e0. The resulting main-to-PR diff contains Phase 3 and
  integration documentation, without repeated Phase 2-only files. Final merge
  commit and post-merge CI outcomes are recorded in PR #6.
- Original worktree's unrelated scanix/modules/udp_scan.py edit was preserved and
  excluded. Its recorded SHA-256 is
  880894f38bc74007b1ad0d94609964f136667fe8be865e7466cb37535056893c.

## Implemented and committed

- ef5cd07: original versioned registry, safe finite matchers, pure protocol parsers,
  shared minimal UDP helpers and per-signature fixtures.
- 3c33b79: bounded service engine and numeric-endpoint transport; TLS verification,
  SNI, explicit insecure mode, optional upgrades; reports, CLI/preview, exporters,
  profiles, exclusions, cancellation and reproducible public test certificates.
- 6770228: parser-controlled fragmented response framing, multiline SMTP, IPv6
  verified TLS, DNS/NTP fallback budgets and stricter registry validation.
- cb594e1 follow-up: stop all fallback connections after observed protocol/TLS evidence
  when a capability/application follow-up fails; preserve the evidence and error.
- 4196bde registry follow-up: hard-limit file reads before JSON parsing and test the
  actual read bound.
- Final pacing follow-up: sample the monotonic clock while holding the scheduling
  lock, with a deterministic pre-lock-descheduling regression.
- f9eb60f documentation/lab increment: README, ROADMAP, exact service semantics, this
  progress record, actual validation results and an unprivileged CLI lab driver.

## Validation

Final local suite with Python 3.14.3 and each of Scapy 2.8.0 / 2.6.1:
115 run, 113 passed, 2 privileged skips. Four real CLI loopback cases passed. Certificate regeneration
reproduced all four PEMs byte-for-byte. No public targets were scanned.

Original Phase 3 CI at 44843e0 passed all seven Linux/macOS/Windows PR and push jobs,
each running 115 tests. Those delivery runs skipped two privileged cases on
Linux/macOS; Windows also skipped the existing POSIX subprocess SIGINT case.
Integration local reruns after synchronizing main at ad61a83 again ran 115 tests
with 113 passed and two skips under each Scapy version (9.126 / 9.074 seconds),
and all four real CLI loopback cases passed. Updated-base integration CI and final
post-merge main results are recorded in PR #6. See
[precise evidence](validation/SERVICE_RESULTS.md). Later-head/PR checks must be
reported from their actual statuses; previous passes do not certify queued checks.

## Remaining limitations and follow-up

Implementation covers the documented initial protocols and required controls.
Broad interoperability is unverified beyond original fixtures and local services;
unsupported variants remain unknown. HTTP/2, FTP TLS, exhaustive cipher discovery,
virtual-host enumeration and richer insecure-certificate parsing are not delivered.
Certificate revocation/chain export are absent. TLS handshake bytes are bounded
by the backend/deadline rather than the application-data counters. Low rate/time
budgets may prevent later fallback probes; issues/attempt counts disclose this.

The Phase 2-to-main dependency is resolved by #7. Optional privileged Phase 2
validation is retained with its previous Linux evidence; no fresh privileged run
is claimed for integration. Privileged macOS/BPF remains explicitly incomplete.
Integration merges require reviewed diffs, passing checks and no unresolved review
blockers; no force-push, branch deletion or required-check bypass is used. Phase 4
has not started.
