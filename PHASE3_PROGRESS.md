# Phase 3 progress

## Repository and dependency verification

- No applicable AGENTS.md or PR template was present.
- Origin: git@github.com:numankhaan/scanix.git; default branch main. SSH transport
  was unavailable; fetch/push used the same origin repository's HTTPS URL.
- PR #4 is merged into main, with passing CI.
- PR #5 is merged, but GitHub reports its base as phase1/tcp-connect-reliability,
  not main. Updated main (ece9bd0) does not contain Phase 2 head 3dbad9c.
- Isolated worktree: /Users/nouman/Downloads/scanix-phase3, branch
  phase3/service-identification. It started from updated main and normally merged
  Phase 2 as 3bf9831, preserving existing commit ancestry.
- PR #6: https://github.com/numankhaan/scanix/pull/6, base
  phase2/scanning-accuracy. This compares only Phase 3 changes. Neither earlier PR
  was retargeted or merged by this work. Phase 2 still needs to reach main before
  Phase 3 can be integrated there. No force-push was used.
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
- Final follow-up: stop all fallback connections after observed protocol/TLS evidence
  when a capability/application follow-up fails; preserve the evidence and error.
- f9eb60f documentation/lab increment: README, ROADMAP, exact service semantics, this
  progress record, actual validation results and an unprivileged CLI lab driver.

## Validation

Final local suite with Python 3.14.3 / Scapy 2.8.0: 113 run, 111 passed,
2 privileged skips. The preceding 112-test suite independently passed with both
Scapy 2.8.0 and minimum 2.6.1 (110 passed, 2 skips each). Four real CLI loopback cases passed. Certificate regeneration
reproduced all four PEMs byte-for-byte. No public targets were scanned.

CI at 6770228 passed all seven Linux/macOS/Windows jobs. Each ran 112 tests;
Linux/macOS skipped two privileged cases, Windows also skipped the existing
POSIX subprocess SIGINT case. Earlier 107-test CI also passed. See
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

The Phase 2-to-main dependency is unresolved. Optional privileged Phase 2 validation
is retained, with its previous Linux evidence; no new privileged run was made in
Phase 3. Privileged macOS/BPF remains explicitly incomplete. No PR has been merged.
