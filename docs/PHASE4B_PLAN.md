# Phase 4B: native asynchronous SYN discovery

Status: PR #12 merged at 66f0455e6d69c0807de04e84f9c391dbd07776c5. Linux namespace
ground truth/capture passed 25 checks at d181e1b; latest-head and post-merge CI passed. Python remains the default; the native connect engine remains available.

## Starting point

Phase 4A merged through PR #11 at 3e57881a8e03e3d4b5b0a58835714cb3a652d483.
The review added locked Rust 1.85.0 build/test CI; all eight pre-merge workflows passed.
Post-merge CI must be inspected separately. Historical privacy remediation and privileged
macOS/BPF validation remain unresolved; neither is silently waived by this work.

## Scope

Linux-first numeric IPv4 SYN scanning, explicitly selected with native engine and SYN
method. IPv6 remains available through existing supported engines; native IPv6 SYN must
fail before traffic until separately implemented and tested. No UDP, evasion, durable
resume, distributed scanning, or public-network testing in this increment.

## Architecture

- Keep connect and SYN capability selection explicit; never fall back silently.
- Separate pure packet construction/classification from Linux socket setup and I/O.
- Run independent transmitter and receiver tasks with bounded queues and session budgets.
- Use a versioned wire contract for added methods, state reasons, and metrics. Update
  Python handshake validation and compatibility tests together; reject unsupported peers.
- Complete scope, route/source/interface, privilege, and capture preflight before probes.
- Validate reversed endpoints and expected ACK/sequence evidence; correlate quoted ICMP
  packets, reject outbound self-matches, unrelated responses, duplicates and malformed data.
- SYN/ACK establishes open; matched reset establishes closed; administrative prohibition
  establishes filtered. Silence after retry budget remains unknown.
- Pace all explicit SYN, retry, and cleanup RST transmissions within the configured budget.
  Document kernel/backend transmissions outside that accounting.
- Bound outstanding correlation state, retry bookkeeping, queues and memory. Stream
  completed results with backpressure; do not claim the Python aggregating exporter is
  constant-memory.
- Keep service/TLS enrichment as a subsequent bounded stage targeting confirmed open ports.
- On cancellation stop new transmissions, preserve completed evidence, drain within a
  documented bound, and report incomplete coverage.
- Record actual sends, matched/unmatched replies, duplicates, errors, capture drops where
  observable, retry counts, cooldown duration and completion coverage. Unknown metrics
  remain unknown rather than zero.

## Acceptance checklist

- [x] Synthetic packet fixtures cover positive/negative correlation, ICMP, malformed and
      truncated packets, duplicate/out-of-order replies and outbound self-matching.
- [x] Deterministic timing tests cover pacing, retries, cooldown, cancellation, deadlines,
      receiver backpressure and bounded outstanding state.
- [x] CLI, protocol, schema/export and explicit unsupported-platform/method tests pass.
- [x] Isolated Linux network namespace lab validates known open, closed, filtered and
      silent states; offline captures independently confirm probes and observations.
- [x] Tests demonstrate independent sending and receiving without per-probe blocking.
- [x] All existing security, MSRV, native connect and Python regression gates pass.
- [x] Measurements record hardware, topology, configuration, correctness, packet loss,
      throughput, CPU and memory; no performance/parity claim without evidence.
- [x] README, native boundary, roadmap and persistent checkpoint describe actual support.

## Completion

All scoped acceptance passed before merge; see NATIVE_SYN_RESULTS.md and PR #12.
Continue Phase 4C using AUTONOMOUS_PROGRESS.md. Native IPv6 SYN and privileged macOS/BPF
remain explicitly unsupported/incomplete, not inferred from Linux success.
