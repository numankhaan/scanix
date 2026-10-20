# Scanix roadmap

## Delivered

- **Phase 1:** bounded TCP connect scanning, explicit result semantics, typed
  reports, atomic JSON/CSV/HTML exports, cancellation and portable regression CI.
- **Phase 2:** correlated SYN/ACK and RST/ACK handling with reset cleanup; IPv4/IPv6
  ICMP interpretation; DNS/NTP/generic UDP probes; conservative silence semantics;
  retries, global pacing, per-host limits and bounded RTT adaptation; multi-target
  DNS policies, lazy bounded CIDRs, target/exclusion files and offline scope preview;
  bounded TCP/ICMP/ARP/IPv6 ND discovery with evidence and route restrictions.

- **Phase 3:** structured service evidence separated from port guesses; original
  versioned/validated probe and signature registry; bounded HTTP, TLS, SSH and
  FTP/SMTP/POP3/IMAP detection on unusual ports; advertised SMTP/POP3/IMAP TLS
  upgrades; verified TLS with hostname SNI and explicit insecure lab inspection;
  DNS/NTP evidence reuse and targeted UDP fallback; schema-3 JSON/CSV/HTML exports,
  previewed policies, printer exclusions and shared rate/cancellation controls.

Phase 3 has 115 local regression tests (113 passing, two privileged skips), including
loopback protocol/TLS and deterministic parser/resource cases, plus four actual CLI
lab cases. See [coverage and limitations](docs/SERVICE_DETECTION.md),
[validation](validation/SERVICE_RESULTS.md) and [progress](PHASE3_PROGRESS.md).

Phase 2 has deterministic unprivileged coverage and passing Linux/macOS/Windows
CI, including the repaired Windows refusal/backend fixtures. The separate opt-in
Linux namespace lab passed 28 live IPv4/IPv6 SYN/UDP/ICMP/ARP/ND cases, 28 pcap checks
and both privileged loopback tests. See [recorded evidence](validation/RESULTS.md).
Privileged macOS/BPF and broader DNS/NTP interoperability remain unverified.
See [PHASE2_PROGRESS.md](PHASE2_PROGRESS.md) and README for the
implemented platform/privilege requirements and limitations. This is not a claim
of feature or performance parity with other scanners.

## Security and current work

The privacy/security work is merged in #8; its gates remain enforced. Historical
privacy remediation is pending owner decision, independently of feature work.
See [policy](SECURITY.md), [audit](docs/SECURITY_AUDIT.md) and
[checkpoint](docs/AUTONOMOUS_PROGRESS.md).

- **Phase 4A (merged through #11):** opt-in Rust asynchronous TCP connect
  engine, bounded versioned subprocess contract, Python adapter, schema-4 metadata,
  deterministic tests and a measured loopback baseline. Python remains the default.
  Subsequent phases supply Linux IPv4 SYN and durable resume. Native UDP/discovery
  remain unsupported.

- **Phase 4B (merged through #12):** Linux IPv4 native SYN packet/state/I/O
  and original protocol-2 integration (current wire 3 with Phase 4C); 25 isolated
  Linux ground-truth/capture checks passed.
  See docs/NATIVE_SYN.md; latest-head and post-merge CI passed.

- **Phase 4C (merged through #13):** private compatible native checkpoints/resume,
  bounded NDJSON result streaming, deterministic shards and measured commit batching.
  All 33 isolated SYN continuation/capture checks passed. See docs/CONTINUATION.md
  and validation/CONTINUATION_RESULTS.md; latest-head and post-merge CI passed.
- **Phase 5A (merged through #14):** opt-in bounded trusted subprocess
  HTTP/TLS/SSH/DNS plugins, versioned capabilities/evidence API and schema-5 exports,
  shared pacing/cancellation and durable enrichment. See docs/PLUGINS.md.

- **Phase 5B (merged through #15):** opt-in Python SYN captured remote
  TCP/IP features, one original experimental Linux-compatible IPv4 profile,
  explicit inconclusive evidence and versioned bounded database. Fifteen isolated
  OS capture checks passed; see docs/OS_EVIDENCE.md and validation/OS_RESULTS.md.
  Native OS/other systems/IPv6 profiles remain unsupported.

- **Phase 5C (merged through #16):** optional private versioned SQLite
  history, aggregate/native stream ingestion, evidence/version provenance, bounded
  offline comparisons and explicit retention. Missing observations never imply
  removals; partial/crashed saves remain incomplete. See docs/HISTORY.md.

## Planned

- **Phase 6 (validation in progress):** bounded deterministic parser mutation corpus,
  Python candidate packaging/install/reinstall checks across the existing platform
  matrix, dependency/license inventory and signature maintenance procedures.
  Owner licensing and privileged macOS/BPF validation remain incomplete. No public
  publishing without separate authorization; see docs/RELEASE_CANDIDATE.md.

Service follow-ups: more original signatures, broader server interoperability,
HTTP/2 and richer insecure-certificate metadata, virtual-host enumeration within
explicit scope, and more protocol variants. These are not delivered Phase 3 coverage.

Possible follow-ups: scoped IPv6 interfaces, extension-header handling, NAT-aware
correlation, stronger generic UDP probe strategies and broader isolated lab coverage.
No native engine, scripting framework, OS fingerprint database, web UI or database
is included in Phase 2.
