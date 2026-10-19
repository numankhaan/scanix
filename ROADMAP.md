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
  Native raw SYN, UDP, discovery and durable resume are not implemented here.

## Planned

- **Phase 4B (implementation draft #12):** Linux IPv4 native SYN packet/state/I/O
  and protocol-2 integration; controlled live validation remains pending.
  See docs/NATIVE_SYN.md. Do not mark ready/merge until acceptance passes.
- **Phase 4C:** durable resume, streaming, deterministic sharding and measured performance.
- **Phase 5A:** bounded informational enumeration plugins.
- **Phase 5B:** original remote packet OS evidence and conservative fingerprints.
- **Phase 5C:** optional versioned SQLite history and partial-scan comparisons.
- **Phase 6:** cross-platform release validation, fuzzing, packaging/license review
  and release-candidate report; no public publishing without separate authorization.

Service follow-ups: more original signatures, broader server interoperability,
HTTP/2 and richer insecure-certificate metadata, virtual-host enumeration within
explicit scope, and more protocol variants. These are not delivered Phase 3 coverage.

Possible follow-ups: scoped IPv6 interfaces, extension-header handling, NAT-aware
correlation, stronger generic UDP probe strategies and broader isolated lab coverage.
No native engine, scripting framework, OS fingerprint database, web UI or database
is included in Phase 2.
