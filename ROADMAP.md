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

## Planned

- **Phase 4:** separately designed native asynchronous discovery engine, with
  measured throughput, resource bounds and correctness checks.
- **Phase 5:** enumeration plugins, remote OS fingerprints and scan history.

Service follow-ups: more original signatures, broader server interoperability,
HTTP/2 and richer insecure-certificate metadata, virtual-host enumeration within
explicit scope, and more protocol variants. These are not delivered Phase 3 coverage.

Possible follow-ups: scoped IPv6 interfaces, extension-header handling, NAT-aware
correlation, stronger generic UDP probe strategies and broader isolated lab coverage.
No native engine, scripting framework, OS fingerprint database, web UI or database
is included in Phase 2.
