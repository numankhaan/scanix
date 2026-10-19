# Scanix roadmap

## Delivered

- **Phase 1:** bounded TCP connect scanning, explicit result semantics, typed
  reports, atomic JSON/CSV/HTML exports, cancellation and portable regression CI.
- **Phase 2:** correlated SYN/ACK and RST/ACK handling with reset cleanup; IPv4/IPv6
  ICMP interpretation; DNS/NTP/generic UDP probes; conservative silence semantics;
  retries, global pacing, per-host limits and bounded RTT adaptation; multi-target
  DNS policies, lazy bounded CIDRs, target/exclusion files and offline scope preview;
  bounded TCP/ICMP/ARP/IPv6 ND discovery with evidence and route restrictions.

Phase 2 has deterministic unprivileged coverage. Privileged loopback tests are
opt-in; live ARP/ND and DNS/NTP validation on isolated Linux/macOS lab networks is
still outstanding. See [PHASE2_PROGRESS.md](PHASE2_PROGRESS.md) and README for the
implemented platform/privilege requirements and limitations. This is not a claim
of feature or performance parity with other scanners.

## Planned

- **Phase 3:** TLS-aware service detection, protocol signatures and version evidence
  separated from port-based guesses; expand the small UDP probe registry carefully.
- **Phase 4:** separately designed native asynchronous discovery engine, with
  measured throughput, resource bounds and correctness checks.
- **Phase 5:** enumeration plugins, remote OS fingerprints and scan history.

Possible follow-ups: scoped IPv6 interfaces, extension-header handling, NAT-aware
correlation, stronger generic UDP probe strategies and broader isolated lab coverage.
No native engine, scripting framework, OS fingerprint database, web UI or database
is included in Phase 2.
