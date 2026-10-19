# Scanix roadmap

Phase 1 delivers a reliable, bounded, testable Python TCP connect scanner with
explicit states, structured exports, and cancellation. Later phases are planned;
they are not claims about currently implemented capabilities or performance.

- **Phase 2:** Robust SYN and UDP classification, response correlation and cleanup,
  host discovery, IPv6 and multi-address policies, retries, and timing controls.
- **Phase 3:** TLS-aware service detection, protocol probes and signatures, and
  version evidence distinguished from port-based guesses.
- **Phase 4:** A separate native asynchronous high-speed discovery engine,
  with measured throughput, resource limits, and correctness checks.
- **Phase 5:** Enumeration plugins, remote OS fingerprints, and scan history.

Nmap-like depth and a Masscan-inspired discovery engine are long-term directions,
not parity or performance guarantees.
