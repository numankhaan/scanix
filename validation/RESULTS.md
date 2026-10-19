# Phase 2 validation results

Validated implementation: `aa07fde`, 2026-10-19. This record distinguishes live Linux
validation, native Windows CI, local unprivileged tests and unavailable macOS raw I/O.

## Native Windows and regular CI

- Phase 1 fix `fb0277f`: [run 39286464882](https://github.com/numankhaan/scanix/actions/runs/39286464882), all seven matrix jobs passed.
- Phase 2 fixes and lab `aa07fde`: [run 39289431799](https://github.com/numankhaan/scanix/actions/runs/39289431799), all seven matrix jobs passed.
- Matrices retain Ubuntu Python 3.10–3.14 and macOS/Windows Python 3.14.
- Native Windows Phase 1: 36 run, 35 passed, one POSIX SIGINT test skipped.
- Native Windows Phase 2: 82 run, 79 passed, POSIX SIGINT and two opt-in raw tests skipped.
- Local macOS Python 3.14.3: Phase 1 36 passed; Phase 2 82 run, 80 passed, two opt-in raw tests skipped, with both Scapy 2.6.1 and 2.8.0.
- Original Windows failure causes and measured socket codes are in [CI_WINDOWS.md](CI_WINDOWS.md).

## Live privileged Linux lab

[Run 39289424498](https://github.com/numankhaan/scanix/actions/runs/39289424498) passed
using Python 3.14.8 and Scapy 2.8.0. [Download the evidence artifact](https://github.com/numankhaan/scanix/actions/runs/39289424498/artifacts/12203863545).
The regular test matrix remains unprivileged; this separate lab is explicitly opt-in.

Actual topology: fresh scanner and peer Linux network namespaces connected by one
veth pair, `sxscan` (10.203.0.1/29, fd53:ca:1::1/64) to `sxpeer`
(10.203.0.2/29, fd53:ca:1::2/64). Recorded route tables show no external default
route on either node. Only the namespace-local peer receives port probes. Routed
addresses 10.204.0.2 and fd53:ca:2::2 are method-rejection tests, with zero ARP/NS
requests to those addresses. No public hosts or networks were scanned.

**28/28 live cases and 28/28 packet-evidence checks passed:**

| Case | Expected | Observed | Captured requests | Capture check |
| --- | --- | --- | --- | --- |
| IPv4-syn-19000 | open | open | 1 | passed |
| IPv4-syn-19001 | closed | closed | 1 | passed |
| IPv4-syn-19002 | filtered | filtered | 1 | passed |
| IPv4-syn-19003 | unknown | unknown | 2 | passed |
| IPv4-udp-53 | open | open | 1 | passed |
| IPv4-udp-123 | open | open | 1 | passed |
| IPv4-udp-19000 | open | open | 1 | passed |
| IPv4-udp-19001 | closed | closed | 1 | passed |
| IPv4-udp-19002 | filtered | filtered | 1 | passed |
| IPv4-udp-19003 | open\|filtered | open\|filtered | 2 | passed |
| IPv4-icmp-up | up | up | 1 | passed |
| IPv4-arp-up | up | up | 3 | passed |
| IPv4-arp-no_response | no_response | no_response | 2 | passed |
| IPv4-arp-error | error | error | 0 | passed |
| IPv6-syn-19000 | open | open | 1 | passed |
| IPv6-syn-19001 | closed | closed | 1 | passed |
| IPv6-syn-19002 | filtered | filtered | 1 | passed |
| IPv6-syn-19003 | unknown | unknown | 2 | passed |
| IPv6-udp-53 | open | open | 1 | passed |
| IPv6-udp-123 | open | open | 1 | passed |
| IPv6-udp-19000 | open | open | 1 | passed |
| IPv6-udp-19001 | closed | closed | 1 | passed |
| IPv6-udp-19002 | filtered | filtered | 1 | passed |
| IPv6-udp-19003 | open\|filtered | open\|filtered | 2 | passed |
| IPv6-icmp-up | up | up | 1 | passed |
| IPv6-nd-up | up | up | 3 | passed |
| IPv6-nd-no_response | no_response | no_response | 2 | passed |
| IPv6-nd-error | error | error | 0 | passed |

The three ARP/NS requests to the live peer include automatic link resolution as
well as explicit discovery; Scanix scan attempt counts are recorded separately in
each per-method JSON report. Unused-address discovery emitted two requests; routed
ARP/ND emitted none. Each SYN/UDP silence case emitted exactly its two-attempt budget.
The offline verifier reuses pure packet classifiers and additionally checks actual
request counts and reset sequence/acknowledgment values. Downloaded Ethernet pcap
evidence was rechecked locally with both supported Scapy versions.

**Existing opt-in loopback integration tests: 2/2 passed**, no skips:
`test_syn_listener` and `test_udp_echo_and_closed`, inside the same isolated Linux
network namespace. `loopback-tests.log` reports two tests in 0.689 seconds; the
loopback capture is separate from the Ethernet capture. Its packet checks also
verify SYN/ACK and Scanix reset, a matched UDP reply and a matched ICMP port
unreachable. The driver uses immediate capture delivery and waits for complete
packet evidence before stopping tcpdump; a passing test process alone is insufficient.

Validation also reproduced and fixed a loopback false-open edge case: a UDP probe
with source port equal to destination port matched its own request. Probe builders
now exclude the destination port from the random source-port space, and regression
tests cover both loopback families and source-port range boundaries. No short
connect timeout is reclassified as closed.

## Packet capture details

- `capture.pcap`: 88 packets; tcpdump reports 88 received by filter and zero kernel drops.
- `loopback.pcap`: 9 packets; tcpdump reports 18 received by filter and zero kernel drops (Linux loopback capture accounting).
- Ethernet capture SHA-256: `8dd444024074ef6556e867ee025c2df6d46d1d0dd794aa6b2b4202102cc95a3a`.
- Loopback capture SHA-256: `1c84c0ba3d1f3e8414c60adee634e55bc38c590db485676c9ee08580d7a0ec5a`.
- Both hashes were verified after artifact download. Each pcap has a 256-byte snap length.
- Artifact also retains expected/observed JSON, ICMP quote evidence, addresses/routes/firewall rules, peer logs and capture logs.

Concrete reset correlations in the downloaded Ethernet capture:

- IPv4, source port 61915: SYN sequence 2802123782; SYN/ACK sequence 103330747, ACK 2802123783; Scanix RST/ACK sequence 2802123783, ACK 103330748.
- IPv6, source port 55667: SYN sequence 3469904098; SYN/ACK sequence 3826478226, ACK 3469904099; Scanix RST/ACK sequence 3469904099, ACK 3826478227.

Kernel-generated bare resets are also present; the verifier specifically requires
Scanix's RST/ACK and validates its sequence and acknowledgment against SYN/ACK.

## Still unavailable / outside validated coverage

Live macOS/BPF validation remains incomplete: passwordless sudo is unavailable,
`/dev/bpf0` denies capture, and the installed Podman VM cannot start (`vfkit` SIGTRAP,
exit 2). Local lab preflight returned unavailable with zero packets sent; no local
pcap or macOS privileged pass is claimed. The successful raw validation above is
Linux-only. NTP/DNS peers are minimal isolated services, not broad server/vendor
interoperability testing. Privileged macOS behavior,
real-interface performance, NAT, scoped IPv6 and extension-header/reassembly support
are not established by this lab. General unsupported features remain documented
in the project README. Hosted artifacts expire under repository retention policy;
download the linked evidence for longer preservation.
