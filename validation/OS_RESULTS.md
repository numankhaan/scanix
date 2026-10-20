# Phase5B controlled validation

One local Podman Linux VM/container lab, Python3.14/Scapy2.8.0, isolated container
network plus fresh scanner/peer namespaces, IPv4/IPv6 veth MTU1500 and no external
default routes. The VM was originally stopped and restored to stopped afterward.
No public targets, host route/firewall edits or account settings were involved.
Container base was pulled from the official Python image and pinned to its digest
for the local lab build; installation used iproute2/iptables/tcpdump/libpcap. Raw
reports, topology logs and pcaps remain owner-private and were not uploaded.

Executed:python -B validation/privileged_lab.py --output <new-private-directory>
--os-evidence, inside the privileged isolated Linux container. Optional native
validation was not rerun:Rust/native packet code and scheduling are unchanged.

- 28 existing IPv4/IPv6 SYN/UDP/ICMP/ARP/ND state/discovery cases passed.
- 28 independent existing capture checks and both privileged loopback tests passed.
- 15 new OS checks passed; zero measured kernel capture drops.
- Open19000 stayed open with correlated SYN/ACK; closed19001 stayed closed with
  inconclusive OS evidence for both families. IPv4 matched all five original Linux
  experimental signals; IPv6 stayed explicitly unsupported/inconclusive.
- Independent capture checked endpoints/acknowledgment and TTL/hop limit, IPv4 DF,
  window and MSS against reported remote features; no reliable/version OS claim.

OS capture SHA256:489d8e3f4e12d8264fbaa575e820c113ed5b65b0021a67b09b4f0d7b57ff52c0

The executed working source was based on main7407b13, with recorded production,
fixture and validation source digest:4b493a519f496089760630d44e5c50b01fe0719de89d0860398d4ef77d531453.
Packet/evidence parsing, matching and lab-module file hashes equal feature commit
`c444e43a31de2f4db651339fcf499785ea73162a` (verified individually). Those files were unchanged afterward; subsequent
changes were terminal presentation, additional output/hash tests, profile provenance
text and documentation. Profile signal values were confirmed, not widened. No
second privileged run is claimed for those changes. The checkpoint/PR records the
final reviewed commits and platform CI separately from this local Linux lab.

This is controlled accuracy evidence, not a throughput/CPU/memory benchmark. Existing
native baseline/continuation measurements remain attributed to their original
sources; they were not rerun for this opt-in Python evidence feature. No performance
improvement or parity claim. Broader systems, routed profiles and privileged
macOS/BPF validation remain incomplete.
