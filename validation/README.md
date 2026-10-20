# Privileged Phase 2 validation

This opt-in lab is separate from the unprivileged `Tests` workflow. A pass requires
both expected Scanix states and independently checked packet-capture evidence.
It never scans public targets or attaches the test network to a host interface.

## Reproduce on Linux

Install project requirements into a virtualenv. The lab also requires `iproute2`,
`iptables` (with IPv6 support), `tcpdump` and util-linux `unshare`, plus root with
network/mount/PID namespace and raw-socket privileges. From the repository root:

```sh
sudo -- "$(pwd)/.venv/bin/python" -B validation/privileged_lab.py --output /tmp/scanix-lab-evidence
cat /tmp/scanix-lab-evidence/results.json
```

The output directory must be new. Exit 0 means every state and capture check passed;
1 means a failed case/setup; 2 means preflight unavailable. Inspect the report and
logs before interpreting a nonzero exit as a scanner defect. No dependency is
installed by the driver. It refuses to run in the caller's network namespace,
with unexpected interfaces or with an external default route. The new mount/PID
namespaces isolate `/proc` and process cleanup; the veth pair and firewall rules
exist only in the two private network namespaces. The driver preserves artifacts
and terminates its peer and capture process even after failure.

The optional GitHub workflow can run on a push to `phase2/scanning-accuracy` that
changes lab files and explicitly includes `[privileged-lab]` in its commit message.
It runs separately from the regular test matrix. The current security policy prohibits
raw artifact uploads; captures and raw logs must remain private. Manual dispatch is also provided for when the workflow is available
on the default branch. No Windows test is disabled or skipped by this workflow.

## Topology and expectations

| Node | IPv4 | IPv6 | Interface |
| --- | --- | --- | --- |
| Scanner namespace | 10.203.0.1/29 | fd53:ca:1::1/64 | sxscan |
| Peer namespace | 10.203.0.2/29 | fd53:ca:1::2/64 | sxpeer |

The interfaces form one veth pair. Both namespaces have loopback and no external
default route. The peer has minimal DNS/NTP/UDP services and a TCP listener.
Two explicit test routes through the peer represent routed destinations:
10.204.0.2/32 and fd53:ca:2::2/128. They are used only to verify that discovery
rejects routed ARP/ND; no IP scan is sent to those addresses.

| Case, for both IPv4 and IPv6 | Expected Scanix state | Required capture evidence |
| --- | --- | --- |
| SYN, TCP 19000 listener | open | SYN, correlated SYN/ACK, Scanix's correctly sequenced RST/ACK |
| SYN, TCP 19001 with no listener | closed | correlated RST/ACK |
| SYN, TCP 19002 with administrative reject | filtered | matched quoted ICMP admin prohibition |
| SYN, TCP 19003 with DROP | unknown | two SYN attempts and no matching state response |
| UDP 53, minimal nonrecursive DNS | open | query and response with matching transaction/question |
| UDP 123, minimal NTP mode 3 | open | request and server response with matching originate timestamp |
| UDP 19000 echo | open | request and matching UDP response |
| UDP 19001 without service | closed | matching quoted ICMP port unreachable |
| UDP 19002 with administrative reject | filtered | matching quoted ICMP admin prohibition |
| UDP 19003 with DROP | open\|filtered | two UDP attempts and no matching response |
| ICMP echo to peer | up | matching addresses, ID, sequence and echoed nonce |
| ARP / ND to peer | up | matching ARP reply / solicited NA |
| ARP / ND to unused .3 / ::3 | no_response | request(s), no matching reply |
| ARP / ND to routed test address | error | `routed_target_not_on_link`; zero ARP/NS requests to that address |

This is **28 live cases**: 20 scan cases, two ICMP echo cases and six link-discovery cases. Scan attempts
are serial, fixed timeout 0.75 seconds, one retry, rate four transmissions/second.
Raw reset cleanup is also paced. The peer's reject/drop rules are per-protocol,
per-port rules in its namespace. TCP 19001 is not artificially reclassified.

## Evidence and current status

`results.json` records expected/observed states, attempts, environment, packet counts,
per-case capture checks and capture SHA-256. Per-method Scanix JSON reports retain
classification evidence. `capture.pcap` contains only the isolated `sxscan` link;
`scanner-topology.json`, `peer-topology.json`, `peer.log` and `capture.log` record
setup and errors. Capture is capped at 10,000 packets and 256 bytes per packet;
all generated requests/ICMP quotations fit within that snap length. A separate
`loopback.pcap` and test/capture logs preserve execution of the two existing opt-in
raw loopback tests. The driver requires those tests and correlated loopback packet evidence to pass,
using immediate capture delivery and a finite drain deadline.

**Privileged local macOS/BPF execution remains unavailable.** Noninteractive
`sudo -n true` still fails. A later local Linux VM lab succeeded for Phase5B in
isolated namespaces (see OS_RESULTS.md); the VM was restored stopped. That is Linux
validation, not macOS raw/BPF coverage. Captures remain private. The driver returns
unavailable on macOS without creating sockets or sending packets.
The hosted Linux lab **passed 28 live cases and 28 capture checks**, plus both
existing opt-in raw loopback integration tests. See [RESULTS.md](RESULTS.md) for
actual historical observations and pcap hashes; current workflows do not upload raw captures.
Linux validation does not establish macOS privileged backend behavior.

See [CI_WINDOWS.md](CI_WINDOWS.md) for exact CI failure evidence and the fixes.
Protocol/tool references: [unshare](https://www.man7.org/linux/man-pages/man1/unshare.1.html)
and [iptables REJECT](https://www.man7.org/linux/man-pages/man8/iptables-extensions.8.html).

## Unprivileged Phase 3 service lab

The independent service driver uses ephemeral loopback HTTP/TLS endpoints and the
real CLI, without raw privileges or external targets:

```sh
python -B validation/service_lab.py --output /tmp/scanix-service-evidence.json
```

See [service validation results](SERVICE_RESULTS.md) for actual local/CI outcomes,
TLS fixtures, expected/observed states and remaining limitations. It does not replace
the optional privileged packet-capture validation above.
