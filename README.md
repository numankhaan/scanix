# Scanix

Scanix is a bounded Python network reconnaissance tool. Phase 2 adds correlated
SYN and protocol-aware UDP probes, IPv6 scopes, exclusions, host discovery and
shared timing controls to Phase 1's TCP connect scanner and atomic exports.
It does not claim Nmap accuracy or Masscan throughput. Scan only authorized systems.

## Installation

Python **3.10–3.14** is supported. From the repository root:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m scanix --help
python -m scanix scan --help
python -m scanix discover --help
```

TCP connect, TCP discovery, exports and offline preview use the standard library.
Scapy (`>=2.6,<3`, tested locally with 2.8.0) is required for raw scans, raw discovery
and synthetic packet tests. Raw I/O supports Linux and macOS with a working Scapy
capture backend and appropriate raw-socket/BPF privileges (usually root). Windows
supports connect/TCP discovery; raw methods fail explicitly. Capture is opened
before probes are scheduled; setup failures are reported without a connect fallback.
Linux loopback uses raw IP sockets. ARP/ND also require Ethernet layer-2 capture.

## Scanning and scope

Examples use loopback; no public scan targets are needed:

```sh
python -m scanix scan -t 127.0.0.1 -p 22,80 --connect
python -m scanix scan -t ::1 --family 6 -p 22,80 --connect
python -m scanix scan -t 127.0.0.1 -t ::1 --family any -p 22 --out json --out-file -
python -m scanix scan -t 127.0.0.0/30 -p 22,80 --exclude 127.0.0.2 --preview
python -m scanix scan --target-file targets.txt --exclude-file exclusions.txt -p 22 --preview
python -m scanix scan -t localhost --dns-policy all --family any -p 22 --preview --resolve-preview
```

Repeat `--target` and `--exclude` for IP addresses, hostnames or CIDRs. Target and
exclusion files are UTF-8, one entry per line, with blank lines and `#` comments.
Reads are limited to 1 MiB per file and 10,000 combined entries. Invalid addresses,
control characters, scoped IPv6 (`%interface`) and malformed entries are rejected.
Numeric CIDRs are normalized with host bits cleared. IPv4 network/broadcast and
IPv6 subnet-router anycast addresses are omitted using `ipaddress.hosts()`; IPv4
/31 and IPv6 /127 include both addresses, and individual addresses are included.

`--family 4` is the default; `6` and `any` are explicit alternatives. DNS uses the
system resolver once per normalized hostname. `--dns-policy first` selects the
first answer in system order for the selected family, retaining Phase 1's default
IPv4 policy. `all` selects every distinct answer. Excluded hostnames exclude **all**
their answers regardless of scan policy. DNS has system-managed timing, outside
probe timeouts. Multi-target resolution failures reject the scope before probes.
The legacy single-target path retains Phase 1 per-port resolution error rows.

Targets are deduplicated and exclusions applied before traffic. Each result retains
`target`, numeric `resolved_ip`, `address_family`, and all matching input labels in
`original_targets`, including aliases resolving to the same address. CIDRs stay
lazy ranges. The conservative input budget is 4,096 addresses by default; raise
`--max-targets` explicitly to at most 65,536. Overlapping ranges/aliases count toward
the input budget before deduplication/exclusions. Oversized ranges are rejected,
never truncated; an IPv6 /64 is not expanded. Scan reports are limited to 1,000,000
selected address/port pairs; split larger scopes into separate runs.

`--preview` performs no DNS, route lookup, capture setup or probe traffic. It shows
numeric effective targets (up to 256 samples), ports, methods and exclusions.
Hostnames are listed as unresolved and `scope_complete` is false; an exact effective
count is unavailable until DNS is allowed with `--resolve-preview`. That option
permits DNS only. An empty effective scope sends no probes.

Single ports, inclusive ranges and comma combinations are accepted, deduplicated
and sorted. `--connect` (default), `--syn` and `--udp` are mutually exclusive.
`--banner` is available only with connect, gathering at most 2,048 bytes of raw
plaintext evidence on a separately paced connection. It does not confirm a service
or version and does not implement TLS.

## SYN and UDP evidence

Raw examples below match the CLI help. They require the privileges described above;
the local validation run exercised their permission-failure path, not privileged I/O.

```sh
python -m scanix scan -t 127.0.0.1 -p 22,80 --syn --rate 10 --retries 1
python -m scanix scan -t 127.0.0.1 -p 53,123 --udp --rate 1 --per-host 1 --retries 1
python -m scanix scan -t ::1 --family 6 -p 53 --udp --out json --out-file udp.json
```

SYN probes use random source ports and sequence numbers. Replies must reverse the
actual source/destination addresses and ports and acknowledge `sequence + 1`.
Matched SYN/ACK is `open/syn_ack`; RST/ACK is `closed/syn_rst_ack`. Naked RSTs,
incorrect acknowledgments and unrelated packets supply no evidence. A successful
probe sends a correctly addressed RST/ACK using the response's acknowledgment as
its sequence and response sequence + 1 as its acknowledgment. Cleanup is paced;
`reset_sent` and any cleanup error remain evidence without erasing the open result.
The kernel may independently reset unsolicited SYN/ACKs.

The UDP probe registry is intentionally small:

| Port | Probe | Response validation |
| --- | --- | --- |
| 53 | A query for `scanix.invalid`, RD=0, no EDNS | endpoints, transaction ID, response/opcode, echoed question |
| 123 | 48-byte NTPv4 client request (mode 3) | endpoints, server mode/version, echoed originate timestamp |
| Other | eight random bytes | endpoints only; no generic application transaction identifier |

No DNS ANY/recursive requests, NTP control/monlist requests, broadcasts or response
size extensions are used. NTP stratum-zero responses record the kiss code and
`RATE` evidence. Application replies and ICMP errors are interpreted separately.
Matching ICMP errors require quoted addresses, ports and TCP sequence or UDP header
(length/checksum); IPv4 also checks the original IP ID. This works with minimum
IPv4 quotations containing the IP header plus eight transport bytes. IPv6 uses
its own ICMP types/codes. Responses with insufficient/mismatched quotes are ignored.

| Method/evidence | State | Reason |
| --- | --- | --- |
| Connect succeeds | `open` | `connection_succeeded` |
| Connect is refused | `closed` | `connection_refused` |
| Connect timeout | `unknown` | `timeout` |
| Matched SYN/ACK | `open` | `syn_ack` |
| Matched RST/ACK | `closed` | `syn_rst_ack` |
| SYN retry budget exhausted | `unknown` | `syn_no_response` |
| Matched UDP reply | `open` | `udp_response` |
| Matched ICMPv4 type 3/code 3 or ICMPv6 type 1/code 4 for UDP | `closed` | `icmp_port_unreachable` |
| Explicit administrative prohibition (v4 codes 9/10/13; v6 codes 1/5/6) | `filtered` | `icmp_administratively_prohibited` |
| UDP retry budget exhausted | `open\|filtered` | `udp_no_response` |
| Other matched ICMP path error | `unknown` | `icmp_unreachable_or_path_error` |
| Local raw execution failure | `error` | OS classification or `worker_exception` |

Silence never establishes an open port. A non-administrative ICMP path error remains
`unknown`, including UDP: it proves neither a port state nor administrative filtering.
Connect retains Phase 1's `routing_failure`, `permission_denied`, `resource_exhausted`
and `socket_error` classifications, with POSIX/Winsock error codes when supplied.
ICMP rate limiting can hide closed ports; default UDP pacing is one probe/second,
with one retry and exponential timeout backoff. This reduces loss, not uncertainty.

## Discovery

```sh
python -m scanix discover -n 127.0.0.0/30 --methods tcp -p 22,80 --concurrency 4
python -m scanix discover -t 127.0.0.1 --methods icmp,tcp --rate 5
python -m scanix discover -t ::1 --family 6 --methods icmp --preview
python -m scanix scan -t 127.0.0.1 -p 22,80 --discovery tcp --discovery-ports 22,80
python -m scanix scan -t 127.0.0.1 -p 22,80 --skip-discovery
```

`discover --methods` accepts `tcp`, `icmp`, `arp` and `nd`, comma-separated. TCP
(default) treats connection success **or refusal** as positive reachability evidence.
It needs no elevated privileges. ICMP echo validates addresses, identifier, sequence
and echoed payload. ARP validates matching Ethernet/IPv4 replies; it is restricted
to directly connected IPv4 destinations with no gateway. IPv6 neighbor discovery
sends solicited-node multicast NS and validates solicited NA, target, addresses,
hop limit 255 and link-layer option. It requires a directly connected IPv6 Ethernet
route. Routed targets never receive ARP/ND probes. Unsupported family, route, link
or backend produces an explicit method error. ICMP, ARP and ND require raw privileges.

Discovery stops testing a host after positive evidence. Reports distinguish `up`,
`no_response`, `unreachable` (matched ICMP path error or OS routing failure), and
`error` (local/setup failure), preserving the actual observation. `unreachable`
describes the observed path and does not prove a host is permanently down. Silence
is only `no_response`. Standalone discovery returns JSON to stdout or atomically to
`--out-file`; `-n/--network` remains an alias for repeatable targets. The former
system-ping text output is replaced by structured evidence.

Scanning skips discovery by default. `--discovery` enables a gate: only positive
hosts proceed to port scans. Skipped hosts remain in `discovery`, selected port
coverage remains incomplete, and silence is never relabeled as closed. Use
`--skip-discovery` to override the gate. TCP discovery is an explicitly requested
preflight operation, including when the subsequent port method is SYN/UDP.

## Timing, scheduling and cancellation

| Setting | Default/behavior |
| --- | --- |
| `--rate` | connect 100 attempts/s; SYN 10 packets/s; UDP 1 packet/s; standalone discovery 10 probes/s |
| `--concurrency` | scan 100 global ceiling; standalone discovery 16 hosts, capped at 64 |
| `--per-host` | 8 outstanding port tasks, also capped by concurrency |
| `--retries` | one additional raw attempt; range 0–5; TCP connect/discovery never retry |
| `--timeout` | initial 1 second; finite (0, 300] |
| `--min-timeout`, `--max-timeout` | adaptive bounds 0.1–5 seconds; configurable within 0.01–300 |
| `--fixed-timeout` | use the exact configured timeout; disable adaptation/backoff |

One monotonic, cancellation-aware limiter is shared across all selected hosts and
methods, including discovery, raw retransmissions, resets and banner connections.
TCP connect limits application connection starts: kernel SYN retransmissions, ACKs,
DNS, ARP/NDP resolution and backend link maintenance are outside this rate. Raw
rates count Scanix packet transmissions; backend-generated link resolution is also
outside that count. There is no burst-credit accumulation.

Port scanning visits hosts lazily, one at a time, with at most
`min(concurrency, per-host)` pending/running futures. Standalone discovery visits
hosts in parallel with a bounded submission window. Discovery methods within each
host run serially. There is no unbounded task queue or packet-response collection.
Reports and deduplication sets are retained in memory within the explicit scope
budgets; this is not a streaming high-speed engine.

RTT adaptation uses a per-host EWMA plus four times deviation, clamped to the
configured bounds. Raw retry deadlines double within the same bounds. Only matched
first-attempt replies contribute RTT samples (no ambiguous retransmission samples).
Connect uses one attempt. Slow/limited ICMP may still require a higher timeout,
lower rate and `--per-host 1`. `--progress` writes completed/selected coverage to
stderr; it does not infer responses for unfinished probes.

Ctrl+C stops submission, wakes pacing waits and stops raw capture within its polling
interval (50 ms). Running connect sockets finish within their configured timeouts.
Completed results survive and requested exports are written. Repeated CLI Ctrl+C
sets the same event. System DNS, backend setup/send calls and forced process
termination cannot guarantee prompt cancellation or saved output.

## Reports and exports

```sh
python -m scanix scan -t 127.0.0.1 -p 22,80 --out json --out-file results.json
python -m scanix scan -t 127.0.0.1 -p 22,80 --out csv --out-file results.csv
python -m scanix scan -t 127.0.0.1 -p 22,80 --out html --out-file results.html
python -m scanix scan -t 127.0.0.1 -p 22 --out json --out-file - --progress
```

Schema version **2** retains Phase 1 fields and adds `probe_type`, `evidence`,
`attempts`, `original_targets`, scope/effective scheduling metadata and discovery
observations. Unknown evidence is `null`; service names remain unconfirmed port-table
guesses, and UDP does not inherit TCP service guesses. OS/version detection remains
unimplemented. `connection_elapsed_seconds` is monotonic; for raw probes it includes
pacing, retries and cleanup. Wall timestamps are UTC ISO 8601.

`requested_ports` counts selected address/port pairs; `completed_ports` counts result
rows, including errors. `completion_status` is `complete`, `failed` or `interrupted`.
`incomplete` is true for failures/interruption **or missing selected coverage**,
including discovery skips. Thus a successful discovery gate can exit 0 while
`incomplete` is true. No rows are fabricated for unattempted ports on cancellation.
Fatal setup/worker/local raw failures mark execution failed. Connect routing errors
retain Phase 1's per-probe semantics. Results are sorted deterministically.

JSON retains structured evidence. CSV includes a metadata row even for empty scans,
then result rows; nested evidence and null values use JSON cells. HTML escapes all
untrusted values. Raw banners are not printed to terminals. Export files use a
temporary file, fsync and atomic replacement; failure preserves existing output.
Only JSON supports `--out-file -`, and stdout contains only JSON. Export failures
exit 1, even during interruption. Without `--out-file`, the default is
`scan_results.<format>`.

Exit codes: **0** executed, **2** invalid input, **1** setup/dependency/worker/output
failure, **130** interrupted. `PortScannerwithOSFingerprint.py` remains a compatibility
launcher. `traceroute` remains a legacy system utility outside Phase 2 guarantees.

## Architecture, validation and limitations

`modules/packets.py` contains pure Scapy builders and classifiers;
`modules/transport.py` owns privileged capture/transmission; `raw_scan.py` owns raw
retry orchestration. `core/targets.py` handles untrusted scope input, and
`core/timing.py`, `scanner.py`, `scope_scan.py` bound execution. Existing typed scan
reports feed the same JSON/CSV/HTML exporters. Discovery uses its own host-evidence
JSON envelope and is embedded in typed scan reports when used as a gate.

```sh
python -B -m unittest discover -s scanix/tests -v
# Optional, only in a privileged local lab (never enabled by CI):
SCANIX_PRIVILEGED_TESTS=1 python -B -m unittest scanix.tests.test_integration_optional -v
```

The default suite uses synthetic IPv4/IPv6 packets, deterministic timing and loopback
sockets. It requires no public network or administrator access. CI installs Scapy
and tests Python 3.10–3.14 on Linux plus 3.14 on macOS/Windows. Privileged tests cover
loopback SYN and generic UDP; ARP/ND and real DNS/NTP require additional isolated
lab verification. The current validation record is in [PHASE2_PROGRESS.md](PHASE2_PROGRESS.md).

Limitations: no scoped/link-local IPv6 interface selection, IPv6 extension-header or
fragment reassembly, NAT-translated probe correlation, application signatures beyond
DNS/NTP, adaptive congestion control or native packet engine. DNS question validation
is deliberately strict and may ignore unusual compressed questions. Generic UDP
uses endpoint matching only; random source ports reduce but cannot eliminate stale
or spoofed replies. Capture loss, firewall policy, ICMP suppression and service
behavior can leave ports inconclusive. Packet correlation is evidence, not
cryptographic authentication. Backend-generated warnings may appear on stderr.
