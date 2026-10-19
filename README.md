# Scanix

Scanix is a modular Python network reconnaissance tool. Phase 1 provides a tested,
bounded TCP connect scanner. It does not claim Nmap accuracy or Masscan throughput.
Scan only systems you are authorized to test.

## Installation

Supported Python versions: **3.10–3.14**. The TCP scanner, exports, and tests use only
the standard library. Run from the repository root (the directory containing the
`scanix/` package):

```sh
git clone https://github.com/numankhaan/scanix.git
cd scanix
python3 -m venv .venv
source .venv/bin/activate
python -m scanix --help
```

Optional experimental SYN scanning requires Scapy (`python -m pip install scapy`)
and suitable raw-packet privileges. TCP connect scanning does not require it.
The old `PortScannerwithOSFingerprint.py` filename is a compatibility launcher;
it no longer guesses OS information. The supported interface is `python -m scanix`.

## TCP scanning

```sh
python -m scanix scan -t 127.0.0.1 -p 22
python -m scanix scan -t 127.0.0.1 -p 22,80,443,8000-8010 --connect
python -m scanix scan -t 127.0.0.1 -p 1-1024 --timeout 0.5 --concurrency 50
python -m scanix scan -t 127.0.0.1 -p 22,80 --banner
```

Single ports, inclusive ranges, and comma-separated combinations are supported.
Ports are deduplicated and sorted. Empty selections, malformed or reversed ranges,
and values outside 1–65535 are rejected before resolution or traffic. Timeout must
be finite and greater than zero, at most 300 seconds; concurrency must be 1–1024.
Defaults are 1 second and 100 workers. At most that many futures are outstanding.

Phase 1 uses IPv4 and resolves each target **once per scan**, choosing the first
IPv4 address returned by the system resolver. A hostname with multiple addresses
is not an instruction to scan them all. The numeric address is used for every
connection and optional banner probe. IPv6 and multi-address policies are future
work. System DNS resolution has its own timing; `--timeout` bounds socket operations,
not DNS resolution or the entire scan.

`--banner` makes a separate best-effort plaintext connection to open ports, reads
at most 2048 bytes, and sends a small HTTP HEAD or SMTP HELO on selected ports.
Each socket operation uses the configured timeout. It can take several timeouts
per port and does not do TLS, service confirmation, or version parsing. A banner
failure does not change a confirmed open result. Banners are untrusted raw evidence;
they are retained in exports and never printed directly to the terminal.

## States and report schema

| State | Reason | Meaning |
| --- | --- | --- |
| `open` | `connection_succeeded` | The TCP connection succeeded. |
| `closed` | `connection_refused` | The OS reported refusal. This is the only TCP failure classified as closed. |
| `unknown` | `timeout` | No conclusive port state. This does **not** establish firewall filtering. |
| `error` | `routing_failure` | Network/host unreachable or down; port state is unknown. |
| `error` | `resolution_failed` | No IPv4 address resolved; no port probe was made. |
| `error` | `permission_denied` | The local system denied the operation. |
| `error` | `resource_exhausted` | Local descriptor, buffer, memory, or source-address resources were unavailable. |
| `error` | `socket_error` | Other OS socket error; no confirmed port state. |
| `error` | `worker_exception` | An unexpected worker failure was observed and recorded. |

`connect_ex()` error codes and raised socket exceptions use the same classification.
Nonblocking in-progress/would-block results at the configured deadline are unknown
with reason `timeout`. Common POSIX and Winsock codes are recognized. Only a native
error code actually supplied by the OS is recorded; unavailable codes are `null`.
A network intermediary can generate a refusal: results describe the observation,
not proof about a particular remote process.

The typed model is in `scanix/core/models.py`. Every result includes:

- `target` (original input), `resolved_ip`, `address_family` (`IPv4`), `port`,
  `protocol` (`tcp`), `scan_method` (`connect` or `syn`).
- `state`, machine-readable `reason`, optional numeric `error_code`.
- `timestamp` (UTC ISO 8601 probe start) and `connection_elapsed_seconds`
  (monotonic elapsed connection attempt, excluding banner work).
- Nullable `service_name`, `detection_source`, `banner`, `version_evidence`, and `os`.

Port table guesses use `detection_source: "port_table"` and are **not confirmed
service detection**. Unknown services and evidence are `null`, including
`version_evidence` and `os`. No OS identification is performed. The old local
socket `IP_TTL` read did not measure remote TTL and has been removed.

JSON schema version 1 has `configuration`, `results`, `started_at`, `finished_at`,
`completion_status`, `incomplete`, `requested_ports`, `completed_ports`, and `issues`.
Configuration records the original target, sorted ports, timeout, requested
concurrency, method, and banner flag. SYN's effective concurrency is always one.
Nested evidence stays structured in JSON. Resolution failures create an error row
for each selected port, with null address/family/elapsed time; `completed_ports`
counts result rows, not successful network probes.

`completion_status` is `complete`, `failed`, or `interrupted`. Fatal setup,
resolution, permission, resource, and internal failures produce `failed`, with
`incomplete: true`, even if every requested port has an error result. Routing and
ordinary socket errors are per-probe observations and do not by themselves make
execution fatal. Final results are sorted by target, resolved address, port, method.

## Export and interruption

```sh
python -m scanix scan -t 127.0.0.1 -p 1-100 --out json --out-file results.json
python -m scanix scan -t 127.0.0.1 -p 22,80 --out csv --out-file results.csv
python -m scanix scan -t 127.0.0.1 -p 22,80 --out html --out-file results.html
python -m scanix scan -t 127.0.0.1 -p 22 --out json --out-file -
```

Without `--out-file`, a requested export defaults to `scan_results.<format>`.
`--out-file -` supports JSON only. Stdout JSON contains only the report; diagnostics
and completion messages go to stderr. Exported results have no added terminal
color/progress data. JSON escapes control characters in remote text; CSV retains
raw banner text. HTML escapes target, banner, evidence, metadata, and title values.
CSV has a `record_type=scan` metadata row followed by `record_type=result` rows;
nested cells and nulls use JSON (`null`, objects, arrays), preserving structure
without Python repr strings. The metadata row exists even for an empty scan.

Files are written to a temporary file in the destination directory, flushed, then
atomically replaced. A failed write leaves an existing destination intact and
returns a failure exit code. Destination directories must already exist.

Ctrl+C stops submission and cancels queued work. Running sockets finish within
their configured operation timeouts; completed results are retained and any
requested export is written with `completion_status: "interrupted"` and
`incomplete: true`. DNS resolution may delay cancellation until the system resolver
returns. The CLI signal handler also protects collection from repeated Ctrl+C;
forced process termination cannot save results.

| Exit code | Meaning |
| --- | --- |
| `0` | Scan executed, including when no ports are open. |
| `2` | Invalid input or unsupported UDP; no scan traffic sent. |
| `1` | Fatal scan/dependency failure or output failure. An output failure takes precedence over interruption. |
| `130` | Interrupted; partial output saved when requested and writable. |

## Experimental and unimplemented features

`--syn` and `--connect` are mutually exclusive; connect is the default. SYN runs
only SYN probes and never silently runs a TCP connect scan. `--syn --banner` is
rejected. The existing Scapy implementation is retained with a common report
schema but **does not meet Phase 1 TCP accuracy guarantees**. It is serialized,
uses fixed TCP flag matching and best-effort RST cleanup, and lacks robust response
correlation, ICMP interpretation, retries, and adaptive timing. No response is
`unknown/syn_no_response`; unrecognized packets are
`unknown/syn_unrecognized_response`; recognized responses use `syn_ack` or
`syn_rst_ack`. Its elapsed field includes packet wait and optional RST cleanup.

UDP is unimplemented: `--udp` explicitly exits with code 2. An unvalidated UDP
prototype in the source tree is not exposed by the CLI. Advanced remote OS
fingerprinting is unimplemented. Legacy `discover` (system ping) and `traceroute`
commands remain available but are outside Phase 1 guarantees and depend on system
utilities. See [ROADMAP.md](ROADMAP.md).

## Development

From the repository root:

```sh
python -B -m unittest discover -s scanix/tests -v
python -m scanix --help
python -m scanix scan --help
```

Tests use loopback servers and deterministic mocks, never external targets. They
cover connect/error semantics, one-time resolution, port validation, method routing,
UDP rejection, bounded scheduling, observed worker errors, socket cleanup,
cancellation, partial exports, ordering, and atomic/escaped output. The suite needs
permission to bind local loopback TCP sockets. GitHub Actions runs it on Python
3.10–3.14 on Linux, with a macOS/Windows portability job on Python 3.14.
