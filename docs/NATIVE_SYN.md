# Native IPv4 SYN — Phase 4B implementation draft

PR #12 remains draft until isolated Linux ground-truth and packet-capture validation
pass. Synthetic tests/cross-compilation do not establish a working raw backend.
Python remains default; native connect remains available on Linux/macOS/Windows.

## Selection and compatibility

```sh
cargo build --release --locked --manifest-path native/Cargo.toml
python -m scanix scan -t 127.0.0.1 -p 8080 --engine native --syn --preview
```

Live native SYN requires Linux and CAP_NET_RAW (usually root), and the explicitly
selected trusted binary. Only numeric IPv4 SYN is supported. Native IPv6 SYN,
UDP and discovery are rejected before traffic; use existing Python implementations
where supported. No Python connect fallback or automatic binary download/build.

Wire **protocol 2**, engine **0.4.1**: adds required retries and cooldown_ms start
fields, SYN/ICMP state evidence and measured counters. Version-1 clients/binaries
reject the mismatch; rebuild a binary matching the checkout. Connect semantics
remain unchanged. Report schema remains 4; per-result attempts/evidence and top-level
implementation metrics use existing typed fields/exporters.

## Boundaries and bounds

Pure packet construction/classification is separate from Linux I/O and deterministic
work state. IPv4/TCP headers/checksums are constructed directly; reverse endpoints,
ports and SYN sequence+1 ACK are required for SYN/ACK or RST/ACK. Naked RST,
outbound self-matches, malformed/truncated/fragmented IP, and unrelated packets do
not classify. Quoted ICMP must match original source/destination, ports and sequence.
TCP checksum validation is not claimed: local capture offload can expose unfinished
transport checksums. Packet evidence is unauthenticated, not cryptographic identity.

Preflight validates every target, routes/source addresses, OS entropy, raw-socket
privilege and capture descriptors before scheduling SYNs. Source selection uses a
UDP connect without sending any payload. Capture uses non-promiscuous AF_PACKET
SOCK_DGRAM bound to selected interfaces, not libpcap. Limit 16 interfaces, requested
1 MiB receive buffer each (Linux doubles SO_RCVBUF, kernel caps may reduce it).
IPv4/multicast/broadcast scope failures are explicit. Route changes during scanning
are not monitored; time-bounded silence remains inconclusive.

Independent Tokio transmitter and receiver tasks share bounded channels (32 frames,
receive frame maximum 65,535 bytes). Work admission is round-robin across hosts;
pending+ready rows are bounded by global concurrency (1–1024), per-host limits apply
independently, recent-response bookkeeping is capped at 1024 probes. Existing target,
port/pair/frame ceilings remain. Rust streams; Python still aggregates up to the
million-pair ceiling for atomic exports. Durable resume/end-to-end streaming is 4C.

The global monotonic packet ceiling includes all explicit SYNs, retries and RST/ACK
cleanup, with no burst credit. Kernel ARP, retransmissions or automatic RSTs are
outside this accounting. Default SYN ceiling 10 packets/s; response retries default
1, bounded 0–5. Each retry waits for the previous response deadline; exponential
backoff is bounded. Optional per-host RTT estimation excludes retried/ambiguous
responses. Cleanup uses the validated peer sequence and probe acknowledgment.

`--syn-cooldown` defaults 0.2 seconds, range 0–1: extends the final response window
for each probe and enables a final receive drain for late/duplicate accounting.
Replies after a completed probe's budget increment late counters without reopening
the result. Cancellation stops new sends and drains reception for at most 200 ms,
retaining matched rows even if reset cleanup could not complete. Parent watchdogs
and stdout backpressure bounds from the foundation remain. No-response work still
pending on cancellation is incomplete coverage, not a completed closed port.

## Evidence and metrics

- Matching SYN/ACK: open/syn_ack, followed by paced RST/ACK cleanup.
- Matching RST/ACK: closed/syn_rst_ack.
- Quoted ICMP administrative codes 9/10/13: filtered/icmp_administratively_prohibited.
- Other relevant destination-unreachable/time-exceeded evidence:
  unknown/icmp_unreachable_or_path_error.
- Silence after full retry/window/cooldown budget: unknown/no_response.
- Local transmission failure: error; setup failure retains zero-probe failed coverage.

Reset errors do not erase an observed open state. Actual successful SYN/retry/reset
sends, unique attempted work, send errors, matched/duplicate/unmatched/late packets,
timeouts, peaks, receive cooldown and userspace queue drops are reported separately.
PACKET_STATISTICS supplies kernel capture drops where available; unknown is null,
not zero. These counters cover selected capture sockets, including unrelated traffic,
and do not infer end-to-end network loss. Measured capture drops/queue drops or send
errors mark execution failed while preserving completed rows. Raw packets, arbitrary
stderr and exception messages are not exported. Service enrichment remains a separate
bounded stage, explicitly requested and scoped to confirmed open results.

## Validation still required

Pure packet/work-state/wire tests and cross-builds run without privileges. Regular CI
must retain Python/native connect, security, Rust lint/audit and minimum 1.85 coverage.
Live namespace validation must independently check open/closed/admin-filtered/silent
states, retries, resets, pacing, exclusions, parallel outstanding sends, cancellation,
IPv6/platform rejection and Python agreement, plus capture/drop/resource measurements.
No live native SYN results or performance figures are claimed yet. Privileged macOS/BPF
validation remains incomplete; this backend explicitly does not support macOS raw I/O.

Primary API references: [Linux packet sockets](https://man7.org/linux/man-pages/man7/packet.7.html),
[Linux raw sockets](https://man7.org/linux/man-pages/man7/raw.7.html),
[Tokio AsyncFd ownership/readiness](https://docs.rs/tokio/latest/tokio/io/unix/struct.AsyncFd.html).
