# Phase 4C controlled validation and measurements

Measured and live-tested source: `66123724901cf85848a433bb2795b992c4a46ebd`.
No public targets, production credentials or uploaded raw captures/reports. The final
follow-up adds inline-export guards, documentation and artifact-gate boundary tests;
transmission, classification, scheduling and checkpoint algorithms are unchanged.

## Durable stream baseline

macOS 27.0.1 arm64, Apple M4, 10 logical CPUs, 16 GiB RAM; Python 3.14.3,
SQLite 3.52.0, Rust 1.91.1 release binary. Clean tree. Three fresh worker processes
per mode/batch, alternating aggregate/stream order. IPv4 loopback, one host and 128
ephemeral accepting TCP listeners, all expected and observed open; exactly 128 unique
completed pairs per sample. Fixed timeout 5s, adaptive off, concurrency/per-host 16,
ceiling 500 connection starts/s. No SYN, raw packet-loss or high-volume measurement.

Wall includes scanner/adapter startup; streaming adds binary/source hashing, SQLite
setup/FULL+fullfsync commits and NDJSON writes. Worker interpreter/import and listener
setup are excluded from wall. Python tracemalloc is enabled during both modes. CPU
includes worker/imports and child; RSS is the sum of self/child lifetime high-water
marks, an upper bound, not simultaneous or isolated Rust workload memory. Tracemalloc
excludes Rust and SQLite C allocations. Do not derive CPU utilization from unlike scopes.

| Batch | Mode | Median seconds | Min–max seconds | Median pairs/s | Median CPU seconds | Maximum RSS upper bound MiB |
| --- | --- | ---: | --- | ---: | ---: | ---: |
| 1 | aggregate | 0.415033 | 0.411290–1.049616 | 308.4 | 0.131141 | 32.48 |
| 1 | stream | 2.208202 | 2.193916–2.211953 | 58.0 | 0.300354 | 33.59 |
| 16 | aggregate | 0.412072 | 0.403825–0.416116 | 310.6 | 0.114336 | 32.52 |
| 16 | stream | 0.523470 | 0.520159–0.523756 | 244.5 | 0.157404 | 33.59 |

Per-result mode: 128 result commits, median 2.011454s in transactions. Batch16:
eight commits, .124700s. Median durable stream wall fell from 2.208202s to .523470s
at this same source; it remains slower than aggregate output. The optimization addresses
measured local flush overhead; it changes crash replay granularity, not packet speed.
Batch1 remains available. Sparse batches target a .25s monotonic flush; normal completion/
cancellation commits a final partial batch. SQLite/OS flush latency is not a hard bound.

Streaming retained zero report result objects vs 128 for aggregate; both checkpoints were
106,496 bytes. Peak Python traced memory was about 274,293 bytes for streaming vs
145,354–145,519 bytes for aggregate: fixed overhead made this small case larger, not
smaller. No large-scan memory/scalability claim follows. Completed-checkpoint replay
launched no engine; median .048943s (batch1) and .046252s (batch16).

## Isolated Linux SYN ground truth

[Workflow run 39400801059](https://github.com/numankhaan/scanix/actions/runs/39400801059)
passed all **33 native checks**, plus the retained Phase 2 namespace/capture suite and
optional privileged loopback cases. Scanner/peer namespaces with veth, no external
default route; synthetic 10.203.0.1/29 and 10.203.0.2/29 only. Four scoped ports:
18000 DROP=unknown/no_response; 19000 listener=open/syn_ack; 19001 closed=syn_rst_ack;
19002 administrative REJECT=filtered/icmp_administratively_prohibited. Timeout .4s,
retry1, fixed timeouts, rate20 explicit packets/s, concurrency/per-host4, cooldown200ms.
CIDR/exclusions retained only the peer. No ARP for routed networks or public traffic.

Baseline observed all four states, five SYN sends including one retry, one reset,
three matched replies and one timeout; engine/kernel/userspace drops zero. Session
1.603081s, native CPU .011642s; RSS high-water 93,491,200 bytes may include the pre-exec
Python image and is an upper bound. This four-pair correctness case is dominated by
silence/cooldown, not a throughput benchmark.

Continuation checks interrupted a durable session with completed evidence, resumed
missing work, checked final states/coverage, and independently verified **no SYN was
sent to completed ports**. A completed checkpoint re-export sent **no probes** and
launched no engine. Captures remained private/ephemeral; only digests/counts follow.

| Capture | Packets | Kernel drops | SHA-256 |
| --- | ---: | ---: | --- |
| native-syn | 10 | 0 | `dd0da006638830bbee7238c04c02a4095d72d5b994069ac369f5cd8e1b25574c` |
| native-excluded | 0 | 0 | `615b36d88ab5e59eaca680e5d9204c1a5ee4151d1d81488709776053e5161d95` |
| native-cancel | 5 | 0 | `2b4962b7075073dbbdc073914690c6132976707b352e0266c60bf4462e78d6ab` |
| native-resume-partial | 6 | 0 | `b0b2995392c23f379c7ef6b34a36f26c314f3860f89ba7d11f6907957c34b785` |
| native-resumed | 4 | 0 | `2dea2c5d44647c2faaf5c53c28d23553445d7820086f4e0eb5691255be7dc2f3` |
| native-complete-resume | 0 | 0 | `615b36d88ab5e59eaca680e5d9204c1a5ee4151d1d81488709776053e5161d95` |

## Reproduce

Build the release binary, create a trusted private output directory, and run:

```sh
python -B validation/continuation_benchmark.py --binary native/target/release/scanix-engine --ports 128 --samples 3 --batch 1 --output .security-private/batch1.json
python -B validation/continuation_benchmark.py --binary native/target/release/scanix-engine --ports 128 --samples 3 --batch 16 --output .security-private/batch16.json
```

The benchmark refuses to overwrite output. Each worker uses a temporary private
checkpoint/stream. For optional isolated Linux validation, use the documented guarded
`validation/privileged_lab.py --native-binary ...` procedure in NATIVE_SYN_RESULTS.md;
regular CI needs no privileges. Never publish private benchmark outputs or captures.

Coverage limitations: three samples on one machine, one small all-open connect workload,
no IPv6 performance distribution, no hardware power-loss injection, no cross-filesystem
flush guarantee, no high-speed loss characterization or Nmap/Masscan parity. Native
IPv6 SYN/UDP/discovery remain unsupported; privileged macOS/BPF remains incomplete.
Check latest PR/main CI separately from these source-specific measurements.
