# Phase 4A measured connect baseline

Measured source: `50322ab61e8031525d4be16918fd6de00177ab8a`, clean tree.
Release build, Rust 1.91.1; macOS 27.0.1 arm64, Apple M4, 10 logical CPUs,
16 GiB RAM; Python 3.14.3. Five samples per engine and size, alternating engine
order, fresh worker process per sample. No public targets or elevated privileges.

## Topology and boundaries

One IPv4 loopback host, 32 or 128 ephemeral listening ports, all expected open.
Every sample completed exactly the selected count and all states were open.
Concurrency/per-host 16; rate ceiling 500 connection starts/s; fixed timeout 5 s,
adaptive timeout disabled. No retransmission/packet rate or raw SYN measurement.

Wall time includes scanner/report and native child startup, excludes parent listener
setup and worker interpreter/import startup. CPU includes worker/imports and its
native child, excluding the listener process. RSS is the sum of self/child high-water
marks: an upper bound, not a simultaneous peak. Do not infer CPU utilization or
memory efficiency by dividing these differently scoped metrics.

## Observations

| Ports | Engine | Median seconds | Min–max seconds | Median completions/s | Median CPU seconds | Maximum RSS upper bound (MiB) |
| --- | --- | ---: | --- | ---: | ---: | ---: |
| 32 | python | 0.078171 | 0.077637–0.078497 | 409.4 | 0.105009 | 25.02 |
| 32 | native | 0.106461 | 0.103318–0.108275 | 300.6 | 0.099773 | 27.06 |
| 128 | python | 0.306840 | 0.301294–0.307856 | 417.2 | 0.155188 | 25.19 |
| 128 | native | 0.416761 | 0.410884–0.418292 | 307.1 | 0.122081 | 27.16 |

Native was **slower on this small paced connect baseline**. A rate is a ceiling,
not a throughput promise. No bottleneck cause was instrumented or established.
These measurements are a foundation baseline, not SYN/packet-loss performance,
general network accuracy or Nmap/Masscan parity. Phase 4C optimization remains future
work. IPv6 functionality is tested separately; no IPv6 performance claim is made.

## Reproduce

Build at the source commit above in an isolated checkout, using the pinned runtime
requirements and Rust toolchain described in NATIVE_ENGINE.md. For current source:

```sh
cargo build --release --locked --manifest-path native/Cargo.toml
python -B validation/native_benchmark.py --binary native/target/release/scanix-engine --ports 32 --samples 5 --output /tmp/scanix-baseline-32.json
python -B validation/native_benchmark.py --binary native/target/release/scanix-engine --ports 128 --samples 5 --output /tmp/scanix-baseline-128.json
```

Use `.exe` on Windows. POSIX CPU/RSS measurements are unavailable on Windows and
are reported as null. Store generated reports outside Git; this aggregate contains
only controlled topology and measured timing/resource values, no raw scan evidence.
Timing varies with hardware, timer resolution, system load and runtime versions.
