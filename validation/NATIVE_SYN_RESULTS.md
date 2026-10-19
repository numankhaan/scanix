# Phase 4B isolated Linux validation

Implementation/lab source: `d181e1b1eee2ea1cd71c8bb8f9db112576bac67d`.
[Opt-in run 39342284692](https://github.com/numankhaan/scanix/actions/runs/39342284692)
completed successfully. All **25 native SYN checks** passed; the existing Phase 2
namespace state/capture and optional loopback checks also passed in the same job.
Raw captures/reports stayed private in the ephemeral runner; no artifacts uploaded.
The sanitized log contains measured counters, capture digests and synthetic states.

## Ground truth and observed behavior

Fresh scanner/peer namespaces, veth, no external default routes. Static synthetic
IPv4 lab addresses `10.203.0.1/29` and `10.203.0.2/29`; no public targets. Silent
port deliberately sorts first, so capture proves later sends continue during its
response window. CIDR exclusions leave exactly the peer in scope.

| TCP port | Controlled peer | Observed state/reason | Actual attempts |
| --- | --- | --- | ---: |
| 18000 | Firewall DROP | unknown/no_response | 2 |
| 19000 | Listener | open/syn_ack | 1 |
| 19001 | No listener | closed/syn_rst_ack | 1 |
| 19002 | Administrative REJECT | filtered/icmp_administratively_prohibited | 1 |

Independent capture correlation passed for every row, including quoted ICMP details,
full retry count and correct RST/ACK sequence/acknowledgment. The open probe was sent
before the first silent probe's response window expired. Separate captures proved
empty exclusions send no SYN and cancellation retains the observed open port.
Python SYN state agreement passed independently of the known firewall/listener truth.

## Measured single-case baseline

GitHub-hosted Ubuntu Linux, x86_64, 4 logical CPUs, approximately 15.6 GiB physical
RAM (16,760,340,480 bytes). CPU model/frequency were not collected. Release Rust
1.91.1; four work pairs, concurrency/per-host 4, fixed response timeout .4 s,
retry budget 1, packet ceiling 20/s, final cooldown .2 s.

| Measurement | Observed |
| --- | ---: |
| Native session elapsed seconds | 1.602964998 |
| Unique attempted/completed pairs | 4/4 |
| Explicit SYN / retry subset / reset sends | 5/1/1 |
| Native send errors | 0 |
| Matched / duplicate / late replies | 3/0/0 |
| Timeouts | 1 |
| Peak outstanding / per-host | 4/4 |
| Kernel capture / userspace queue drops | 0/0 |
| Measured final receive cooldown ms | 200 |
| Minimum captured explicit-packet gap seconds | 0.050554 |
| Completions per full native session second | 2.4954 |
| Explicit packets per full session second | 3.7431 |
| Native-process CPU seconds (lifetime) | 0.014989 |
| Process RSS high-water upper bound bytes | 93597696 |
| Adapter/capture-decode parent CPU seconds | 0.009967 |
| Wall seconds including capture setup/drain | 1.754534 |

This is one deliberately small correctness case dominated by silent-port retry and
cooldown, **not a maximum throughput benchmark**. Zero observed socket/queue/tcpdump
drops do not prove zero end-to-end network loss. Capture counters cover selected
sockets; kernel-generated RST/ARP traffic is outside explicit application sends.

`getrusage(RUSAGE_SELF)` measures the child process lifetime. Linux retains usage
across exec, so RSS can include the forked pre-exec Python image and is an upper
bound, not isolated Rust allocator/native-workload memory. Parent CPU includes
adapter/capture decoding; RSS excludes kernel socket buffers. CPU and wall windows
differ: do not infer utilization/speedups from them. Native CPU/RSS failures remain
unknown rather than fabricated zero. See [Linux getrusage documentation](https://man7.org/linux/man-pages/man2/getrusage.2.html).

## Independent capture digests

| Case | Packets | Capture drops | SHA256 |
| --- | ---: | ---: | --- |
| native-syn | 10 | 0 | `d83662c1f2dc8c6318a61500466feb3ce4e8b89d9794a500874c0f6b5c616e40` |
| native-excluded | 2 | 0 | `8d57de5da553c565c20a5d3eeb4d53c609915ca45faee94b92b8e4f85683da75` |
| native-cancel | 5 | 0 | `a119d73ed1530976cc6a6bc5aec32870098c86253c3cd7bfc7ccd3a52260f890` |

## Reproduce

Build matching release source, install the documented Scapy/lab dependencies, then
on an authorized Linux host with namespace/admin/raw capabilities:

```sh
cargo build --release --locked --manifest-path native/Cargo.toml
sudo -- "$(command -v python)" -B validation/privileged_lab.py --output /tmp/scanix-private-syn-lab --native-binary "$PWD/native/target/release/scanix-engine"
```

The output directory must be new. The wrapper verifies fresh namespaces/no default
routes before scanning. Do not upload raw captures/reports. The optional GitHub
workflow runs the same guarded command; regular CI stays privilege-independent.
Local macOS invocation returned unavailable (exit 2), not pass. Native macOS/Windows
raw SYN and native IPv6 SYN are unsupported. Privileged macOS/BPF remains incomplete.
No parity, scalability or high-speed claim is made.
