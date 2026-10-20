# Native engine boundary (Phases 4A–4B)

Python remains the default. The original Python TCP/SYN/UDP paths remain available.
The opt-in Rust engine **implements asynchronous TCP connect scanning** for numeric
IPv4/IPv6 targets on Linux, macOS and Windows. Phase 4B adds validated Linux IPv4 SYN
([support and evidence](NATIVE_SYN.md)). Native UDP/discovery are not implemented. Unsupported requests fail explicitly; no engine fallback or
automatic build/download happens. This is a foundation and connect baseline, not
a high-speed or parity claim.

## Build and use

The manifest declares Rust **1.85** as its minimum. A dedicated Linux CI job
builds and tests the locked dependencies with Rust **1.85.0**; the cross-platform
integration matrix uses **1.91.1**. Commit Cargo.lock and build with `--locked`. A release binary is separate from the Python
installation; no new Python runtime dependency is needed.

```sh
cargo build --release --locked --manifest-path native/Cargo.toml
python -m scanix scan -t 127.0.0.1 -p 8080 --engine native --native-binary native/target/release/scanix-engine
python -m scanix scan -t ::1 --family 6 -p 8080 --engine native --preview
python -m scanix scan -t 127.0.0.1 -p 8443 --engine native --native-binary native/target/release/scanix-engine --service-detect --tls-insecure
```

On Windows use `native/target/release/scanix-engine.exe`. Alternatively set
`SCANIX_NATIVE_ENGINE` to that trusted executable's path, or put `scanix-engine`
on PATH. This executable is trusted local code, **not sandboxed**; its path never
comes from target files or remote responses. Missing/unusable binaries, incompatible
protocols, unsupported methods and protocol failures are errors, not Python retries.
`--banner` and scan discovery gates are explicitly unsupported in native foundation;
use Python for these, or `--service-detect` for the separate enrichment stage.
Offline preview starts no child process and needs no compiler or executable.

Targets are resolved/normalized once by the Python scope layer, with existing
family/DNS-answer/exclusion policies. The child receives selected numeric targets
only; it performs no DNS and cannot follow names in responses. Hostname associations
remain in Python reports and supply SNI to existing bounded service detection.

## Versioned wire contract

Protocol **3**, UTF-8 JSON objects, exactly one newline-terminated object per frame,
maximum **65,536 bytes including newline**. Adapter response JSON is limited to
16 container levels, independently of interpreter recursion behavior. Unknown commands/fields, duplicates,
malformed input, nonnumeric target addresses and out-of-limit settings are rejected
before network operations. The child emits only protocol data to stdout; fatal
pipe/backpressure diagnostics can also go to stderr. The adapter exports only its
byte count, not arbitrary stderr or local exception messages. No shell or arbitrary code is
selected by wire messages.

Sequence:

1. Child `hello`: protocol=3, engine=scanix-rust, engine_version=0.4.2,
   capabilities=[connect] (plus syn_ipv4 on Linux), limits. A client must validate protocol and capability before transmitting scope/start.
2. Parent `start`: protocol, method, sorted unique ports; timeout_ms,
   min_timeout_ms/max_timeout_ms/adaptive; concurrency/per_host/rate;
   max_targets/max_results/session_timeout_ms, retries and cooldown_ms. All fields are required.
3. Zero or more parent `target` frames with a numeric `ip`, followed by `run`.
   Targets must be unique. No traffic starts before complete scope preflight.
4. Child `ready` records exact requested address/port pairs. Child streams `result`
   frames as operations finish, with deterministic work ID, target index, numeric
   IP, port, state, reason, optional OS error and monotonic elapsed seconds.
5. Parent may send `cancel` before or after `run`; direct SIGINT also cancels.
   EOF after `run` means no more control input, not cancellation. Unexpected control
   frames during scanning fail execution, retaining already completed rows.
6. Child `done`: status complete/interrupted/failed, requested/completed/attempted,
   peak_outstanding, elapsed_seconds, optional reason. No frames follow it.

Registration-time cancellation may emit `done` without `ready`, with zero completed
operations and only registered coverage counted in its native metric. Python keeps
full requested coverage in its report and marks it interrupted/incomplete.
A fatal preflight emits `diagnostic` (code, fatal=true) and exits without `ready`.
The adapter rejects duplicate IDs, out-of-scope results, contradictory state/reason,
nonfinite durations, invalid coverage and exit-status disagreement. A failed worker,
pipe or protocol never discards previously received result rows or invents closed
ports. Completed ports survive interruption, including queued completed native work.

Exit codes: **0** completed, **2** invalid input/protocol, **3** execution/I/O/session
budget failure, **4** unsupported method, **130** cancelled. The adapter retains
execution diagnostics separately from port classification. Complete coverage with
local resource/permission failures still marks the Python report failed.

## Bounds, timing and evidence

The table below describes connect. SYN concurrency, retry, capture and packet
rate bounds are documented separately in [NATIVE_SYN.md](NATIVE_SYN.md).

| Resource | Enforced bound |
| --- | --- |
| Frame / stdio channels | 64 KiB; 32 frames per channel |
| Targets / ports / work pairs | 65,536 / 4,096 / 1,000,000 maximum |
| Outstanding native work | min(concurrency, per_host), each 1–1024 |
| Host scheduling | serial targets, asynchronous ports; no unbounded task creation |
| Per-connect timeout | 1–300,000 ms; optional bounded RTT adaptation, same EWMA rules as Python |
| Start rate | 0.000001–10,000 connection starts/s, global monotonic pacing, no burst credit |
| Total session | --engine-timeout, default 3,600 s; range 0.1–86,400 s including pacing |
| Blocked output frame | 5-second acknowledgement deadline, then exit 3 |
| Adapter pipe queues / stderr | 32 frames / drained and counted, never exported |
| Adapter startup / cancel / final-exit watchdog | 30 s / 2 s / 2 s, then kill and retain received results |

All registration input is bounded; no work outside registered IP/port pairs is
accepted. Rust streams results without collecting them. The **Phase 4A Python
compatibility adapter still aggregates typed results** within the explicit million
pair ceiling for existing atomic JSON/CSV/HTML exports. Durable resume and a true
end-to-end non-aggregating output mode belong to 4C and are not claimed here.

TCP success is open; refusal closed; silence/timeout unknown; local failures error.
Error codes remain platform-specific. TCP retransmissions/ACKs and system link
resolution are outside the application start rate. No native connect retry occurs.
Target order and sorted port indexes yield stable work IDs; completion order may
vary. RTT adaptation excludes timeouts and uses successful/refused connections only.
Windows loopback refusal can require roughly two seconds; use fixed timeout 5 s
when testing eventual refusal, as in existing regression coverage.

Service detection runs afterward through the existing separate Python stage with
its worker/byte/time/exclusion controls, sharing configured rate semantics. A
conservative one-interval guard separates native connection starts from enrichment.
It cannot turn an observed open port into closed. No service traffic occurs unless
requested. Cancellation wakes native work promptly while a slow/non-reading
consumer can delay shutdown up to the documented pipe deadline.

## Report compatibility, tests and benchmarks

Report schema **5** retains top-level `implementation` metadata and configuration
engine/session-budget fields. CSV adds the implementation metadata column. Python
reports identify engine=python; native reports include engine version, wire protocol,
exit code and metrics. Existing result/service fields and atomic file exports remain.
Schema-3/4 consumers must accept the new schema/column; the probe database stays 1.0.0.

```sh
cargo test --locked --manifest-path native/Cargo.toml
cargo clippy --locked --manifest-path native/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path native/Cargo.toml --check
python -B validation/native_ci.py
python -B validation/native_benchmark.py --binary native/target/release/scanix-engine --ports 32 --samples 3 --output /tmp/scanix-connect-baseline.json
```

The native CI workflow builds pinned Rust on Linux/macOS/Windows and runs the full
Python suite with the real executable, including Python/native agreement, IPv6,
exclusions, cancellation and trusted TLS/SNI enrichment. Regular Python-only jobs
explicitly skip five native integration tests if no executable is configured; mock
wire tests still run. Privileged tests stay optional and macOS/BPF validation remains
**incomplete**. No regular test or benchmark uses public scan targets or privileges.

The benchmark uses ephemeral listening loopback ports only, alternating engines,
fresh worker processes, fixed configuration and a release binary. It records actual
elapsed time, CPU and a clearly labeled RSS upper bound on POSIX; unavailable metrics
are null. It is a small connection/IPC baseline including native startup, not a
packet-throughput or accuracy benchmark. See [measured baseline](../validation/NATIVE_BASELINE.md) for actual results;
native was slower in these small paced loopback samples.

Implementation references: [Tokio bounded channels](https://docs.rs/tokio/latest/tokio/sync/mpsc/),
[Tokio TcpStream](https://docs.rs/tokio/latest/tokio/net/struct.TcpStream.html),
[Rust bounded BufRead](https://doc.rust-lang.org/std/io/trait.BufRead.html),
[Python subprocess pipe cautions](https://docs.python.org/3/library/subprocess.html).
The adapter drains stdout/stderr concurrently and bounds both data and child lifetime.

Rust dependencies serve the boundary: serde/serde_json provide typed, strict JSON
and Tokio provides bounded asynchronous sockets, channels and monotonic timers.
Cargo.lock pins transitive versions; no Rust source is vendored and no additional
Python runtime dependency is introduced. The manifest disables package publication.

At the integration milestone, 8 Rust tests and 138 Python tests with the actual
release subprocess passed (136 passed/two privileged skips). With no native binary
configured, 131 passed/seven explicit skips: five native plus two privileged.
Nineteen security-gate tests, Bandit, workflow policy/actionlint, pip-audit and
cargo-audit/fmt/Clippy passed. Cross-platform native claims depend on PR CI;
local validation is macOS arm64 only. Measured baseline results are recorded
separately, not inferred from these test outcomes.

## Phase 4C selection contract

Wire protocol 3 adds `shard_index` (zero-based), `shard_count` (1–1024) and
`completed` setup frames with at most 4,096 IDs each. Work ID is target index ×
port count + sorted port index. Shards partition IDs by modulo. All registered
completed IDs must be unique, in scope and in the selected shard. Both native
schedulers exclude them before creating work. Ready/done counts describe remaining
selected work, while result IDs retain the full-scope identity. Incompatible engines
fail before receiving scope; there is no engine fallback.

The Python adapter supports a bounded result callback and explicit non-retention.
Its duplicate bitmap is at most one million bytes; scope is still bounded separately.
Durable storage and CLI integration are implemented; see [continuation semantics](CONTINUATION.md)
and [source-specific measurements](../validation/CONTINUATION_RESULTS.md).
