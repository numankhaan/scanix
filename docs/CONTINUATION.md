# Durable native continuation and streaming (Phase 4C)

Python remains the default. Checkpoints/shards currently apply to the explicitly
selected native connect or Linux IPv4 SYN engine. Existing aggregate JSON/CSV/HTML
exports continue to work without the new options. They retain results in memory.

## Interface and compatibility

Build the engine with `cargo build --release --locked --manifest-path native/Cargo.toml`.
The adapter and binary must both support wire protocol 3 (engine 0.4.2). There is no
fallback to an old binary or the Python engine. Report schema stays 4, with optional
`completed_probes` for nonretained results and implementation continuation metadata.
Checkpoint format and NDJSON stream format are independently versioned at 1.

For an authorized loopback endpoint (choose an existing local listener):

```sh
python -m scanix scan -t 127.0.0.1 -p 19000 --engine native --native-binary native/target/release/scanix-engine --checkpoint private.sqlite --stream-file first.ndjson
python -m scanix scan -t 127.0.0.1 -p 19000 --engine native --native-binary native/target/release/scanix-engine --checkpoint private.sqlite --stream-file resumed.ndjson --resume
```

Both paths are explicit, private local artifacts and must not already exist for a
new scan. Resume requires an existing checkpoint and a **new** stream file; it never
overwrites the previous partial stream. Choose a trusted, owner-controlled parent
directory. POSIX files are created mode 0600; resume rejects symlinks, nonregular
files, other owners and group/other permissions. Windows inherits directory ACLs;
use an owner-private directory. Ignore rules are prevention, not removal of tracked
files or history. Never upload real results/checkpoints to public PRs or CI artifacts.

`--checkpoint` and `--stream-file` are required together; aggregate `--out` is mutually
exclusive. Add `--preview` to see continuation/shard/enrichment policy without opening
a checkpoint, hashing/running a binary, resolving DNS (unless explicitly requested),
or sending probes. Preview does not assert checkpoint compatibility.

## Durable work and crash semantics

The manifest hashes every configuration field, input/exclusion/family/DNS policy,
resolved numeric target and original hostname association, ordering, shard, report/
wire/format version and exact trusted binary bytes. Resume re-resolves the explicit
scope and rejects any difference **before traffic**. Changed DNS answers/order or a
rebuilt/upgraded binary therefore require a new checkpoint; no automatic migration
or widened scope. A checkpoint is local unauthenticated evidence, not a signature or
proof against a malicious person who can edit the file.

SQLite FULL synchronous rollback-journal commits persist one validated result before
it is emitted. Exclusive locking rejects concurrent writers and is released by the
OS after a crash. Fixed schema validation rejects extra views/triggers; SQL is fixed
and parameterized, extensions are not enabled. Per-record digests detect accidental
record corruption; they do not authenticate data. No pickle/code is loaded. Standard
SQLite/filesystem durability assumptions apply, not a guarantee against broken disks,
network filesystems or lying flush implementations. Regular tests exercise abrupt
process exit, not power-loss hardware fault injection.

A result becomes completed only when durably committed. Unfinished probes may already
have reached the network; after interruption/crash they may be sent again. Semantics
are **at least once for unfinished work**, not exactly-once transmission. A normal
interrupt preserves completed rows; resume skips those IDs in both native schedulers.
After a crash or missing engine completion frame, old process-wide send/drop/resource
metrics can be unknown and remain explicitly unknown, rather than zero. Known capture/
transmission loss is sticky in the checkpoint and prevents a clean completion; use a
fresh checkpoint for a new observation. Positive evidence remains preserved.

A completed checkpoint can be re-exported without launching an engine. Each invocation
first streams restored rows, then new rows, then optional enrichment updates and a final
summary. Result frames are **upserts by stable work ID**; enrichment may repeat an ID.
Latest frame wins. A missing final summary, malformed/truncated final line or a summary
with `incomplete: true` must be treated as partial. The durable checkpoint is authoritative
if streaming fails after a commit. Resume creates a full new stream, so a consumer need
not combine two files. File exports contain private unauthenticated network evidence.

## Scheduling and bounds

Work ID = resolved target index × sorted selected-port count + port index. Scheduling
is deterministic for the same resolved scope/configuration. `--shard 0/3`, `1/3`, and
`2/3` partition IDs by modulo; the index is zero-based and count is 1–1024. Exclusions
are applied before IDs are assigned. Shards share no completed work or rate coordinator:
configure each process's rate so their combined traffic stays within your authorization.
Changing shard count/index is incompatible with an existing checkpoint.

Scope remains bounded to 65,536 targets, 4,096 ports and one million full-scope pairs.
Completed/duplicate bitmaps are at most one million bytes each, plus the bounded target
and port scope. Streaming retains zero result objects in the report; one record at a
time is serialized/restored, SQLite cache is 2 MiB, records are at most 64 KiB and a
new 4 KiB-page checkpoint is capped at 1 GiB. Disk exhaustion or scanner/storage failure
is an error, never a clean scan. These are bounds, not measured total process RSS.

A resumed port session waits one conservative rate interval before new sends; it fails
explicitly if that guard cannot fit the remaining session budget. Native session budgets
are reduced by setup/replay/guard time; normal cancellation/watchdog drain grace remains.
Blocking filesystem flushes depend on the OS/storage. The engine retains its bounded
queues, per-host limits, pacing and retry semantics. Slower storage can backpressure the
engine; a bounded engine output timeout fails explicitly and retains committed records.

Service detection remains a subsequent stage after classification, using existing
protocol/exclusion/TLS/rate/timeout policies. Streaming enrichment currently runs one
endpoint at a time, within configured concurrency/per-host maxima and the remaining
session budget. Completed evidence is durably updated; failed enrichment cannot change
port state. Interrupted/not-attempted enrichment may be retried on resume. Stream consumers
must process updates. Classification rate and application/TLS transmission rate remain
distinct domains; kernel traffic is not counted as explicit raw packet sends.

## Validation status

Implementation and deterministic/local loopback tests are in progress. See the persistent
checkpoint for actual commands/outcomes. Do not treat compilation or unit fixtures as
privileged network validation. Phase 4B's existing optional isolated Linux lab remains;
privileged macOS/BPF remains incomplete. Measurements will be recorded separately; no
Nmap/Masscan parity or high-speed claim follows from this feature.
