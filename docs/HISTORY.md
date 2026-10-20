# Optional private scan history

History is an opt-in local observation store, separate from native resume checkpoints.
Python remains the default scanner. No database is opened unless requested; offline
preview shows scope without creating history or sending service traffic.

## Commands

Choose an existing owner-controlled directory. On POSIX the parent must belong to
the current user and deny group/other writes; the database must be owner-only (0600).
Windows uses the parent directory ACL; choose a private user directory.

```sh
python -m scanix scan -t 127.0.0.1 -p 8080 --history private/history.sqlite --out json --out-file private/scan.json
python -m scanix scan -t ::1 --family 6 -p 8080 --history private/history.sqlite --preview
python -m scanix history --db private/history.sqlite list --limit 20
python -m scanix history --db private/history.sqlite show SCAN_ID --results
python -m scanix history --db private/history.sqlite diff PREVIOUS_ID CURRENT_ID
python -m scanix history --db private/history.sqlite delete SCAN_ID
python -m scanix history --db private/history.sqlite prune --keep 10
```

Create `private` before the first real scan. Replace IDs with the 32-character IDs
printed after persistence or returned by `list`. History commands are offline and
emit JSON lines with terminal controls escaped. `show` includes configuration,
coverage, original hostname associations, scope policies and implementation/database
versions. `--results` streams stored observations. No automatic retention is applied.

Native bounded streaming can also be persisted:

```sh
python -m scanix scan -t 127.0.0.1 -p 8080 --engine native --checkpoint private/resume.sqlite --stream-file private/results.ndjson --history private/history.sqlite
```

Use a trusted built native binary on PATH (or `--native-binary`). Checkpoint and
stream paths must be new; history can be reused. The existing stream header,
configuration, continuation fingerprint, work IDs, records and final summary are
validated. Same-ID enrichment upserts replace the same numeric endpoint only.
Aggregate reports are inserted in batches too; their scanner still retains aggregate
results. Existing JSON/CSV/HTML exports and native streaming remain available.

## Schema, completion and comparisons

SQLite history schema is **1**, storing report schema **5**. Only initial empty
schema 0 to 1 migration exists. Unknown versions, foreign schemas, extra triggers
and incompatible page sizes fail explicitly, without attempting destructive repair.
The report, scan configuration, selected scope policy, completion status, evidence,
engine/wire/probe/plugin/OS database versions and writer implementation digest are
stored. Version provenance is included in the comparison header.

Records compare canonical numeric address, port and transport. Resolution failures
retain their original label separately. Aliases remain in stored observations.
Comparisons do not assume identical selected scopes from equal policy alone: DNS
answers, exclusions, scan configuration and version differences need consideration.
Only two actual observations can establish a port-state change. Missing records are
`not_observed` or `new_observation`, **never inferred removal or closure**, even for
complete reports. Missing service evidence is not a service-removal claim. Product,
version and confidence changes are unauthenticated evidence changes, not vulnerabilities.
Port-name guesses do not become confirmed service findings. Top-level observation
timestamps, elapsed durations and scheduling counters do not create spurious changes;
protocol evidence changes can still reflect server volatility.

Persistence starts after the scan returns, including interruption; it is not a live
Python scan checkpoint. A crash before persistence needs the native checkpoint/stream
workflow for recovery. A scan header is committed before rows; batches contain at most
16 records. Crashes, invalid/truncated input or failed batches leave an unfinalized
entry. Valid earlier batches remain visible; incomplete coverage is explicit. An
interrupted source remains partial even after all its available rows are persisted.
A truncated NDJSON stream cannot seal an entry. Repeated saves create new scan IDs;
this is not automatic resume or deduplication of whole scans.

History is preflighted before resolution/probes. A later recording failure returns
failure while preserving requested file exports; export failure still attempts
history recording. Diagnostics use exception categories without disclosing paths or
raw evidence. Inspect private files locally after either failure.

## Bounds and privacy

Requires Python's optional SQLite module and SQLite **3.31+**. Ordinary scan/help
commands work without SQLite; explicitly requested history fails clearly. No new
package dependency or code deserialization is introduced. Reads enforce duplicate-key,
JSON depth and encoded-byte limits; schemas are exact, trusted schema is disabled and
extensions are not loaded. FULL synchronization, rollback journals and exclusive
locking favor predictable single-writer durability over concurrent access. A locked
store fails rather than retrying indefinitely. This does not promise filesystem or
hardware durability beyond SQLite and the platform.

Limits: 1 GiB main database (4096-byte pages), 10,000 scans, 1,000,000 observations per
scan, 64 KiB encoded record, 4 MiB metadata, 2 MiB SQLite page cache; list limit 1–1000.
Comparison/record iteration is bounded in Python memory. SQLite indexes and temporary
files use disk and may add space beyond the main database cap. Streaming input is
bounded per frame but total processing time scales with the supplied local file;
there is no overall import deadline. Database checksums detect accidental record
corruption, not malicious modification by the database owner. Files are not encrypted
or authenticated. Store them on trusted local storage, not in source control.

`delete` removes one scan and its observations; `prune --keep N` keeps the newest N
saved entries, **including partial ones**. `--keep 0` deletes all entries. Both are
logical deletion, not secure erasure: backups, journals, filesystem snapshots and
freed database pages may retain data. No automatic VACUUM or overwrite guarantee is
provided. Ignore rules and secret/privacy gates reject scan/database artifacts; ignore
rules do not remove already tracked data. Never upload real histories or captures.

Tests use synthetic reports and owned loopback servers: schema/migration/rollback,
permissions, tampering/byte bounds, partial comparisons, retention, escaped output,
export failures and actual native stream/enrichment/completed resume. Storage changes
do not alter packet handling; earlier isolated packet validation and measured native
baselines retain their recorded source revisions. No history throughput claim is made.

SQLite safety/durability semantics follow the [official pragma documentation](https://www.sqlite.org/pragma.html)
and [Python SQLite interface](https://docs.python.org/3.13/library/sqlite3.html).
