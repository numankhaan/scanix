# Phase 6 candidate validation record

Candidate1.0.0rc1; prepared locally without publishing. Code source **8940b35ba6e5ecc03a9557f6a3b818d802063191**. This is the local pre-push validation snapshot; current CI outcomes are recorded in PR #17 and the progress checkpoint. Local passes below are not CI outcomes. Keep the PR draft pending the remaining CI job and licensing decision. Privileged macOS raw/BPF operation is experimental and unverified; tested unprivileged macOS functionality is retained.

## Actual local execution

- `python -B -m unittest scanix.tests.test_release_validation`: **3 passed** (deterministic/offline corpus, budget bounds, distribution rejection of synthetic private/unexpected members).
- `python -B validation/parser_corpus.py --cases 128`: **3,120 inputs passed**, outcome SHA256 `928fb0459f555587d7adfb7239f84d763e34da8178afce8eec798aaa0f0b381a`. This finite mutation corpus is not coverage-guided fuzzing or exhaustive accuracy evidence.
- `cargo test --locked --manifest-path native/Cargo.toml structured_mutations_never_accept_mismatched_endpoints_or_ack`: **1 passed**. Checksum-repaired endpoint/ACK mutations are rejected; existing native fuzz/truncation tests remain in CI.
- `python -B validation/package_smoke.py`: **8 checks passed**, 52 runtime members, built wheel from sdist (final validation disables build isolation and package-index access after pinned tool installation), fresh isolated install, matching CLI/version, both bundled registries, IPv6 offline preview, real owned IPv4 HTTP/plugin/history scan, same-candidate reinstall/history unchanged. No prior wheel/cross-version upgrade or installed native binary claim.
- `python -B -m unittest discover -s security/tests`: **20 passed**. `python security/run.py bandit`: **0 findings**; `workflows`: actionlint passed, policy0 failures; `dependencies`: runtime0/build-tools0/tool-environment0 advisories; `rust`: cargo-audit0 advisories/0 warnings, formatting and Clippy passed.
- Local tools: Python3.14.3, SQLite3.52.0, Rust1.91.1, Scapy2.8.0; pinned build1.6.1/setuptools84.2.0 and existing reviewed security tool versions. No public scan, privilege requirement, raw finding upload or new exception.

Phase5C final head955d5b09bbc161196d220e7d18a26949f63b1b73 passed all8 push/PR workflows before merge51288fe75298fb29bab9cc88903ff0ff35fabc8d. Post-merge CodeQL39474664273, Tests39474663922, Native39474664070, Security39474664219 all passed. Those are base validation, not candidate-head CI.

## Measured synthetic history storage

Command: `python -B validation/history_benchmark.py --rows 256 --samples 3`. Each sample uses a fresh private local SQLite file; two aggregate synthetic reports with256 observations each, every state changes open→closed, comparison must yield exactly256 changes. No packets or real scan findings. Batches16, synchronousFULL/fullfsync, current history bounds.

Hardware: Apple M4, 10 logical CPUs, 16 GiB RAM; macOS-27.0.1-arm64-arm-64bit-Mach-O / arm64. Python3.14.3, SQLite3.52.0. Runtime SHA256 `1e9e1d186438e6a69b917c853982f6a63ca2ec45a38151c264bdd6bafedb73a6`. Source8940b35 was committed; dirty flag reflects only pending documentation/checkpoint edits. Later changes improve offline build validation, platform-tool audit coverage and documentation; they do not alter this measured Python runtime and do not justify remeasurement.

| Sample | Save two scans (s) | Compare (s) | Save observations/s | CPU save+compare (s) | Main DB bytes |
| --- | --- | --- | --- | --- | --- |
| 1 | 0.615948 | 0.020131 | 831.24 | 0.098813 | 450560 |
| 2 | 0.639020 | 0.025712 | 801.23 | 0.132673 | 450560 |
| 3 | 0.650049 | 0.021584 | 787.63 | 0.131231 | 450560 |

Median saved observations/s: **801.23**. Whole-process peak RSS: **33456128 bytes**; includes retained synthetic aggregate fixtures and interpreter overhead, not evidence of streaming memory savings. CPU covers save+compare; timing includes durable commits, excludes initial database creation. Filesystem/cache/hardware affect results. This measures SQLite storage, not network throughput or speed parity.

## Packet accuracy, loss and earlier performance

Packet construction/transport/scheduling/resume behavior is unchanged by the candidate; the Rust addition is test-only. Existing isolated Linux Phase2 ground truth28 cases/28 independent capture checks/two privileged loopback tests, native SYN25 checks, continuation33 checks and Phase5B15 OS checks remain documented in their exact-source reports. Latest Phase5B OS capture observed0 kernel drops; this is a local sample, not a packet-loss guarantee. No new privileged lab was justified for packaging/validation/docs.

Native connect/stream batching throughput/CPU/RSS measurements remain tied to source66123724901cf85848a433bb2795b992c4a46ebd in CONTINUATION_RESULTS.md; no rerun or speed claim for the later documentation/metadata/storage candidate. This candidate does not establish high-rate SYN accuracy, general OS recognition or Nmap/Masscan parity.

## Incomplete acceptance and privacy

- Project LICENSE absent; owner decision requested, no invented license. Optional Scapy GPL-2.0-only and locked Rust license inventory reviewed in docs/DEPENDENCY_LICENSES.md. Public distribution/license compliance still pending.
- `sudo -n true` failed locally: privileged macOS/BPF validation unavailable. LinuxVM evidence does not substitute. Broader network/OS/TLS interoperability remains unverified as earlier docs state.
- Historical privacy cleanup remains owner-pending. Full reachable-history secret scans remain enforced; scheduled historical privacy inventory is distinct from new-change gates. No history rewrite, new broad allowlist, credential revocation or public release performed.
- Current candidate push/PR status is maintained in PR #17. Do not infer supported privileged macOS operation from unprivileged CI. No merge, license addition or publication is authorized now; no raw logs, histories, local install artifacts or captures are published.
