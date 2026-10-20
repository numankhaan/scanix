# Phase 6 release-candidate validation

Candidate: **1.0.0rc1**, matching the Python package and CLI. The native engine is
independently versioned at **0.4.2**, wire protocol **3**. See [changelog](../CHANGELOG.md).
The owner authorized an annotated `v1.0.0rc1` Git tag after readiness checks; package,
binary and GitHub Release publication remain unauthorized. Original code is GPL-2.0-only; original CC0 data and third-party terms are retained. Privileged
macOS raw/BPF operation is experimental and unverified, not a supported privileged
mode; tested unprivileged macOS functionality is retained. Passing checks do not guarantee security,
privacy, interoperability or scan accuracy on arbitrary networks.

## Installation and upgrade boundary

Source checkout commands in README remain supported. The new Python distribution
uses installed pinned setuptools84.2.0 without hidden backend downloads, declares Python3.10+ and installs the `scanix` entry point.
Connect/TLS/history/plugins use the standard library; optional `[raw]` pins Scapy2.8.0.
The wheel contains runtime Python and the two original JSON registries. Tests,
synthetic private keys/certificates, captures, caches and native binaries are excluded.
The source archive also includes native source/lockfile and documentation. No package
or public GitHub release is created by validation or CI.

```sh
python -m pip install -r validation/requirements.txt
python -B validation/package_smoke.py
python -B validation/parser_corpus.py --cases 128
# Local build only, into a chosen private directory; do not upload:
python -m build --no-isolation --outdir private/dist
# Install a locally built wheel (substitute its filename):
python -m pip install --no-index --no-deps private/dist/scanix-1.0.0rc1-py3-none-any.whl
scanix --version
```

The packaging smoke test builds the wheel from its sdist, verifies runtime membership,
installs into a fresh virtualenv outside the checkout, checks bundled registries,
IPv6 offline preview and an owned IPv4 HTTP/plugin/history scan. It reinstalls the
same candidate and verifies history preservation. There is no prior published wheel
for an actual cross-version package upgrade comparison. Python3.10–3.14 on Ubuntu
and Python3.14 on Windows/macOS execute packaging smoke in the regression matrix.
The optional native executable is built separately with locked Cargo dependencies;
its current version remains0.4.2/wire3. No silent engine fallback occurs.

Report5/history1/checkpoint1/native wire3/plugin API1 retain their format versions.
The package/CLI version now agrees. Existing exact native checkpoint compatibility
includes Python implementation contents: a changed candidate needs fresh continuation
files, not an unsafe compatibility bypass. History supports only the initial empty
migration; unknown/future layouts fail. Preserve private exports/backups before any
upgrade. No destructive migration or package/binary/GitHub Release publication occurs.

## Platform and privilege matrix

| Feature | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Python/native TCP connect IPv4/IPv6, TLS, plugins, exports | Regular CI | Regular CI | Regular CI |
| Optional SQLite history | Regular CI, SQLite3.31+ | Regular CI, SQLite3.31+ | Regular CI, SQLite3.31+, parent ACL |
| Python raw SYN/UDP, ICMP | Privileged isolated IPv4/IPv6 lab | Experimental, unverified privileged/BPF; no supported-operation claim | Explicitly unsupported |
| ARP/IPv6 ND | Directly connected isolated Ethernet lab | Experimental, unverified privileged/BPF/layer2 | Explicitly unsupported |
| Native SYN | Linux IPv4 isolated lab | Explicitly unsupported | Explicitly unsupported |
| Experimental OS evidence | Python SYN constrained Linux IPv4 profile | No validated remote profile/platform claim | No raw backend |

Scope exclusions/preview remain before traffic; ARP/ND reject routed networks.
Connect rate controls connection attempts; raw rates cover packets/retries/resets;
enrichment remains a separate bounded stage. DNS/system route lookup timing and
platform capture constraints remain documented limitations. No public targets are
used in regression or lab validation. Noninteractive local elevation remains
unavailable; Linux VM tests do not establish macOS/BPF behavior. This does not
demote the tested unprivileged macOS capabilities in the first two table rows or
TCP discovery/preview/continuation. No privileged macOS success is inferred from CI.

## Parser and maintenance coverage

Deterministic mutations cover framed HTTP/SSH/FTP/SMTP/POP3/IMAP, fake TLS bytes,
minimal correlated DNS/NTP, duplicate/nonfinite/deep native JSON, both versioned
registries, synthetic IPv4/IPv6 packets and TCP options, offline target parsing and
port ranges. Inputs and mutation budgets are bounded. Corpus output contains counts
and an outcome digest, never payloads. Native tests add checksum-repaired structured
endpoint/ACK mutations to the existing random-byte/truncation corpus. These tests
are not exhaustive or coverage-guided fuzzing and measure no branch-coverage percent.

See SIGNATURE_MAINTENANCE.md for provenance, original fixtures, positive/negative
coverage, version changes, evidence rules and contribution checks. Dependency/license
inventory is separate in DEPENDENCY_LICENSES.md; license scope/source obligations are documented in LICENSING.md.

## Validation record and release blockers

Actual local commands/results, source hashes and measurements are recorded in
validation/RELEASE_RESULTS.md. Existing packet evidence remains tied to its exact
measured source. Unchanged packet/scheduling code does not justify repeating labs;
documentation-only revisions do not justify repeating benchmarks. CI status belongs
to the exact final candidate head and is recorded separately from local tests.

PR #17 merged as `09b51052e395730ca264611efadbc1b6dcf2e324`: all eight final-head
and four post-merge core workflows passed. The owner selected GPL-2.0-only,
and the recorded scope/provenance/notice checks passed. Python/OpenSSL runtime
bundles remain outside the cleared distribution scope; see LICENSING.md.
The owner has narrowed macOS raw/BPF claims to experimental and unverified;
claiming supported privileged operation would require actual validation evidence.
Require current-base final-head regression/native/security/CodeQL success and resolve
reviews. Historical privacy cleanup remains independently owner-pending. Do not
rewrite history or silently accept historical findings. Package/release publication
requires separate authorization even after a candidate PR is accepted. Normal readiness/merge is authorized only after current-base final-head checks and
review acceptance; package/release publication remains unauthorized.
See [project-license comparison](PROJECT_LICENSE_OPTIONS.md); the current choice and compatibility scope are in LICENSING.md.
