# Changelog

## 1.0.0rc1

First consolidated Git release candidate. Package/CLI version: `1.0.0rc1`.
The separately built native engine remains `0.4.2` (wire protocol 3); these versions
describe different components and do not need to match. No package or GitHub Release
is published by creating the candidate tag.

- Bounded Python TCP connect, correlated SYN/UDP classification, IPv4/IPv6 target
  handling, exclusions, scope preview, discovery and cancellation/partial exports.
- Evidence-based service detection, TLS inspection, original versioned probe and
  fingerprint data, informational plugins and optional SQLite scan history.
- Opt-in Rust connect and Linux IPv4 SYN backends, versioned subprocess interface,
  paced scheduling, durable continuation and deterministic sharding.
- Isolated installation/reinstallation checks, deterministic malformed-input
  coverage, cross-platform regression CI and preserved privacy/security gates.
- GPL-2.0-only project code, independently licensed CC0 data, authentic third-party
  notices and documented corresponding-source obligations.

Python remains the default engine. Native binaries are built separately. Report
schema 5, history schema 1, checkpoint schema 1 and plugin API 1 are unchanged.
Implementation-bound checkpoints may require a fresh scan after an incompatible
upgrade; preserve existing private exports/backups. Same-candidate reinstall is
tested; an upgrade from a previously published wheel has not been tested.

Privileged macOS raw SYN/UDP/ICMP/ARP/ND remains **experimental and unverified**;
tested unprivileged macOS functionality is retained. Native SYN is Linux IPv4 only.
Remote OS evidence is experimental and limited to documented controlled profiles.
Frozen Python/OpenSSL bundles and combined installers/containers are not cleared
by the licensing review. Historical personal metadata/path exposure remains
unresolved; a new tag does not clean history. No parity or security guarantee.

See [candidate scope and installation](docs/RELEASE_CANDIDATE.md),
[licensing/source delivery](docs/LICENSING.md) and
[exact validation evidence](validation/RELEASE_RESULTS.md).
