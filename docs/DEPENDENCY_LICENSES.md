# Dependency and source license inventory

Local inventory at the Phase6 candidate. Project license selection is pending the owner; no project license is inferred from dependencies or the original CC0 data. Do not publish this candidate until resolved.

## Runtime and build boundary

- Python standard library follows its interpreter distribution license. No third-party dependency is needed for connect, TLS, plugins or local history.
- Optional Scapy2.8.0: GPL-2.0-only, verified installed distribution metadata and the [upstream tag license](https://github.com/secdev/scapy/blob/v2.8.0/LICENSE). The Python raw extra and test requirements pin this version. Review distribution/linking obligations when selecting the project license; do not assume a permissive project license overrides them.
- Rust dependencies are separately built into the opt-in native executable. Locked dependency metadata below includes platform-specific packages, not all of which link on every target. Retain applicable license texts/notices when distributing binaries.
- Original probe/OS JSON databases declare CC0-1.0; fixtures are original synthetic material. No Nmap or other third-party signature database is imported.
- Local packaging uses build1.6.1 and setuptools84.2.0 (MIT), packaging26.3 (Apache-2.0 OR BSD-2-Clause), pyproject_hooks1.3.3 (MIT), tomli2.5.0 (MIT) and colorama0.4.6 (BSD-3-Clause), installed/audited on every validation host even when the frontend does not need them. Pins are in validation/requirements.txt and covered by dependency audits/Dependabot. Transitive build requirements may still vary on older interpreter patch versions.

## Locked Rust inventory

Obtained with `cargo metadata --locked --offline --format-version 1 --manifest-path native/Cargo.toml`. Source URLs and expressions are supplied by upstream crate metadata; they are an inventory, not an automated compliance determination.

| Package | Version | Declared license |
| --- | --- | --- |
| errno | 0.3.14 | MIT OR Apache-2.0 |
| itoa | 1.0.18 | MIT OR Apache-2.0 |
| libc | 0.2.191 | MIT OR Apache-2.0 |
| memchr | 2.8.3 | Unlicense OR MIT |
| mio | 1.2.4 | MIT |
| pin-project-lite | 0.2.17 | Apache-2.0 OR MIT |
| proc-macro2 | 1.0.107 | MIT OR Apache-2.0 |
| quote | 1.0.47 | MIT OR Apache-2.0 |
| serde | 1.0.229 | MIT OR Apache-2.0 |
| serde_core | 1.0.229 | MIT OR Apache-2.0 |
| serde_derive | 1.0.229 | MIT OR Apache-2.0 |
| serde_json | 1.0.154 | MIT OR Apache-2.0 |
| signal-hook-registry | 1.4.8 | MIT OR Apache-2.0 |
| socket2 | 0.6.5 | MIT OR Apache-2.0 |
| syn | 3.0.9 | MIT OR Apache-2.0 |
| tokio | 1.54.0 | MIT |
| tokio-macros | 2.7.2 | MIT |
| unicode-ident | 1.0.27 | (MIT OR Apache-2.0) AND Unicode-3.0 |
| wasi | 0.11.1+wasi-snapshot-preview1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| windows-link | 0.2.1 | MIT OR Apache-2.0 |
| windows-sys | 0.61.2 | MIT OR Apache-2.0 |
| zmij | 1.0.23 | MIT |

The native project itself has no selected license yet. Toolchain, platform SDK and operating-system notices are additional distribution considerations. cargo-audit checks advisories, not license compliance. Review changed lockfiles, upstream license files and any new dependency before approving a release.

Primary references: [Cargo metadata](https://doc.rust-lang.org/cargo/commands/cargo-metadata.html), [Python package metadata](https://packaging.python.org/en/latest/guides/writing-pyproject-toml/) and [setuptools data files](https://setuptools.pypa.io/en/latest/userguide/datafiles.html).
