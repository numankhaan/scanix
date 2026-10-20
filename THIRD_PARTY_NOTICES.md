# License scope and third-party notices

Scanix's original project code is licensed under **GPL-2.0-only**, at the repository
owner's instruction following the recorded provenance review. The complete unmodified
text is in LICENSE and native/LICENSE. This is not an or-later grant. Copyright
remains with the respective rights holders; no holder/year has been invented from
Git author metadata. Existing third-party notices are preserved verbatim.

The original probe and OS data files retain **CC0-1.0** (third_party/licenses/CC0-1.0.txt).
They are not relicensed as GPL. Consequently the Python distribution metadata uses
`GPL-2.0-only AND CC0-1.0`; the native project crate uses `GPL-2.0-only` for its own code.
No Scapy, interpreter, OpenSSL or native executable is embedded in the Python wheel.
License documents included for reference do not relicense their upstream projects.

## Optional Python dependency and interpreter

Scapy2.8.0 retains GPL-2.0-only. Its [published tagged LICENSE](https://github.com/secdev/scapy/blob/v2.8.0/LICENSE)
contains the GPLv2 text. It is installed separately by the raw extra/requirements;
redistributing Scapy requires preserving its own complete notices and corresponding
source. This file does not replace the notices in the Scapy source distribution.
Legacy terminal helpers optionally import Colorama if installed, with a standard-library
fallback when absent. Reviewed Colorama0.4.6 is BSD-3-Clause; its complete authentic
notice is included, and its package code is not bundled.
Python3.10–3.14's [PSF licensing](https://docs.python.org/3.14/license.html) and licenses
of incorporated components remain unchanged; no interpreter is redistributed here.

The reviewed local TLS runtime is OpenSSL3.6.1, Apache-2.0 according to the
[OpenSSL license policy](https://openssl-library.org/source/license/). Apache-2.0 is
[not GPLv2-compatible](https://www.apache.org/licenses/GPL-compatibility.html).
Current source/wheel artifacts do not bundle Python/OpenSSL, and the native engine
does not link OpenSSL. **Frozen executables, containers/installers bundling a Python/
OpenSSL runtime, or other combined runtime distributions are not cleared by this
review.** Resolve applicable system-library/combination permissions before distributing
such bundles; no OpenSSL exception or third-party relicensing is granted here.

## Native dependencies and runtime

All22 locked Cargo dependencies offer MIT terms; those alternatives are selected for
this distribution instead of Apache-2.0. `unicode-ident` additionally requires
Unicode-3.0. Full authentic notices are retained per crate under third_party/licenses;
third_party/licenses.json records exact versions, upstream declarations, selected
terms, primary crates.io archive checksums and notice hashes. These components retain
their licenses; they have not been relicensed as project code.

The pinned Rust1.91.1 standard library offers MIT/Apache alternatives with specific
BSD-2-Clause and Unicode-3.0 portions. Retain the supplied unmodified MIT, COPYRIGHT
and COPYRIGHT-library notices, and complete BSD/Unicode texts. The library notice
was collected from the actual installed1.91.1 toolchain; compiler/root notices were
verified against the [upstream1.91.1 source](https://github.com/rust-lang/rust/tree/1.91.1).
It covers that runtime, not an arbitrary future toolchain/target or bundled SDK.

When distributing a native binary, accompany it with LICENSE, this notice, the
third_party notice directory/manifest, matching build/interface sources and the
corresponding source arrangement described in docs/LICENSING.md. Do not ship a naked
binary and assume a repository URL automatically satisfies GPLv2 section3.

Build/audit tools are separate tools, not linked runtime components. Their licenses
remain as inventoried in docs/DEPENDENCY_LICENSES.md. Third-party logos/databases and
unreviewed copied code are not licensed by the Scanix grant. Review dependency,
toolchain, provenance and distribution changes before updating this inventory.
