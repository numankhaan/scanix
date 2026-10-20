# GPL-2.0-only licensing and corresponding source

The owner selected **GPL-2.0-only**, conditional on provenance/dependency review.
That grant applies to Scanix's original code, not an or-later version. LICENSE and
native/LICENSE contain the complete unmodified GPLv2 text. The appendix's sample
or-later notice is explanatory license text, not Scanix's grant. Existing CC0 data
and all third-party terms/copyright notices remain unchanged. No copyright holder
or year was inferred or invented from Git metadata.

## Provenance review and its limits

At reviewed source0f1aefa,121 commits were locally available across fetched refs.
GitHub returned110 main-history commits and114 PR-branch commits; all were associated
with the repository-owner account. The repository is not marked as a fork, and the
contributors endpoint reported one contributor/no other human contributor account.
All138 current source/config/doc introduction records mapped to those owner-associated
commits except the locally held documentation, whose identity matched a verified
owner-associated commit. The held commit changes eight Markdown files only and is
included without rewriting history. No tracked binary/document asset needed a separate
code grant; TLS keys/certificates are the documented original disposable fixtures.

Available attribution/history review found no unexplained third-party code provenance
requiring another grant. This is evidence from available Git/GitHub/source records,
not proof of originality, employment ownership or rights in inaccessible objects.
The owner's authorization supplies the project licensing decision; commit metadata
alone does not establish legal copyright title. Raw identity inventory remains private.
New external contributions must come with rights and compatible licensing; see
CONTRIBUTING.md. No historical identity cleanup or third-party relicensing occurred.

## Dependency compatibility and notice selection

- Scapy2.8.0 is GPL-2.0-only. Its published tagged license and installed metadata were
  checked; the current raw integration's GPL version aligns with the project grant.
- Optional legacy Colorama0.4.6 terminal cosmetics are BSD-3-Clause, with a fallback
  if absent. Its authentic published-wheel notice/checksum is retained; no package
  code is bundled. Production import inspection found only Scapy/Colorama beyond
  the standard library and project modules.
- Python's PSF terms are retained. The wheel is pure Python source plus the original
  CC0 registries; no interpreter, OpenSSL, Scapy code or native binary is bundled.
  Metadata uses `GPL-2.0-only AND CC0-1.0` to describe that mixed distribution accurately.
- All22 actual locked Cargo packages offer MIT. We selected MIT rather than incompatible
  Apache-only terms; `unicode-ident` also requires Unicode-3.0. Each complete selected
  license was checked against its primary published crate archive, with archive SHA256
  matching Cargo.lock; the cached file matched too. No crate's license was changed.
- Rust1.91.1's actual standard-library notice identifies MIT/Apache alternatives and
  BSD-2-Clause/Unicode portions. The reviewed MIT choice and additional notices/texts
  are retained. This is not clearance for arbitrary future toolchains, targets or SDKs.
- Build/audit tools execute separately and are not linked into Scanix. Their licenses
  are inventoried separately. No material conflict was found in code bundled in the
  current source/wheel/native forms under the selected terms.

There is a material **runtime-bundling constraint**: the inspected Python TLS runtime
uses OpenSSL3.6.1, whose Apache-2.0 terms are not GPLv2-compatible. Current artifacts
do not embed that runtime and the Rust engine does not link OpenSSL. This review
**does not clear frozen executables, Python/OpenSSL bundles or containers/installers
redistributing that combination**. Assess applicable system-library/combination
permissions first; do not infer an exception from optional installation, separate
downloads or subprocess separation. No exception on behalf of Scapy or another
copyright holder is granted. See THIRD_PARTY_NOTICES.md and primary references below.

## Python builds and source delivery

From a reviewed checkout, install pinned `validation/requirements.txt`, then:

```sh
python -B validation/licensing.py
python -m build --no-isolation --outdir private/dist
python -B validation/package_smoke.py
```

Build creates an sdist and a wheel from it without an implicit backend download.
The package test checks exact license-file bytes/License-Expression, runtime members,
private artifact exclusions, source/build/license files, installed CLI/registries,
owned loopback/plugin/history and reinstall behavior. No upload occurs. The sdist
includes pyproject/MANIFEST, runtime source/data, validation build scripts/tool pins,
native sources/lockfile and notices. Tests/disposable keys are excluded; use the
reviewed repository for its full regression suite. No generated artifacts belong in Git.

If a wheel or other covered binary/object form is distributed, arrange complete
corresponding source under GPLv2 section3, e.g. accompany it with the matching sdist
and necessary build/interface scripts/dependencies. Do not assume a bare repository
URL or an inaccessible future source promise satisfies the license. Preserve notices,
identify changes under section2, and do not impose additional restrictions.

## Native builds and source delivery

```sh
cargo +1.91.1 build --release --locked --manifest-path native/Cargo.toml
python -B validation/licensing.py --cached
```

Use `.exe` on Windows. `--cached` checks the actual resolved graph and primary archive
license bytes offline; native CI runs it after the locked build. The native crate
metadata is GPL-2.0-only and includes its own complete LICENSE. No engine fallback or
runtime feature changed as part of licensing.

For redistribution, include LICENSE, THIRD_PARTY_NOTICES.md, the complete third_party
notice directory/manifest and matching Rust source/interface/build files. Supply
complete corresponding source through a valid GPLv2 section3 arrangement. To prepare
an offline build source directory, copy native/{Cargo.toml,Cargo.lock,LICENSE,src},
root notices/third_party and docs/NATIVE_ENGINE.md to a private source directory.
From that directory run `cargo vendor --locked --versioned-dirs vendor` and save its
configuration to `.cargo/config.toml` (create `.cargo` first; ensure the directory
entry is relocatable `vendor`). Verify `cargo +1.91.1 build --release --frozen` there.
Vendor output contains upstream sources/notices and must stay outside this repository.
Include any required runtime/dependency sources and scripts; evaluate the compiler/
OS system-library exception for the actual distribution, not as a blanket exclusion.

A target/toolchain change requires refreshing its authentic runtime/SDK notices;
if those are absent or cannot be verified, do not distribute a naked binary. No
package, release, container, source bundle or native binary is publicly published
by this work. Publication still needs separate authorization.

## Maintenance and primary sources

`third_party/licenses.json` binds versions, declared/selected terms, Cargo.lock and
notice hashes. Default validation rejects missing/tampered text, changed metadata
or an unreviewed lockfile; cached validation compares published crate bytes. Hashes
are integrity/freshness checks, not independent proof of legal compatibility. Review
source provenance, license changes and corresponding-source scope on updates. Git
attributes preserve notice bytes and checksum-bound policy files across Windows
checkouts. Two exact upstream files retain their original trailing whitespace, with
Git whitespace diagnostics adjusted only for those files; security scanners still
inspect all their bytes. No
secret/privacy exception was needed for these authentic public notices.

References: [GPLv2 sections2–3](https://opensource.org/license/gpl-2.0),
[Scapy tag license](https://github.com/secdev/scapy/blob/v2.8.0/LICENSE),
[Python license](https://docs.python.org/3.14/license.html),
[OpenSSL license](https://openssl-library.org/source/license/),
[Apache/GPL compatibility](https://www.apache.org/licenses/GPL-compatibility.html),
[Rust licensing](https://rust-lang.org/policies/licenses/),
[Rust1.91.1 notices](https://github.com/rust-lang/rust/tree/1.91.1),
[Unicode-3.0](https://spdx.org/licenses/Unicode-3.0.html),
[Cargo metadata](https://doc.rust-lang.org/cargo/commands/cargo-metadata.html) and
[Python license metadata](https://packaging.python.org/en/latest/specifications/license-expression/).
