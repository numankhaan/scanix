# Project license options — decision pending

This comparison grants no license. No project LICENSE or package/native license
field has been added. PR #17 stays draft pending its remaining CI job and the
owner's licensing decision; no merge or publication is authorized now.

| Option | Main tradeoff | Scapy and native distribution |
| --- | --- | --- |
| MIT or BSD-2-Clause | Permissive reuse, including proprietary derivatives; retain required notices. Neither text has an express patent grant. | Does not override Scapy's GPL-2.0-only terms. A combined raw-enabled distribution needs GPL compatibility review. A genuinely independent native distribution could use permissive terms with crate notices. |
| Apache-2.0 | Permissive, with an express contributor patent grant/termination and redistribution/NOTICE requirements. | Apache documents incompatibility with GPLv2. Not a straightforward choice for a combined distribution using current Scapy. More plausible for an independent native component, after dependency review. |
| GPL-2.0-only or GPL-2.0-or-later | Copyleft on distributed covered works; binary distribution needs a compliant corresponding-source arrangement. | Evaluate GPLv2 for a Scapy-combined distribution. An or-later grant on owned Scanix code does not upgrade Scapy's GPL-2.0-only grant. Native dependency choices/notices still need review. |
| GPL-3.0-only | Modern copyleft with express patent and additional distribution requirements. | Does not supply GPLv2 permission for a combined work using GPL-2.0-only Scapy. Requires another permission or a reviewed independent distribution boundary; not a drop-in solution. |

Scapy 2.8.0 is GPL-2.0-only according to its installed distribution metadata; its
[upstream license](https://github.com/secdev/scapy/blob/v2.8.0/LICENSE) supplies the
GPLv2 terms. Raw Python paths import Scapy in the same interpreter. An optional
extra, separate download or absent bundling is not proof that a distributed
combination is independent. GPLv2 distinguishes independent works/aggregation from
covered combined works; the actual integration and distribution need review.

The Rust engine is a separate subprocess and has no Scapy dependency. That makes a
separate native license/distribution a candidate to assess, **not an automatic legal
exception**. Its binary incorporates crate code: retain applicable license texts
and notices, select permitted alternatives where a crate offers OR terms, and
review additional Unicode/LLVM-exception terms in the [locked inventory](DEPENDENCY_LICENSES.md).
Do not assume one permissive crate license covers the whole binary. The original
CC0 probe/OS data declarations do not determine the project code's license.

Decision guide: evaluate MIT/BSD for permissive reuse, GPLv2-compatible terms for a
copyleft distribution including the current raw integration, or a separately
licensed native component if that distribution boundary is established. Apache-2.0
and GPL-3.0-only introduce extra compatibility concerns with current Scapy. Confirm
rights to license existing contributions and the intended Python/raw/native
distribution before selecting terms. No option is selected here.

Primary sources: [MIT](https://opensource.org/license/mit),
[BSD-2-Clause](https://opensource.org/license/bsd-2-clause),
[Apache-2.0 sections 3–4](https://www.apache.org/licenses/LICENSE-2.0),
[Apache's GPL compatibility guidance](https://www.apache.org/licenses/GPL-compatibility.html),
[GPLv2 sections 2–3 and 9](https://opensource.org/license/gpl-2.0) and
[GPLv3](https://opensource.org/license/gpl-3.0). Boundary assessments above are
questions for distribution review, not a determination that Scanix is legally
independent of Scapy.
