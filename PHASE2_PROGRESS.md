# Phase 2 delivery and validation

The completed implementation at `3dbad9c` is now included in main through
[integration PR #7](https://github.com/numankhaan/scanix/pull/7), merge commit
`ad61a834210b79ac955e675fd1cbf9af0f57797b`. PR #4 originally merged Phase 1 into main;
PR #5 merged Phase 2 into Phase 1. Recovery reused that existing history with a
normal merge (`7427f70`) and no implementation changes or conflicts. Before the
progress updates, the recovery tree exactly matched the Phase 2 tree.
See [integration record](INTEGRATION_PROGRESS.md) for ancestry and validation.

The original worktree's unrelated `scanix/modules/udp_scan.py` edit is preserved
and excluded. Its prototype is separate from the committed Phase 2 implementation.
Integration merges follow reviewed diffs and passing CI; no required check is bypassed.

## Implemented

Packet construction/classification and privileged transport are separate. SYN and
UDP results require actual probe correlation; silence never opens a port. UDP uses
minimal DNS/NTP requests plus a generic fallback. ICMPv4/v6, reset cleanup, raw
retries, cancellation and local failures are covered by synthetic fixtures.
Targets support multiple inputs, DNS policies, bounded lazy CIDRs, exclusions,
files and offline preview. Discovery supports bounded TCP, echo, on-link ARP and
Ethernet IPv6 ND. Shared monotonic pacing, per-host limits and bounded RTT timing
apply to scan/discovery operations. Existing scan exporters preserve new evidence.
README and ROADMAP describe result semantics, compatibility and limitations.

## Validation record

- Phase 1 current local regression: Python 3.14.3, **36 passed**.
- Phase 2 current local regression: Python 3.14.3, Scapy 2.6.1 and 2.8.0,
  **82 run, 80 passed, two opt-in privileged tests skipped, no failures**.
- Native CI: Phase 1 run 39286464882 and Phase 2 run 39289431799 each passed
  all seven matrix jobs (Ubuntu Python 3.10–3.14; macOS/Windows Python 3.14).
- Original Windows failures: shared half-second refusal assertion and Phase 2's
  incomplete Linux backend mock. Diagnostics measured 10035 at 0.5 seconds and
  10061/refusal after about two seconds. Strict closed assertions remain; product
  result semantics are unchanged. Phase 2's fixture uses a fixed budget.
- Phase 1 repair `fb0277f` was merged normally into Phase 2 (`b0f0cde`);
  Phase 2-specific repair is `dccb8ba`. These repairs preserved history; later
  delivery and integration merges are recorded above.
- Separate optional privileged Linux run 39289424498 on `aa07fde`: **28/28 live
  cases, 28/28 pcap checks and 2/2 opt-in raw loopback tests passed**. Captures and
  topology retained in the linked artifact; hashes and expected/observed results
  are in [validation/RESULTS.md](validation/RESULTS.md).
- Ethernet pcap has 88 packets; loopback pcap has nine. Both report zero kernel
  drops. Downloaded packet evidence was rechecked offline locally.
- No public hosts/networks scanned. Regular CI remains unprivileged; the lab is
  a separate explicitly opted-in workflow. Generated evidence remains in Actions
  artifacts, not the source commits.
- Original source worktree's unrelated UDP prototype remains unchanged and
  uncommitted; SHA-256 `880894f38bc74007b1ad0d94609964f136667fe8be865e7466cb37535056893c`.

## Remaining validation and limitations

Privileged macOS/BPF validation is incomplete: local capture and passwordless sudo
are denied, and the installed Podman VM fails with `vfkit` SIGTRAP/exit 2. The
successful privileged result is from hosted Linux namespaces, not this Mac.
Broader protocol/backend interoperability is not established by the minimal lab peers. Windows raw methods intentionally fail
explicitly; portable connect remains covered. Scoped IPv6, extension headers and
reassembly, NAT correlation, rich protocol signatures and rate control over
kernel/backend-generated packets remain unsupported. See README and the linked
validation report for exact coverage and reproduction instructions.

New documentation-only pushes can start additional matrix runs; PR descriptions
carry the latest observed check state. Never interpret queued checks as passes.
