# Phase 2 delivery and validation

Implementation is on `phase2/scanning-accuracy` in the isolated worktree
`/Users/nouman/Downloads/scanix-phase2`. It depends on unmerged Phase 1
(`phase1/tcp-connect-reliability`, PR #4), so its PR targets that branch.
The original worktree's unrelated `scanix/modules/udp_scan.py` edit is preserved
and was excluded from Phase 1 commits. Phase 2 replaces the committed placeholder
independently in its isolated worktree. Neither PR is to be merged automatically.

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
  Phase 2-specific repair is `dccb8ba`. No history rewrite or PR merge.
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
Neither PR is to be merged automatically.
