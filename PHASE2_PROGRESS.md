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

- Phase 1 before committing: Python 3.14.3, **35 tests passed**.
- Phase 2: Python 3.14.3, Scapy 2.8.0, `python -B -m unittest discover -s scanix/tests -v`:
  **73 tests run; 71 passed, 2 optional privileged tests skipped; no failures**.
- Retained/adapted Phase 1 tests run as part of the Phase 2 suite. Unsupported UDP
  tests were deliberately replaced by working-UDP routing/invalid-method tests.
- Unprivileged TCP connect and TCP discovery exercised on loopback without Scapy.
- SYN on loopback with Scapy but no BPF permissions: exit 1, failed report,
  0/1 completed results, explicit `/dev/bpf0` permission error; no probes sent.
- `scan --help`, `discover --help`, offline previews and CLI argument examples
  checked against the actual parser. Privileged examples are syntax-verified only.
- No public hosts/networks scanned. No privileged integration tests run locally.
- GitHub Actions currently queued/pending; this is not a CI pass. PR descriptions
  carry the latest observed status because queues can change after this file.

## Remaining validation and limitations

No requested feature is intentionally deferred. Live raw accuracy remains
unverified in this environment: run the optional loopback tests with capture
privileges, then isolated Linux/macOS ARP/ND and DNS/NTP lab checks. Windows raw
scans/discovery intentionally fail explicitly; connect remains portable.
Scoped IPv6, extension headers/reassembly, NAT translation, rich protocol discovery
and rate control over kernel/backend-generated packets are unsupported and
documented. Default offline preview cannot resolve hostname scope; it reports
that uncertainty, with DNS permitted only by explicit `--resolve-preview`.

Before merging, review the final Actions results and any platform-specific
failures. The source worktree must continue to retain its unrelated UDP edit.
