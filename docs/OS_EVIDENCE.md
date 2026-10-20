# Experimental remote OS evidence (Phase 5B)

`--os-detect` collects evidence from a correlated **remote SYN/ACK** in Python SYN
mode. It does not inspect the scanner's own OS, local TTL, banners or service port
names. Existing port states remain independent; enrichment errors cannot close an
observed open port. No additional probes are sent, and successful probes retain the
existing paced reset cleanup. Python stays default; this mode needs the same raw
capture privileges/backend as Python SYN scanning.

```sh
python -m scanix scan -t 127.0.0.1 -p 8080 --syn --os-detect --preview
python -m scanix scan -t 127.0.0.1 -p 8080 --syn --os-detect --out json --out-file -
python -m scanix scan -t ::1 --family 6 -p 8080 --syn --os-detect --preview
```

Use owned listeners. Loopback and most arbitrary systems will be inconclusive:
the initial database is deliberately narrow. Connect, UDP and native OS detection
are explicitly rejected before traffic; they do not silently select another engine.
IPv6 remote headers can be collected, but no IPv6 fingerprint profile is supported.
Privileged macOS/BPF remains unvalidated. This is not general OS/version recognition
or a claim of parity with an established fingerprint database.

## Evidence and matching rules

Only replies with the selected addresses, reversed ports and expected SYN
acknowledgment can supply features; unrelated packets, ICMP quotations, RSTs and
silence cannot identify an OS. A maximum 60-byte TCP header supplies observed TTL /
hop limit, IPv4 DF, advertised window, header length, ordered option kinds, MSS,
window scale and SACK/timestamp presence. Malformed lengths/duplicate known options
produce no fingerprint evidence. TCP timestamp **values** (potential uptime clues)
and packet payloads are not retained. IP/TCP checksums are not independently
validated for OS inference; offload/capture and spoofing limitations still apply.

Original `scanix/data/os-fingerprints-v1.json`:schema1/database1.0.0, CC0-1.0 data,
feature format1, strict bounded validation with fixed exact-value comparisons and no
executable matchers. No third-party fingerprint database was copied. The one original
experimental profile was checked against a separate Linux peer namespace over a
MTU1500 veth with the existing SYN-without-options probe:

- Observed TTL64, IPv4 DF set, window64240, ordered option kinds `[2]`, MSS1460.
- **All five** signals must match; TTL alone always returns unknown, even for common
  TTL values. No hop-distance inference or fuzzy scoring is performed.
- A unique exact profile yields `experimental_match`, confidence `experimental`,
  candidate `Linux-compatible`, unknown version and unauthenticated evidence.
- Missing/unsupported evidence, unmatched or conflicting profiles yield
  `inconclusive`, confidence `insufficient`. Invalid local database yields `error`.
- The legacy `os` field stays null: this compatible packet pattern does not prove
  Linux. Other systems, middleboxes and deliberate emulation can share these signals.

The experimental system is the owned Linux namespace/veth configuration above, not
all Linux kernels or distributions. Changed MTU, socket tuning, firewalls, SYN proxies,
routing, packet normalization, loopback windows or different probe options can make
it inconclusive. Windows/macOS/BSD and exact OS/kernel versions are unsupported;
they are not inferred from different TTL values. The Linux
[sysctl documentation](https://docs.kernel.org/networking/ip-sysctl.html) describes
configurable network parameters; packet layout follows
[RFC9293](https://www.rfc-editor.org/rfc/rfc9293.html). These specifications do not
establish unique OS fingerprints.

## Output, compatibility and privacy

Schema5 uses extensible per-result `evidence.remote_tcp` and `evidence.os_detection`
plus `scope.os_detection` policy/database metadata; existing JSON/CSV/HTML exporters
serialize and escape these dictionaries. Terminal output names the experimental or
inconclusive status explicitly. `--preview` shows policy without capture or probes.
Cancellation retains completed rows and evidence; silence remains unknown port
state with inconclusive OS evidence. Service/plugin stages remain separate.

No native wire/stream format change. The native compatibility manifest now hashes
all bundled JSON databases, including the new fingerprint database, as well as
production Python/configuration. Upgrading changes checkpoint compatibility even
when using native scanning without OS detection; start a new checkpoint, preserve
old private exports, and do not silently migrate or widen scope.

Fingerprint evidence can identify infrastructure. Keep reports/captures/checkpoints
private; preventive artifact and privacy gates remain unchanged. Ignore rules do not
remove old tracked files or history. Historical cleanup still requires owner decision.

## Validation and maintenance

Synthetic fixtures test positive/negative signals, wrong probes, malformed/oversized
options, IPv6 inconclusiveness, conflicts, TTL-only refusal, port-state preservation,
exports, offline preview and checkpoint hashing. The optional isolated Linux lab
adds independent packet-capture correlation and compares extracted fields directly
with captured remote headers; see [recorded results](../validation/OS_RESULTS.md).
Regular CI requires no privileges or public network access. On an authorized Linux
lab host with iproute2/iptables/tcpdump/Scapy installed, execute:

```sh
sudo -- "$(command -v python)" -B validation/privileged_lab.py --output <new-private-directory> --os-evidence
```

The lab refuses nonisolated setup and creates only namespace/veth targets. The
existing manually dispatched privileged workflow now includes this flag as well.
It does not upload raw evidence.

Add profiles only with original/licensed fixtures, explicit probe strategy and
controlled remote ground truth. Record topology, kernel/configuration limits,
positive and negative fixtures, collision/conflict behavior and a database-version
change. Do not broaden matching or label an untested system supported merely to
make a fixture pass. Do not commit real scan data or raw captures. Future native
packet evidence, more profiles and routed/MTU variants require separate validation.
