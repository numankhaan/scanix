# Phase 3 service validation

Recorded 2026-10-19. All targets were synthetic or loopback; no public hosts were
scanned. Service identification requires no elevated privileges.

## Local regression coverage

macOS 27.0.1 arm64, Python 3.14.3, implementation head `6770228`:

```sh
python -B -m unittest discover -s scanix/tests -q
```

**112 run, 110 passed, 2 skipped**, independently with Scapy 2.8.0 (8.588 s) and
minimum supported Scapy 2.6.1 (8.612 s). The two skips are the existing optional
privileged raw loopback tests. No Phase 1/2 test assertions or Windows coverage
were weakened. Cases include all registry signatures' positive/negative examples,
nonstandard ports, ambiguous/truncated/malformed/oversized input, fragmented SSH
and SMTP, TLS/plaintext mismatches, all three TLS-upgrade protocols, IPv6 TLS/IP
SANs, UDP DNS/NTP fallback, profile limits, pacing/deadlines, bounded workers,
cancellation/partial exports, exclusions and output escaping.

TLS tests cover the trusted test CA, explicit SNI, numeric targets without SNI,
self-signed rejection/explicit inspection, hostname mismatch and expired leaf,
ALPN/cipher/version metadata, TLS-only service detection, plus successful/refused/
failed SMTP STARTTLS, POP3 STLS and IMAP STARTTLS. Failed upgrades have no later
plaintext retry. The TEST ONLY keys are intentionally public fixtures, not production
credentials. Rebuilding four PEMs with the fixture generator was byte-identical;
regular tests do not require the generator's cryptography dependency.

The failure-path follow-up ran **113 tests, 111 passed, 2 privileged skips**
with Python 3.14.3 / Scapy 2.8.0 (9.074 s). The additional regression proves that
a reset during a capability or post-TLS application probe preserves existing service
evidence and cannot trigger a new plaintext fallback connection. The 112-test
results above remain the recorded minimum-Scapy and earlier CI revision outcomes.

The registry-read follow-up ran **114 tests, 112 passed, 2 privileged skips**
with each of Scapy 2.8.0 and 2.6.1 (9.058 / 9.101 s). Its additional regression
checks that oversized registry input is bounded during the read, before JSON parsing.

## Actual CLI loopback lab

```sh
python -B validation/service_lab.py --output /tmp/scanix-service-evidence.json
```

The driver starts three listeners on 127.0.0.1, runs the real CLI in subprocesses,
checks JSON outcomes, saves the full observed rows/commands when requested and
tears down the listeners. SNI changes only the TLS/HTTP name, not the numeric target.
Final local run used ephemeral TCP ports 61092 (HTTP), 61093 (trusted TLS), and
61094 (self-signed TLS). TLS advertises HTTP/1.1 ALPN. Client and servers share
loopback; no route changes, privileges, external DNS or public targets are involved.

| Case | Expected | Observed | Attempts / application writes + handshake starts |
| --- | --- | --- | --- |
| Plain HTTP, 61092 | open, HTTP over TCP | open; identified HTTP over TCP; prior TLS mismatch retained | 3 / 2 |
| Trusted HTTPS with lab.scanix.invalid SNI, 61093 | open; verified TLS; HTTP over TLS | open; TLS + HTTP/TLS; verified; matching SNI | 2 / 2 |
| Self-signed default policy, 61094 | open; verification failure; no insecure retry | open; service unknown; verification failed | 2 / 1 |
| Self-signed explicit --tls-insecure, 61094 | open; HTTP/TLS; verification disabled | open; TLS + HTTP/TLS; verification disabled | 2 / 2 |

All four subprocesses exited 0 because port scanning completed; certificate failure
is enrichment evidence, not port failure. Elapsed enrichment times were respectively
0.238, 0.422, 0.218 and 0.422 seconds. This is application/TLS evidence, **not a new
packet-capture validation claim**. The script produces its JSON outside the repository.
The standalone driver is an additional manual check; regular CI runs the loopback
unit/integration cases in `scanix/tests`, not this manual command.

## GitHub CI

At implementation head `6770228`, [push run 39294199593](https://github.com/numankhaan/scanix/actions/runs/39294199593)
completed successfully, with logs inspected:

| Jobs | Outcome |
| --- | --- |
| Ubuntu Python 3.10, 3.11, 3.12, 3.13, 3.14 | Each 112 run, 110 passed, 2 privileged skips |
| macOS Python 3.14 | 112 run, 110 passed, 2 privileged skips |
| Windows Python 3.14 | 112 run, 109 passed, 3 skips |

Windows's third skip is the pre-existing POSIX subprocess SIGINT test. The new
cancellation and partial-export cases run on Windows. Earlier implementation
`3c33b79` also passed all seven jobs with 107 tests in
[run 39293637807](https://github.com/numankhaan/scanix/actions/runs/39293637807).
The subsequent 113-test revision cb594e1 also passed all seven jobs in both
[push run 39294803011](https://github.com/numankhaan/scanix/actions/runs/39294803011)
and [PR run 39294812664](https://github.com/numankhaan/scanix/actions/runs/39294812664):
each Linux/macOS job passed 111 with two skips; Windows passed 110 with three skips.
These are actual completed CI outcomes, separate from local runs. Checks on later
documentation commits and PR merge refs are tracked live on
[PR #6](https://github.com/numankhaan/scanix/pull/6); an earlier pass does not imply
a queued/in-progress check has passed.

## Retained privileged validation and limits

The optional Phase 2 Linux namespace driver/workflow is unchanged. Prior 28 live
SYN/UDP/ICMP/ARP/ND cases, 28 pcap checks and two privileged loopback tests are
recorded in [RESULTS.md](RESULTS.md), with topology, captures and hashes. Those
privileged checks were **not rerun for Phase 3**. Privileged macOS/BPF remains
unavailable and incomplete; no new local privileged pass or pcap is claimed.

This validates a small lab corpus, not broad vendor interoperability. Unsupported
protocol variants, HTTP/2, FTP TLS, virtual-host enumeration, certificate revocation,
full chain export and exhaustive cipher discovery remain outside this phase.
Insecure mode retains certificate fingerprint/size only; application byte counters
exclude TLS handshake records. See [exact supported behavior and budgets](../docs/SERVICE_DETECTION.md).
