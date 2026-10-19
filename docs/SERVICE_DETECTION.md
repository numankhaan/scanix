# Phase 3 service detection

`--service-detect` opts into enrichment **after** port scanning, for `open` rows
only. `unknown`, `filtered` and `open|filtered` are not treated as open. Detection
has separate observations and failures; it never changes the observed port state.
Version strings are unauthenticated claims, not vulnerabilities. Unknown product,
version and certificate values stay null or absent.

## Use and compatibility

Start an authorized local HTTP endpoint, then scan its selected port:

```sh
python -m http.server 8080 --bind 127.0.0.1
# In another terminal:
python -m scanix scan -t 127.0.0.1 -p 8080 --service-detect --out json --out-file -
python -m scanix scan -t 127.0.0.1 -p 8080 --service-detect --service-profile deep --out html --out-file services.html
python -m scanix scan -t 127.0.0.1 -p 8443 --service-detect --tls-ca-file lab-ca.pem --sni lab.scanix.invalid
python -m scanix scan -t 127.0.0.1 -p 8443 --service-detect --tls-insecure
python -m scanix scan -t 127.0.0.1 -p 2525 --service-detect --service-profile deep --starttls
python -m scanix scan -t ::1 --family 6 -p 8443 --service-detect --preview
python -m scanix scan -t 127.0.0.1 -p 9100 --service-detect --allow-excluded-probes --preview
```

TLS examples require a lab listener and the matching CA file where specified.
All options above are checked against actual CLI help; the loopback validation
driver executes plaintext, verified TLS/SNI, rejection and insecure inspection.
`--preview` shows the database version, profile, budgets, TLS policy, SNI,
upgrade policy and exclusions **without** opening service connections or resolving
hostnames. Existing target exclusions apply before scanning and enrichment.

`--banner` remains the legacy, separately paced, at-most-2048-byte plaintext banner
operation for connect scans. It supplies raw evidence, not protocol confirmation;
it cannot be combined with `--service-detect`. Other service options only take
effect with `--service-detect`. SYN mode still classifies using raw packets;
explicit service detection can subsequently open ordinary TCP connections to open
ports. UDP detection uses UDP; it does not replace the raw port-state scan.
No new production dependency is required: service detection uses the standard library.

## Evidence and report schema

Report schema **3** retains the Phase 2 fields and adds top-level
`probe_database_version` (null when enrichment is disabled) and per-result
`service_detection` (null for unenriched/non-open results). CSV has the same new
metadata column and a JSON cell for nested detection; HTML renders escaped nested
evidence through the existing atomic exporters. Consumers that require schema 2
must accept the new version/columns. Discovery's separate JSON envelope is unchanged.

`service_name` with `detection_source: port_table` remains a **port guess**, even
when it contradicts observed evidence. Use `service_detection.observations` for
observed services, including those found on unusual ports. Each observation has
service, optional product/version, transport (`tcp`, `tls`, `udp`), detection
method, stable probe/signature IDs, confidence and bounded parsed evidence.
`authenticated: false` applies to application identity/version claims, including
those obtained over verified TLS. Certificate verification is reported separately.

Confidence is an evidence category, not a probability:

| Level | Required evidence |
| --- | --- |
| `banner` | Framed, self-identifying FTP/SMTP/POP3/IMAP greeting. POP3/IMAP positive greetings can be imitated and remain provisional. A generic `220` establishes neither SMTP nor FTP. |
| `protocol` | Parsed HTTP response, SSH identification, correlated DNS/NTP response, completed TLS handshake, or valid response to the selected capability command. Product/version hints are still unauthenticated. |

Observations are retained in order: a greeting, protocol confirmation and a
post-upgrade confirmation can coexist. Their transport and evidence describe the
specific observation; pre-TLS capability evidence is not reused as post-TLS evidence.
No raw response bodies, cookies, authentication headers or full certificates are
exported. HTTP retains only status, Server, Content-Type and Allow. Unknown services
remain unknown, even if their port has a familiar name. Enrichment status is
`identified`, `unknown`, `excluded`, `error`, `interrupted` or `not_attempted`;
per-attempt errors/refusals are also retained in `issues`. `identified` can coexist
with a failed upgrade or failed earlier probe. It does not assert every probe passed.
Scan completion still measures port coverage; inspect enrichment status/issues
for enrichment coverage. Cancellation marks the scan interrupted and saves completed
evidence and original open rows, with unstarted enrichment explicitly `not_attempted`.

## Exact initial protocol coverage

| Protocol | Evidence and traffic |
| --- | --- |
| HTTP | HTTP/1.0 or 1.1 status and complete header block. One `HEAD /`, no crawling, redirects, HTTP/2, body download or authentication. |
| TLS / HTTPS | TLS handshake metadata; HTTP is identified separately only if its response parses over TLS. A TLS handshake alone identifies TLS, not HTTPS. |
| SSH | Bounded, terminated SSH 1.5/1.99/2.0 identification string (including up to three preliminary lines). No key exchange or authentication. Original OpenSSH software/version hint. |
| FTP | Single-line FTP-identifying 220 greeting; deep profile sends FEAT. An ambiguous 220 is tested with EHLO, then FEAT in deep mode if EHLO fails. Original vsFTPd hint. No login, transfer or FTP TLS upgrade. |
| SMTP | ESMTP greeting or valid EHLO response; EHLO in deep mode, when disambiguating 220, or with `--starttls`. Optional advertised STARTTLS. Original Postfix hint, no authentication or message delivery. |
| POP3 | +OK greeting is provisional; deep/upgrade mode confirms CAPA response. Optional advertised STLS. Original Dovecot greeting hint; no login or mailbox access. |
| IMAP | OK/PREAUTH greeting is provisional; deep/upgrade mode confirms tagged CAPABILITY response. Optional advertised STARTTLS. Original Dovecot hint; no login or mailbox access. |
| DNS | Reuses Phase 2 matched DNS evidence with zero extra traffic. Otherwise sends one minimal nonrecursive A question for scanix.invalid, validating transaction ID, opcode and question. |
| NTP | Reuses Phase 2 matched NTP evidence with zero extra traffic. Deep UDP fallback sends one 48-byte mode-3 client request and validates server mode/version/originate timestamp. No control/monlist requests. |

All parsers are conservative. Binary greetings, unusual/multiline FTP greetings,
non-ASCII text, malformed/truncated lines, unsupported versions and excessive
headers may remain unknown. DNS question matching deliberately excludes compressed
question variants. Generic UDP endpoint-only matches do not establish a service;
DNS/NTP fallback must provide transaction evidence. NTP versions/stratum are not
product-version claims. No protocol is supported solely because its port has a name.

## TLS policy

The default is a verified TLS handshake using system trust roots or the explicit
`--tls-ca-file` bundle, including hostname/IP checks and validity dates. A verification
failure is recorded separately from handshake success and stops TLS fallback; there
is no automatic insecure retry. Trust-loading errors are explicit enrichment errors.
`--tls-insecure` is an explicit lab inspection mode: verification is **disabled**,
never reported valid. It is mutually exclusive with `--tls-ca-file`.

The first original hostname associated with the selected address supplies SNI,
HTTP Host and the verification name. Hostnames are never re-resolved by enrichment.
If the address has multiple aliases, this deterministic first-hostname policy does
not enumerate virtual hosts. IP-only targets send no DNS SNI and check certificate
IP SANs by default. `--sni` overrides the handshake/verification name and HTTP Host,
**not** the selected numeric connection destination. Certificate names, HTTP redirects
and response addresses never expand scan scope.

Successful handshakes record negotiated TLS version, cipher, ALPN and bounded
certificate metadata: SHA-256 fingerprint and DER byte count, plus subject, issuer,
serial, validity and SAN fields where Python exposes them. In insecure mode the
stdlib exposes the DER certificate but no parsed metadata; only fingerprint/size
are retained. There is no certificate-chain export, revocation checking, exhaustive
cipher enumeration or guarantee of identity beyond the configured trust policy.
ALPN offers only HTTP/1.1; HTTP/2-only endpoints can remain TLS-only.

`--starttls` upgrades only after a parsed capability response advertises the method.
A refusal is recorded; a failed accepted upgrade ends that connection without a
plaintext retry or fallback connection. After successful TLS, capabilities are
requested again. SMTP follows [RFC 3207](https://www.rfc-editor.org/rfc/rfc3207.html);
POP3/IMAP use [RFC 2595](https://www.rfc-editor.org/rfc/rfc2595.html).
TLS metadata/verification follows [Python ssl](https://docs.python.org/3/library/ssl.html).

## Registry and resource bounds

`scanix/data/probes-v1.json` is schema **1**, database **1.0.0**, an original small
CC0-1.0 registry. No Nmap signature/database material is included. It defines stable
IDs, protocols, transports, allowlisted payload strategies and parser IDs, response
limits, matchers, fallback IDs and sensitivity exclusions. Complex parsing remains
in code; JSON cannot import, evaluate or execute code. Fallback traversal is cycle-safe
and bounded. The file is limited to 64 KiB, each collection to 64 entries, and each
probe response to at most 16 KiB. Text product matchers use an anchored finite regex
subset (no wildcard, unbounded/nested repetition, lookaround, alternation or backrefs),
with fields limited to 256 characters. Every current signature has original positive
and negative fixtures, including transaction/handshake tests for wire signatures.

| Per-open-endpoint ceiling | Quick (default) | Deep |
| --- | --- | --- |
| Connections | 3 | 5 |
| Application writes + TLS handshake starts | 6 | 12 |
| Application bytes received | 8,192 | 16,384 |
| Application bytes sent | 2,048 | 4,096 |
| Total elapsed time including pacing | 3 s | 8 s |
| Per-operation timeout | 0.7 s | 1.5 s |
| Passive greeting wait | 0.2 s | 0.4 s |

TCP tries a passive greeting, TLS, then HTTP, prioritizing TLS on registry TLS hint
ports. Identity always requires a response, not the hint. TLS and HTTP fallback
relationships come from the registry; no endless retry cycle is possible. Profiles
are ceilings: valid evidence stops further fallbacks, and deep need not consume all
five connections. Deep adds capability commands and NTP fallback. TLS protocols
with unsolicited greetings are parsed before attempting HTTP over the secured stream.

`--service-timeout` changes the per-endpoint total budget (0.1–30 seconds). Low global
rates may exhaust that budget before every fallback runs. No hidden retry or
unpaced second attempt occurs. `--service-workers` defaults to 4, maximum 64,
further bounded by scan concurrency and per-host limits. Pending futures never
exceed that bound. Hosts retain Phase 2's lazy serial scheduling. Read/write/connect
and TLS waits poll cancellation and use absolute monotonic deadlines; a slow service
cannot block all endpoints beyond their budgets. OS trust/backend setup is outside
strict interrupt guarantees, as are existing system DNS resolution and raw I/O setup.

Enrichment shares the existing global limiter. A connection start, application
write and TLS handshake start each consume a token. For connect scans this remains
an application-operation limit, not a wire packet limit: TCP/TLS retransmissions,
ACKs and handshake records are controlled by the OS/OpenSSL. On raw scans the same
limiter also paces raw packets; opt-in enrichment adds these explicitly reported
application-operation tokens. Application byte counters exclude encrypted handshake
and certificate records; those are parsed by the TLS backend, under its protocol
limits and the same handshake deadline. Service attempts do not train scan RTT
estimates or inherit raw retransmission behavior.

Ports **515 and 9100–9107** are excluded from all service probing, including passive
connections, to avoid printer/spooler side effects. `--allow-excluded-probes` is the
explicit override. It does not bypass target exclusions. Other services can still
react to probes; this is a small targeted detector, not a comprehensive protocol or
security audit. Completed observations are evidence, not authenticated product facts.

See [validation results](../validation/SERVICE_RESULTS.md) and the retained optional
[privileged Phase 2 lab](../validation/README.md). No public hosts or elevated privileges
are required by regular CI or the service lab.
