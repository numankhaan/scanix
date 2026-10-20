# Informational plugins (Phase 5A)

These are working, explicitly requested probes of **observed open** endpoints,
independent of port guesses and port-state classification. Python remains default.
No credentials, authentication, exploitation, redirects, crawling, remote executable
loading or arbitrary user-supplied plugin modules are supported. Plugins operate only
on the numeric address and selected port already observed by the scan. TCP results
never authorize a UDP probe or vice versa.

## Interface and coverage

```sh
python -m scanix scan -t 127.0.0.1 -p 8080 --plugins http --out json --out-file -
python -m scanix scan -t localhost -p 8443 --plugins tls --tls-insecure
python -m scanix scan -t 127.0.0.1 -p 2222 --plugins ssh
python -m scanix scan -t 127.0.0.1 -p 5353 --udp --plugins dns --preview
python -m scanix scan -t ::1 --family 6 -p 8080 --plugins http,tls --service-profile deep --preview
```

Use owned listeners; example ports do not imply an existing service. UDP port
classification still needs the existing privileged Python capture backend; plugin
DNS itself uses an ordinary connected UDP socket. Native UDP remains unsupported.
Preview does not start workers or send service traffic. `--banner` and
`--service-detect` retain their existing behavior; `--plugins` is separate opt-in.
Combining detection and plugins may repeat a bounded informational request.

| Stable plugin ID (alias) | Declared capabilities | Evidence and limitations |
| --- | --- | --- |
| `http.info.v1` (`http`) | connect, HTTP HEAD | Plain HTTP/1.x `HEAD /`, status and allowlisted Server/Content-Type/Allow headers; no cookies, bodies or redirect following |
| `tls.info.v1` (`tls`) | connect, TLS handshake | Direct TLS >=1.2, negotiated version/cipher/ALPN and bounded certificate metadata; no cipher enumeration or STARTTLS in this plugin |
| `ssh.info.v1` (`ssh`) | connect, passive greeting | Identification line/software hint only; sends no SSH authentication or application request |
| `dns.info.v1` (`dns`) | UDP connect, minimal DNS query | One RD=0 A query under `.invalid`, no EDNS/ANY/recursion; transaction/question validation reuses Phase 2 parser; no zone transfer or resolver enumeration |

The HTTP plugin does not automatically try HTTPS. Run TLS and/or existing
`--service-detect` for that purpose. A mismatched, truncated or unparseable response
stays unknown; failed enrichment never changes the observed open state. All evidence,
including product/version hints and certificate claims, is unauthenticated remote
information, not a vulnerability finding. TLS verification is required by default;
`--tls-ca-file` selects a CA bundle. `--tls-insecure` explicitly records verification
**disabled**, never valid. Original hostname associations supply SNI, IP-only targets
verify the IP without DNS SNI, and `--sni` overrides the verification name while the
connection remains on the selected address. Existing Phase 3 STARTTLS is separate.

## API, capabilities and execution bounds

Original trusted registry `scanix/plugins/registry.py` version **1.0.0**, API **1**,
fixed reviewed builtin dispatch; entries cannot execute code. Adding a builtin needs
a reviewed registry/code change and positive/negative fixtures, not an import path in
input. Capabilities are reviewable declarations, **not OS-enforced permissions**.
All shipped plugins are informational. A plugin declaring `intrusive=True` is rejected
unless `--allow-intrusive-plugins` is set; none is shipped. Printer/spooler exclusions
515 and 9100–9107 apply unless `--allow-excluded-probes` is explicit.

One trusted subprocess per plugin uses the same Python interpreter with isolated
imports and a fixed absolute worker path, no shell. It has the invoking OS user's
privileges: **this is not a security sandbox**, and there is no hard OS RSS quota.
Only bounded parser inputs and reviewed code run. Parent wall deadlines include
startup; cancellation kills/reaps active workers, and worker stderr is discarded.
Process creation itself can take OS-dependent time. See Python's
[subprocess contract](https://docs.python.org/3/library/subprocess.html).

Each plugin permits one connection, at most two application/TLS writes, 1024 sent
application bytes, 4096 received application bytes, and three paced operation tokens.
TLS protocol bytes/retransmits are managed by OpenSSL/kernel and are not application
byte/packet counts. Responses and IPC frames are capped (32768 bytes/frame, queue 2).
Parent validates API/registry, sequential token IDs, evidence shape/counters, exit
status and deadlines. Worker errors expose fixed categories, never raw stderr.

`--plugin-timeout` is 0.1–10 seconds, default 2; all plugins together have a per-endpoint
quick budget of 3 seconds or deep budget of 8 (`--service-profile`). At most four
unique builtins run per endpoint, sequentially, without retries. Worker count is the
minimum of `--service-workers` (default 4), scan concurrency and per-host limit.
Pending endpoint futures never exceed that count. Both engines share parent pacing
with enrichment: connection starts, application writes and TLS handshake starts each
consume a token. A conservative rate guard protects the native-to-Python transition.
No claim that tokens count every TCP/TLS packet. Default UDP pacing remains conservative.

## Results, continuation and privacy

Report schema **5** adds `plugin_results` per row and optional `plugin_api_version` /
`plugin_registry_version` metadata, consistently in JSON/CSV/HTML and NDJSON. Native
wire remains 3, checkpoint/stream formats remain 1; report schema and implementation
bytes participate in compatibility, so existing schema-4 checkpoints require a new
scan. There is no automatic incompatible migration. Consumers must recognize schema 5.

Plugin statuses: `complete` has protocol evidence; `unknown` had no matching evidence;
`excluded` records policy/transport/scope refusal; `error` is local/probe/worker failure;
`timeout` exhausted its budget; `interrupted` was cancelled. Error categories and
actual bounded counters are separate from port states. If a worker is killed before
reporting, counters are null (unknown), not invented zeros. Protocol evidence uses
existing qualitative confidence `protocol`; banner/product hints remain unauthenticated.

Native streaming durably upserts enrichment onto stable result IDs. Resume preserves
completed plugin outcomes and retries interrupted/missing plugins only; timeout,
unknown, exclusion and error are terminal outcomes for that checkpoint. A crash before
an enrichment commit may repeat that bounded informational probe. Completed port work
is not repeated. Native session time also bounds this separate stage. Port coverage
and per-plugin outcomes must both be inspected; complete port coverage does not imply
successful enrichment. Aggregate workflows continue to retain result rows.

HTML escapes evidence and terminal output sanitizes controls. No unlimited raw
responses, cookies, credentials or arbitrary headers are stored. Selected service and
certificate metadata can still identify infrastructure: keep all results/checkpoints
private and out of commits/artifacts. Existing preventive gates remain enabled.
No new dependency or synthetic key exception is introduced.

Tests use deterministic malformed worker fixtures and owned HTTP/TLS/SSH/DNS loopback
servers, existing synthetic CA/key fixtures, shared pacing, budgets, bounded workers,
cancellation, exports and actual native stream/resume. See checkpoint/PR for actual
counts and CI outcomes. Earlier SYN labs/benchmarks remain attributed to their measured
source; plugins have no throughput claim. Privileged macOS/BPF remains incomplete.
