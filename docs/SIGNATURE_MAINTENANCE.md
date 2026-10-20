# Maintaining original signatures and fingerprints

Keep service identity separate from port-state evidence. Port names remain guesses;
unauthenticated product/version strings are not vulnerabilities. Confidence is a
rule-based evidence category, never a numeric probability. Unknown values stay null.

## Service probes and signatures

1. Start with an owned isolated server or original synthetic bytes. Do not contribute
real banners, private hostnames, captures, credentials or identifying metadata. Record
the protocol specification and fixture provenance, not raw private traffic.
2. Edit `scanix/data/probes-v1.json` with stable probe/signature IDs. Declare protocol,
transport, payload strategy, parser ID, response limit, matchers, bounded fallbacks and
sensitive-port exclusions. Existing schema/parser/strategy IDs are validated; entries
cannot choose arbitrary code or executable imports. Complex parsing belongs in code.
3. Bump the database version for semantic changes. Schema changes need an explicit
compatibility plan; never reuse an ID for a different meaning. Preserve privacy and
size budgets. The finite regex subset intentionally rejects wildcard/backtracking
constructs; do not replace it with an unrestricted regex engine.
4. Add original positive and negative fixtures for every signature to
`scanix/tests/fixtures/signatures-v1.json` or the wire-signature tests. Cover malformed,
truncated, oversized, ambiguous, mismatched transaction and plaintext/TLS cases.
5. Run `python -B -m unittest scanix.tests.test_service_parsers scanix.tests.test_service_engine`
and `python -B validation/parser_corpus.py --cases 128`. The mutation corpus is finite
smoke coverage, not continuous or coverage-guided fuzzing. Add any minimized failure
as a synthetic deterministic regression before changing the parser.
6. Review emitted evidence, selected headers, terminal/HTML/CSV escaping, scope,
SNI/certificate semantics, rate grants, exclusions and elapsed/byte budgets. Keep a
failed enrichment from changing the observed port state. Run local outgoing gates
and require final-head platform/security CI before merging.

## OS evidence

`scanix/data/os-fingerprints-v1.json` is a separate original CC0-1.0 experimental
registry. Change code validation/version constants and fixtures together. A new
profile requires actual correlated remote packet evidence and independent isolated
capture validation, multiple distinguishing signals and documented limitations.
Never derive a reliable OS from TTL alone or describe local-host data as remote
identification. Missing/conflicting evidence stays inconclusive. Current coverage is
one constrained Linux-compatible IPv4 profile, not general OS/version identification.

## Licensing and compatibility

Do not copy Nmap, p0f or other signature databases without reviewing their license
and obtaining any necessary permission. Original fixtures and database provenance
must be reviewable. Project license selection remains owner-pending; see
DEPENDENCY_LICENSES.md. Add only narrowly justified synthetic-key exceptions; no
fixture-directory allowlist. Database/code changes invalidate exact native checkpoint
implementation fingerprints, so preserve exports and start a fresh incompatible scan.
History records version provenance but does not migrate unknown schemas silently.
