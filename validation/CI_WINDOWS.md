# Windows CI failure investigation

## Original failed runs

- [Phase 1: 39280962536](https://github.com/numankhaan/scanix/actions/runs/39280962536),
  Windows job 118154758656: one failure in `test_local_open_and_refused`;
  expected `closed`, observed `unknown`. 36 tests ran, one POSIX signal test skipped.
- [Phase 2: 39281188730](https://github.com/numankhaan/scanix/actions/runs/39281188730),
  Windows job 118155586351: the same assertion plus an `ImportError` in
  `test_linux_loopback_uses_ipv4_and_ipv6_raw_sockets`. 74 tests ran, three skipped.

The original failure logs do not contain a native socket code. The new diagnostic
records the native operation at the original 0.5-second deadline instead of
inferring the code from the assertion. In Phase 2 run 39286512391, Windows job
118174352669, the actual observations were:

| Operation | Native code | Elapsed | Result |
| --- | --- | --- | --- |
| Loopback refusal, timeout 0.5 s | 10035 | 0.5048742 s | operation still pending at deadline |
| Scan with fixed timeout 5 s | 10061 | 2.0055131 s | closed / connection_refused |

Thus the short-deadline result was correctly inconclusive; the integration fixture
incorrectly assumed that Windows must complete refusal inside half a second.
The assertion still requires `closed`, `connection_refused`, a real error code,
and the other report properties. It now provides a five-second native-operation
budget. Product classification is unchanged; timeout/in-progress is never rewritten
to closed. Phase 2 additionally disables RTT adaptation **in this fixed-budget
integration fixture** so the open port's fast RTT cannot shrink the refusal budget.
Adaptive timeout bounds retain their deterministic tests.

The Phase 2 backend test mocked only one Scapy class at a time, but the Linux
transport imports `L3RawSocket` and `L3RawSocket6` together. Scapy does not export
those classes on Windows. The IPv4 iteration therefore failed importing its
unmocked IPv6 class. The test now supplies both Linux backend classes on every
platform and asserts that only the correct factory is called and closed. The
separate test still verifies that real Windows raw requests fail explicitly.
No Windows matrix entry or existing assertion was removed.

## Fixes and local verification

- `fb0277f` on Phase 1: fixed integration deadline; record native socket diagnostics.
- `b0f0cde` on Phase 2: normal merge of Phase 1; no history rewrite.
- `dccb8ba` on Phase 2: fixed-timeout fixture and complete Linux backend mocks.
- macOS Python 3.14.3: Phase 1 **36 passed**; Phase 2 **74 run, 72 passed, two
  opt-in privileged tests skipped**, with both Scapy 2.6.1 and 2.8.0.
- The lab driver adds five unprivileged guard/evidence tests: **79 run, 77 passed,
  two opt-in tests skipped** locally with Scapy 2.8.0. These do not prove live I/O.

## CI verification

- Phase 1 [run 39286464882](https://github.com/numankhaan/scanix/actions/runs/39286464882): **all seven matrix jobs passed**, including Windows (36 run, 35 passed, one POSIX skip).
- Phase 2 [run 39287789066](https://github.com/numankhaan/scanix/actions/runs/39287789066): **all seven matrix jobs passed**, including Windows (79 run, 76 passed, three skips: POSIX SIGINT and two opt-in privileged tests).
- Initial Phase 2 fix verification [39286512391](https://github.com/numankhaan/scanix/actions/runs/39286512391), Windows job 118174352669, passed all 74 then-current tests (three skips) and supplied the timing evidence above.
- Separate optional Linux [lab run 39287789060](https://github.com/numankhaan/scanix/actions/runs/39287789060): **26 live cases and 26 capture checks passed**, plus **2/2 privileged loopback tests passed without skips**. This is separate from the regular unprivileged matrix.
- See [RESULTS.md](RESULTS.md) for topology, expected/observed states, packet evidence and explicit remaining macOS validation gaps.
