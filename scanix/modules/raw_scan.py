"""Retry orchestration shared by SYN/UDP, independent of capture backend."""
from concurrent.futures import CancelledError
import time
from .packets import syn_probe, reset_probe, udp_probe, classify_syn, classify_udp
from .transport import PacketTransport
from ..core.scanner import new_result, classify_error
from ..core.timing import Runtime


def raw_scan_port(config, resolved, port, cancel_event, runtime=None):
    runtime = runtime or Runtime(config)
    if cancel_event.is_set():
        raise CancelledError()
    result = new_result(config, resolved, port)
    result.protocol = 'udp' if config.method == 'udp' else 'tcp'
    start = time.monotonic()
    result.attempts = 0
    try:
        with PacketTransport(resolved.ip) as transport:
            if config.method == 'syn':
                probe = syn_probe(transport.source, resolved.ip, port)
                result.probe_type = 'tcp_syn'
                classify = lambda reply: classify_syn(probe, reply)
            else:
                result.probe_type, probe = udp_probe(transport.source, resolved.ip, port)
                classify = lambda reply: classify_udp(probe, reply, result.probe_type)
            for attempt in range(config.retries + 1):
                if cancel_event.is_set():
                    break
                timeout = runtime.timeout.value(attempt) if config.adaptive else config.timeout
                evidence, reply, rtt = transport.exchange(probe, classify, timeout, runtime.limiter, cancel_event)
                result.attempts += 1
                if cancel_event.is_set() and evidence is None:
                    break
                if evidence:
                    result.state, result.reason, result.evidence = evidence.state, evidence.reason, evidence.details
                    if attempt == 0:
                        runtime.timeout.observe(rtt)
                    if config.method == 'syn' and result.state == 'open':
                        try:
                            transport.send(reset_probe(probe, reply), runtime.limiter, cancel_event)
                            result.evidence['reset_sent'] = True
                        except CancelledError:
                            result.evidence['reset_sent'] = False
                        except Exception as exc:
                            result.evidence['reset_sent'] = False
                            result.evidence['reset_error'] = type(exc).__name__
                    break
            else:
                result.state = 'open|filtered' if config.method == 'udp' else 'unknown'
                result.reason = 'udp_no_response' if config.method == 'udp' else 'syn_no_response'
                result.evidence = {'retry_budget_exhausted': True}
            if cancel_event.is_set() and result.reason == 'not_probed':
                result.reason = 'cancelled_during_probe'
    except CancelledError:
        if result.attempts == 0:
            raise
    except OSError as exc:
        result.state, result.reason = classify_error(exc.errno)
        # A raw I/O failure never establishes a remote refusal/open state.
        result.state = 'error'
        result.error_code = exc.errno
    result.connection_elapsed_seconds = time.monotonic() - start
    return result
