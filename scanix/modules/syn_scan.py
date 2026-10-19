"""Experimental legacy Scapy SYN probe, outside Phase 1 accuracy guarantees.

IPv4 only, serialized, fixed TCP flags, no ICMP analysis, retry policy or robust
response correlation. The RST cleanup is best effort, not a tracked TCP session.
"""
from concurrent.futures import CancelledError
import time
from scapy.all import IP, TCP, sr1, conf
from ..core.scanner import new_result, classify_error

conf.verb = 0


def syn_scan_port(config, resolved, port, cancel_event=None):
    if cancel_event is not None and cancel_event.is_set():
        raise CancelledError()
    result = new_result(config, resolved, port)
    start = time.monotonic()
    try:
        packet = IP(dst=resolved.ip) / TCP(dport=port, flags='S')
        response = sr1(packet, timeout=config.timeout, verbose=0)
        if response is None:
            result.state, result.reason = 'unknown', 'syn_no_response'
        elif response.haslayer(TCP):
            flags = int(response.getlayer(TCP).flags)
            if flags == 0x12:
                result.state, result.reason = 'open', 'syn_ack'
                if not (cancel_event and cancel_event.is_set()):
                    sr1(IP(dst=resolved.ip) / TCP(dport=port, flags='R'), timeout=0.5, verbose=0)
            elif flags == 0x14:
                result.state, result.reason = 'closed', 'syn_rst_ack'
            else:
                result.reason = 'syn_unrecognized_response'
        else:
            result.reason = 'syn_unrecognized_response'
    except OSError as exc:
        result.state, result.reason = classify_error(exc.errno)
        result.error_code = exc.errno
    result.connection_elapsed_seconds = time.monotonic() - start
    return result


def syn_scan_range(target, start_port, end_port, timeout=1):
    from ..core.scanner import scan_target
    from ..core.models import ScanConfig
    if not 1 <= start_port <= end_port <= 65535:
        raise ValueError('invalid port range')
    return scan_target(ScanConfig(target, tuple(range(start_port, end_port + 1)),
                                 timeout=timeout, method='syn')).results
