"""Validated raw SYN scanning. Never falls back to connect."""
from .raw_scan import raw_scan_port


def syn_scan_port(config, resolved, port, cancel_event=None, runtime=None):
    import threading
    return raw_scan_port(config, resolved, port, cancel_event or threading.Event(), runtime)


def syn_scan_range(target, start_port, end_port, timeout=1):
    from ..core.scanner import scan_target
    from ..core.models import ScanConfig
    if not 1 <= start_port <= end_port <= 65535:
        raise ValueError('invalid port range')
    return scan_target(ScanConfig(target, tuple(range(start_port, end_port + 1)),
                                 timeout=timeout, method='syn')).results
