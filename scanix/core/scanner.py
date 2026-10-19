"""Bounded IPv4 TCP connect scanning; no terminal output or OS fingerprinting."""
from concurrent.futures import CancelledError, FIRST_COMPLETED, ThreadPoolExecutor, wait
import errno
import socket
import threading
import time

from .models import ResolvedTarget, ScanConfig, ScanReport, ScanResult, State, utc_now
from .services import get_service_name
from .banner import grab_banner_for_port


def classify_error(code: int | None) -> tuple[State, str]:
    # Include Winsock values even when tests run on POSIX.
    if code == 0:
        return 'open', 'connection_succeeded'
    if code in (errno.ECONNREFUSED, 10061):
        return 'closed', 'connection_refused'
    if code in (errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK,
                errno.EINPROGRESS, errno.EALREADY, 10060, 10035, 10036, 10037):
        return 'unknown', 'timeout'
    if code in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ENETDOWN,
                getattr(errno, 'EHOSTDOWN', 10064), 10050, 10051, 10064, 10065):
        return 'error', 'routing_failure'
    if code in (errno.EACCES, errno.EPERM, 10013):
        return 'error', 'permission_denied'
    if code in (errno.EMFILE, errno.ENFILE, errno.ENOBUFS, errno.ENOMEM,
                errno.EADDRNOTAVAIL, errno.EADDRINUSE, 10024, 10055, 10049, 10048):
        return 'error', 'resource_exhausted'
    return 'error', 'socket_error'


def new_result(config: ScanConfig, resolved: ResolvedTarget | None, port: int) -> ScanResult:
    service = get_service_name(port)
    return ScanResult(target=config.target, resolved_ip=resolved.ip if resolved else None,
                      address_family=resolved.family if resolved else None, port=port,
                      scan_method=config.method, service_name=service,
                      detection_source='port_table' if service else None)


def resolve_target(target: str) -> ResolvedTarget:
    # Phase 1 deliberately selects one IPv4 endpoint, once for the whole scan.
    addresses = socket.getaddrinfo(target, None, socket.AF_INET, socket.SOCK_STREAM)
    if not addresses:
        raise socket.gaierror(socket.EAI_NONAME, 'no IPv4 address found')
    return ResolvedTarget(addresses[0][4][0])


def scan_single_port(config: ScanConfig, resolved: ResolvedTarget, port: int,
                     cancel_event: threading.Event | None = None) -> ScanResult:
    if cancel_event is not None and cancel_event.is_set():
        raise CancelledError()
    result = new_result(config, resolved, port)
    start = time.monotonic()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(config.timeout)
            code = sock.connect_ex((resolved.ip, port))
            result.state, result.reason = classify_error(code)
            result.error_code = code if code else None
    except TimeoutError as exc:
        result.state, result.reason = 'unknown', 'timeout'
        result.error_code = exc.errno
    except OSError as exc:
        result.state, result.reason = classify_error(exc.errno)
        result.error_code = exc.errno
    result.connection_elapsed_seconds = time.monotonic() - start
    if result.state == 'open' and config.banner and not (cancel_event and cancel_event.is_set()):
        # Raw evidence only: it cannot confirm the service guess or a version.
        result.banner = grab_banner_for_port(resolved.ip, port, timeout=config.timeout)
    return result


def scan_target(config: ScanConfig, cancel_event: threading.Event | None = None) -> ScanReport:
    report = ScanReport(config)
    stop = cancel_event if cancel_event is not None else threading.Event()
    resolved = None
    pending = {}
    executor = None

    def record(future, port):
        try:
            report.results.append(future.result())
        except CancelledError:
            pass
        except Exception as exc:
            result = new_result(config, resolved, port)
            result.state, result.reason = 'error', 'worker_exception'
            report.results.append(result)
            report.issues.append({'reason': 'worker_exception', 'port': port,
                                  'exception_type': type(exc).__name__})
            report.completion_status = 'failed'

    try:
        probe = scan_single_port
        workers = config.concurrency
        if config.method == 'syn':
            from ..modules.syn_scan import syn_scan_port
            probe, workers = syn_scan_port, 1
        if not stop.is_set():
            resolved = resolve_target(config.target)
            executor = ThreadPoolExecutor(max_workers=workers)
            ports = iter(config.ports)
            exhausted = False
            while pending or not exhausted:
                if stop.is_set():
                    break
                # At most workers futures exist, including running and queued work.
                while len(pending) < workers and not exhausted and not stop.is_set():
                    port = next(ports, None)
                    if port is None:
                        exhausted = True
                    else:
                        pending[executor.submit(probe, config, resolved, port, stop)] = port
                if pending:
                    done, _ = wait(pending, timeout=0.1, return_when=FIRST_COMPLETED)
                    for future in done:
                        record(future, pending.pop(future))
    except KeyboardInterrupt:
        stop.set()
    except socket.gaierror as exc:
        report.completion_status = 'failed'
        report.issues.append({'reason': 'resolution_failed', 'error_code': exc.errno})
        for port in config.ports:
            result = new_result(config, None, port)
            result.state, result.reason, result.error_code = 'error', 'resolution_failed', exc.errno
            report.results.append(result)
    except Exception as exc:
        report.completion_status = 'failed'
        report.issues.append({'reason': 'scan_failure', 'exception_type': type(exc).__name__,
                              'error_code': getattr(exc, 'errno', None)})
    finally:
        if executor:
            for future in pending:
                future.cancel()
            # Running sockets finish within their configured timeout; collect their results.
            executor.shutdown(wait=True, cancel_futures=True)
            for future, port in pending.items():
                record(future, port)
        if stop.is_set():
            report.completion_status = 'interrupted'
        elif any(r.reason in ('permission_denied', 'resource_exhausted', 'worker_exception')
                 for r in report.results):
            report.completion_status = 'failed'
        report.results.sort(key=lambda r: (r.target, r.resolved_ip or '', r.port, r.scan_method))
        report.issues.sort(key=lambda issue: (issue.get('port', -1), issue['reason']))
        report.finished_at = utc_now()
    return report


def scan_ports(target, start_port, end_port, banner=False, max_workers=100, timeout=1.0):
    """Compatibility entry point for existing range-based Python callers."""
    if not 1 <= start_port <= end_port <= 65535:
        raise ValueError('invalid port range')
    return scan_target(ScanConfig(target, tuple(range(start_port, end_port + 1)),
                                  timeout, max_workers, banner=banner)).results
