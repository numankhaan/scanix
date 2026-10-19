"""Bounded TCP connect/raw scan orchestration; no terminal output or OS fingerprinting."""
from concurrent.futures import CancelledError, FIRST_COMPLETED, ThreadPoolExecutor, wait
import errno
import socket
import threading
import time

from .timing import Runtime
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
    service = get_service_name(port) if config.method != 'udp' else None
    return ScanResult(target=config.target, resolved_ip=resolved.ip if resolved else None,
                      address_family=resolved.family if resolved else None, port=port,
                      original_targets=(config.target,), scan_method=config.method,
                      protocol='udp' if config.method == 'udp' else 'tcp', service_name=service,
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
        with socket.socket(socket.AF_INET6 if resolved.family == 'IPv6' else socket.AF_INET, socket.SOCK_STREAM) as sock:
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


def scan_target(config: ScanConfig, cancel_event: threading.Event | None = None, *, endpoint=None, runtime=None, progress=None) -> ScanReport:
    report = ScanReport(config)
    stop = cancel_event if cancel_event is not None else threading.Event()
    resolved = None
    runtime = runtime or Runtime(config)
    pending = {}
    executor = None

    def record(future, port):
        try:
            report.results.append(future.result())
            if progress:
                progress(len(report.results), len(config.ports))
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
        workers = min(config.concurrency, config.per_host)
        if config.method in ('syn', 'udp'):
            from ..modules.raw_scan import raw_scan_port
            from ..modules.transport import PacketTransport
            probe = lambda cfg, addr, port, event: raw_scan_port(cfg, addr, port, event, runtime)
        else:
            original_probe = probe
            def probe(cfg, addr, port, event):
                from dataclasses import replace
                runtime.limiter.acquire(event)
                effective = replace(cfg, banner=False, timeout=runtime.timeout.value() if cfg.adaptive else cfg.timeout)
                result = original_probe(effective, addr, port, event)
                if result.state in ('open', 'closed') and result.connection_elapsed_seconds is not None:
                    runtime.timeout.observe(result.connection_elapsed_seconds)
                if result.state == 'open' and cfg.banner and not event.is_set():
                    try:
                        runtime.limiter.acquire(event)
                        result.banner = grab_banner_for_port(addr.ip, port, timeout=effective.timeout)
                    except CancelledError:
                        pass  # retain the completed connection result
                return result
        if not stop.is_set():
            resolved = endpoint or resolve_target(config.target)
            if config.method in ('syn', 'udp'):
                with PacketTransport(resolved.ip):
                    pass  # fail capture/privilege setup before scheduling probes
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
                              'error_code': getattr(exc, 'errno', None), 'message': str(exc)[:500]})
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
                 for r in report.results) or (config.method != 'connect' and any(r.state == 'error' for r in report.results)):
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
