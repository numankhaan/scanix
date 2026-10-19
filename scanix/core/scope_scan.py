"""Lazy host scheduling with shared pacing and bounded per-host workers."""
from dataclasses import replace
import threading
from .models import ResolvedTarget, ScanReport, utc_now
from .scanner import scan_target
from .timing import RateLimiter, Runtime


def scan_scope(config, plan, stop=None, *, discovery_methods=(), discovery_ports=(80, 443), progress=None):
    stop = stop or threading.Event()
    report = ScanReport(config, schema_version=2, requested_probes=plan.count() * len(config.ports))
    report.scope = plan.preview(config.ports, config.method, discovery_methods, limit=0)
    rate = config.rate or {'connect': 100, 'syn': 10, 'udp': 1}[config.method]
    report.scope['effective_rate'] = rate
    report.scope['effective_per_host'] = min(config.concurrency, config.per_host)
    report.scope['effective_retries'] = 0 if config.method == 'connect' else config.retries
    limiter = RateLimiter(rate)
    try:
        for target in plan:
            if stop.is_set():
                break
            host_config = replace(config, target=target.originals[0])
            runtime = Runtime(host_config, limiter)
            if config.method in ('syn', 'udp'):
                from ..modules.transport import PacketTransport
                with PacketTransport(target.ip):
                    pass  # raw setup must precede even optional TCP discovery
            if discovery_methods:
                from ..modules.discovery import discover_host
                observations = discover_host(target, discovery_methods, discovery_ports, host_config, stop, runtime)
                report.discovery.append(observations)
                if observations['state'] != 'up':
                    if observations['state'] == 'error':
                        report.completion_status = 'failed'
                    continue
            part = scan_target(host_config, stop, endpoint=ResolvedTarget(target.ip, target.family), runtime=runtime)
            for result in part.results:
                result.original_targets = target.originals
            report.results.extend(part.results)
            report.issues.extend(part.issues)
            if part.completion_status != 'complete':
                report.completion_status = part.completion_status
            if progress:
                progress(len(report.results), report.requested_probes)
    except KeyboardInterrupt:
        stop.set()
    except Exception as exc:
        report.completion_status = 'failed'
        report.issues.append({'reason': 'scope_failure', 'exception_type': type(exc).__name__, 'message': str(exc)[:500]})
    finally:
        if stop.is_set():
            report.completion_status = 'interrupted'
        report.results.sort(key=lambda r: (r.target, r.resolved_ip or '', r.port, r.scan_method))
        report.finished_at = utc_now()
    return report
