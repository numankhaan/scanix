"""Called only inside the guarded private namespace lab. Never uploads raw evidence."""
import hashlib
import json
from pathlib import Path
import re
import resource
import signal
import subprocess
import threading
import time


def validate(output, binary, parent_netns):
    from validation.privileged_lab import assert_isolated, V4, record, capture_evidence, command
    assert_isolated(parent_netns, ('lo', 'sxscan'))
    from scapy.all import IP, TCP, rdpcap
    from scanix.core.models import ScanConfig, ResolvedTarget
    from scanix.core.scanner import scan_target
    from scanix.core.targets import ScopePlan
    from scanix.native.adapter import scan_native

    binary = str(Path(binary).resolve(strict=True))
    result = {'status': 'failed', 'checks': [], 'cases': [], 'captures': [],
              'topology': 'fresh scanner/peer namespaces, veth, no external default route',
              'scope': 'synthetic IPv4 lab only; first port 18000 silently dropped',
              'rate_packets_per_second': 20, 'timeout_seconds': .4, 'retries': 1}

    def check(name, passed):
        result['checks'].append({'name': name, 'passed': bool(passed)})

    def captured(name, operation):
        path = output / (name + '.pcap')
        log = output / (name + '-capture.log')
        with log.open('w') as stream:
            process = subprocess.Popen(['tcpdump', '-n', '--immediate-mode', '-U', '-s', '256',
                '-c', '10000', '-i', 'sxscan', '-w', str(path)], stdout=subprocess.DEVNULL, stderr=stream)
            try:
                deadline = time.monotonic() + 5
                while 'listening on' not in log.read_text():
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError('native lab capture unavailable')
                    time.sleep(.02)
                report = operation()
                # Allow packet-buffer delivery before the bounded capture shutdown.
                time.sleep(.1)
            finally:
                if process.poll() is None:
                    process.send_signal(signal.SIGINT)
                process.wait(timeout=5)
        packets = rdpcap(str(path))
        dropped = re.search(r'([0-9]+) packets dropped by kernel', log.read_text())
        check(name + '-independent-capture-loss', dropped is not None and int(dropped[1]) == 0)
        result['captures'].append({'name': name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                                   'packets': len(packets), 'kernel_drops': int(dropped[1]) if dropped else None})
        record(output / (name + '-report.json'), report.to_dict())
        return report, packets

    ports = (18000, 19000, 19001, 19002)
    config = ScanConfig(V4[1], ports, engine='native', method='syn', concurrency=4, per_host=4,
                        timeout=.4, max_timeout=2, adaptive=False, retries=1, rate=20, engine_timeout=5)
    # Only peer survives this bounded CIDR/exclusion policy.
    plan = ScopePlan(['10.203.0.0/29'], ['10.203.0.1', '10.203.0.3', '10.203.0.4/30'])
    own_before = resource.getrusage(resource.RUSAGE_SELF)
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    start = time.monotonic()
    report, packets = captured('native-syn', lambda: scan_native(config, plan, binary=binary))
    elapsed = time.monotonic() - start
    own_after = resource.getrusage(resource.RUSAGE_SELF)
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    result['measurement'] = {'wall_seconds_including_capture_setup_and_drain': elapsed,
        'child_cpu_seconds_including_tcpdump': after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime,
        'child_rss_high_water_upper_bound_bytes': after.ru_maxrss * 1024,
        'memory_scope': 'all children in this lab process; not isolated native RSS',
        'logical_cpus': __import__('os').cpu_count(),
        'parent_cpu_seconds_including_adapter_capture_decode': own_after.ru_utime+own_after.ru_stime-own_before.ru_utime-own_before.ru_stime,
        'physical_memory_bytes': __import__('os').sysconf('SC_PHYS_PAGES')*__import__('os').sysconf('SC_PAGE_SIZE'),
        'architecture': __import__('platform').machine(), 'platform': __import__('platform').platform()}
    expected = {18000: ('unknown', 'no_response'), 19000: ('open', 'syn_ack'),
                19001: ('closed', 'syn_rst_ack'), 19002: ('filtered', 'icmp_administratively_prohibited')}
    check('completed-coverage', report.completion_status == 'complete' and len(report.results) == 4)
    for row in report.results:
        wanted = expected.get(row.port)
        check('state-reason-' + str(row.port), wanted == (row.state, row.reason))
        check('attempts-' + str(row.port), row.attempts == (2 if row.port == 18000 else 1))
        result['cases'].append({'name': 'native-syn-' + str(row.port), 'method': 'syn', 'target': V4[1],
            'source': V4[0], 'port': row.port, 'expected': wanted[0] if wanted else None,
            'observed': row.state, 'attempts': row.attempts})
    evidence = capture_evidence(packets, result['cases'])
    result['capture_evidence'] = evidence
    check('all-independent-wire-correlations', len(evidence) == 4 and all(e['passed'] for e in evidence))
    metrics = report.implementation.get('metrics', {})
    check('actual-transmission-counters', metrics.get('attempted') == 4 and metrics.get('syn_sent') == 5
          and metrics.get('retries_sent') == 1 and metrics.get('resets_sent') == 1 and metrics.get('send_errors') == 0)
    check('observed-capture-loss', metrics.get('capture_drops') == 0 and metrics.get('queue_drops') == 0)
    check('native-process-resource-metrics', isinstance(metrics.get('native_cpu_seconds'),(int,float))
          and metrics['native_cpu_seconds']>=0 and isinstance(metrics.get('native_peak_rss_bytes'),int)
          and metrics['native_peak_rss_bytes']>0)
    check('bounded-outstanding', 1 < metrics.get('peak_outstanding', 0) <= 4 and metrics.get('peak_per_host', 0) <= 4)
    explicit = [p for p in packets if IP in p and TCP in p and p[IP].src == V4[0]
                and int(p[TCP].flags) in (2, 0x14)]
    check('scope-exclusions-on-wire', bool(explicit) and all(p[IP].dst == V4[1] and p[TCP].dport in ports for p in explicit))
    gaps = [float(b.time - a.time) for a, b in zip(explicit, explicit[1:])]
    check('global-packet-pacing', len(explicit) == 6 and gaps and min(gaps) >= .045)
    silent = [p for p in explicit if int(p[TCP].flags) == 2 and p[TCP].dport == 18000]
    opened = [p for p in explicit if int(p[TCP].flags) == 2 and p[TCP].dport == 19000]
    check('send-independent-of-silent-response-window', bool(silent and opened)
          and 0 <= float(opened[0].time - silent[0].time) < .4)
    result['minimum_explicit_packet_gap_seconds'] = min(gaps) if gaps else None
    result['engine_metrics'] = metrics
    native_elapsed=metrics.get('elapsed_seconds',0)
    result['measurement']['completed_pairs_per_native_session_second']=metrics.get('completed',0)/native_elapsed if native_elapsed else None
    result['measurement']['explicit_packets_per_native_session_second']=(metrics.get('syn_sent',0)+metrics.get('resets_sent',0))/native_elapsed if native_elapsed else None

    # Python behavior provides separate method agreement, not the only ground truth.
    from dataclasses import replace
    python = scan_target(replace(config, engine='python'), endpoint=ResolvedTarget(V4[1], 'IPv4'))
    check('existing-python-agreement', python.completion_status == 'complete'
          and [(r.port, r.state) for r in python.results] == [(r.port, r.state) for r in report.results])

    excluded, excluded_packets = captured('native-excluded', lambda: scan_native(
        config, ScopePlan([V4[1]], [V4[1]]), binary=binary))
    check('empty-scope-no-sends', excluded.completion_status == 'complete'
          and excluded.implementation.get('metrics', {}).get('syn_sent') == 0
          and not any(IP in p and TCP in p and p[IP].src == V4[0] and int(p[TCP].flags) == 2 for p in excluded_packets))

    stop = threading.Event()
    cancel_config = replace(config, ports=(19000, 19003))
    interrupted, cancel_packets = captured('native-cancel', lambda: scan_native(
        cancel_config, ScopePlan([V4[1]]), stop, binary=binary,
        progress=lambda done, total: stop.set()))
    check('cancel-keeps-positive-results', interrupted.completion_status == 'interrupted'
          and any(r.port == 19000 and r.state == 'open' for r in interrupted.results)
          and interrupted.to_dict()['incomplete'])
    check('cancel-capture-has-actual-probe', any(IP in p and TCP in p and p[IP].src == V4[0]
          and int(p[TCP].flags) == 2 for p in cancel_packets))
    check('cancel-coverage-bounded', interrupted.implementation.get('metrics', {}).get('attempted', 0) <= 2)

    result['status'] = 'passed' if result['checks'] and all(v['passed'] for v in result['checks']) else 'failed'
    record(output / 'native-syn-results.json', result)
    # Category/counts only; raw reports and captures remain in the ephemeral private directory.
    safe_metrics={key:metrics.get(key) for key in ('elapsed_seconds','attempted','completed','syn_sent',
        'retries_sent','resets_sent','send_errors','received_packets','matched_responses','duplicate_responses',
        'late_responses','timeouts','capture_drops','queue_drops','peak_outstanding','peak_per_host',
        'cooldown_ms','receive_cooldown_ms','native_cpu_seconds','native_peak_rss_bytes')}
    safe_measurement={key:result['measurement'].get(key) for key in ('logical_cpus','physical_memory_bytes',
        'architecture','completed_pairs_per_native_session_second','explicit_packets_per_native_session_second',
        'parent_cpu_seconds_including_adapter_capture_decode','wall_seconds_including_capture_setup_and_drain')}
    print(json.dumps({'native_syn_lab': result['status'], 'checks': len(result['checks']),
        'failed_checks': [v['name'] for v in result['checks'] if not v['passed']],
        'engine_metrics':safe_metrics,'measurement':safe_measurement,
        'states':[{'port':row.port,'state':row.state,'reason':row.reason,'attempts':row.attempts,'error_code':row.error_code} for row in report.results],
        'issues':[{'reason':issue.get('reason'),'exception_type':issue.get('exception_type')} for issue in report.issues],
        'captures':result['captures'],'minimum_explicit_packet_gap_seconds':result.get('minimum_explicit_packet_gap_seconds')}))
    return result
