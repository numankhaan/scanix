"""Bounded trusted workers. Parent owns pacing, cancellation and numeric scope."""
from concurrent.futures import CancelledError, FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path
from dataclasses import fields
import ipaddress
import json
import queue
import subprocess  # nosec B404: trusted fixed worker, no shell
import sys
import threading
import time

from .registry import API_VERSION, PLUGINS, REGISTRY_VERSION, permitted, policy
from ..native.adapter import _decode
from ..service.engine import excluded
from ..service.parsers import clean
from ..service.registry import load_registry
from ..service.models import ServiceEvidence, TLSEvidence

MAX_FRAME = 32768


def _safe(value):
    if isinstance(value, str):
        return clean(value, 1024)
    if isinstance(value, dict):
        return {clean(k, 64): _safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_safe(v) for v in value]
    return value


def _failure(id, status, error):
    return {'plugin_id': id, 'api_version': API_VERSION, 'registry_version': REGISTRY_VERSION,
            'status': status, 'error': error, 'observations': [], 'tls': [],
            'attempts': None, 'transmissions': None, 'bytes_received': None, 'bytes_sent': None}


def _validate(report, plugin):
    expected = _failure(plugin.id, 'unknown', None)
    if (set(report) != set(expected) or report['plugin_id'] != plugin.id or
            type(report['api_version']) is not int or report['api_version'] != API_VERSION or report['registry_version'] != REGISTRY_VERSION or
            report['status'] not in ('complete', 'unknown', 'error') or
            report['error'] not in (None, 'probe_failed')):
        raise ValueError('invalid plugin result')
    for key, limit in (('attempts', 1), ('transmissions', 2), ('bytes_received', 4096), ('bytes_sent', 1024)):
        if type(report[key]) is not int or not 0 <= report[key] <= limit:
            raise ValueError('invalid plugin counters')
    for key in ('observations', 'tls'):
        if not isinstance(report[key], list) or len(report[key]) > 2 or any(not isinstance(x, dict) for x in report[key]):
            raise ValueError('invalid plugin evidence')
    for observation in report['observations']:
        if (set(observation) != {f.name for f in fields(ServiceEvidence)} or
                observation['service'] != plugin.protocol or observation['transport'] != ('tls' if plugin.protocol=='tls' else plugin.transport) or
                observation['confidence'] != 'protocol' or observation['authenticated'] is not False or
                not isinstance(observation['evidence'], dict)):
            raise ValueError('invalid plugin observation contract')
    for evidence in report['tls']:
        if (plugin.protocol != 'tls' or set(evidence) != {f.name for f in fields(TLSEvidence)} or
                evidence['handshake'] not in ('failed', 'succeeded') or
                evidence['verification'] not in ('not_completed','disabled','verified','failed')):
            raise ValueError('invalid plugin TLS evidence')
    return _safe(report)


def run_plugin(row, config, stop, runtime, id, deadline):
    plugin = PLUGINS[id]
    if row.state != 'open' or row.port not in config.ports or row.protocol != ('udp' if config.method == 'udp' else 'tcp'):
        return _failure(id, 'excluded', 'unconfirmed_or_out_of_scope_endpoint')
    if not permitted(plugin, config):
        return _failure(id, 'excluded', 'intrusive_opt_in_required')
    if row.protocol != plugin.transport:
        return _failure(id, 'excluded', 'transport_mismatch')
    if excluded(row.port, load_registry()) and not config.allow_excluded_probes:
        return _failure(id, 'excluded', 'sensitive_port')
    ipaddress.ip_address(row.resolved_ip)
    request = {'api_version': API_VERSION, 'plugin_id': id, 'address': row.resolved_ip, 'port': row.port,
               'original_targets': list(row.original_targets or (row.target,))[:16],
               'configuration': {key: getattr(config, key) for key in
                  ('tls_insecure', 'tls_ca_file', 'sni', 'allow_intrusive_plugins', 'plugin_timeout')}}
    data = (json.dumps(request, allow_nan=False) + '\n').encode()
    if len(data) > MAX_FRAME:
        return _failure(id, 'error', 'request_limit')
    if stop.is_set():
        return _failure(id, 'interrupted', 'cancelled')
    if time.monotonic() >= deadline:
        return _failure(id, 'timeout', 'time_budget')
    process = None
    events = queue.Queue(2)
    finished = threading.Event()
    reader = writer = None
    writes = queue.Queue(2)
    grants = 0

    def read():
        try:
            while not finished.is_set():
                line = process.stdout.readline(MAX_FRAME + 1)
                if len(line) > MAX_FRAME or not line.endswith(b'\n'):
                    frame = {'type': 'fault'}
                else:
                    frame = _decode(line)
                while not finished.is_set():
                    try:
                        events.put(frame, timeout=.05)
                        break
                    except queue.Full:
                        pass
                if frame.get('type') in ('result', 'error', 'fault'):
                    return
        except (OSError, ValueError, UnicodeError):
            try:
                events.put_nowait({'type': 'fault'})
            except queue.Full:
                pass

    def write():
        try:
            while not finished.is_set():
                try:
                    payload = writes.get(timeout=.05)
                except queue.Empty:
                    continue
                process.stdin.write(payload)
                process.stdin.flush()
        except (OSError, ValueError):
            pass

    try:
        # -I excludes ambient PYTHONPATH/user-site; worker anchors reviewed package imports.
        process = subprocess.Popen([sys.executable, '-I', '-u', str(Path(__file__).with_name('worker.py'))],  # nosec B603: fixed trusted builtin worker
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        reader = threading.Thread(target=read, name='plugin-reader', daemon=True)
        reader.start()
        writer = threading.Thread(target=write, name='plugin-writer', daemon=True)
        writer.start()
        writes.put_nowait(data)
        hello = False
        while True:
            if stop.is_set():
                raise CancelledError()
            if time.monotonic() >= deadline:
                return _failure(id, 'timeout', 'time_budget')
            try:
                frame = events.get(timeout=min(.05, max(.001, deadline-time.monotonic())))
            except queue.Empty:
                continue
            if not hello:
                if frame != {'type': 'hello', 'api_version': API_VERSION, 'registry_version': REGISTRY_VERSION}:
                    raise ValueError('incompatible plugin worker')
                hello = True
            elif frame.get('type') == 'token':
                grants += 1
                if frame != {'type': 'token', 'id': grants} or grants > 3:
                    raise ValueError('plugin token budget')
                runtime.limiter.acquire(stop, deadline=deadline)
                writes.put_nowait((json.dumps({'type': 'grant', 'id': grants}) + '\n').encode())
            elif set(frame) == {'type', 'report'} and frame['type'] == 'result':
                result = _validate(frame['report'], plugin)
                while process.poll() is None:
                    if stop.is_set():
                        raise CancelledError()
                    if time.monotonic() >= deadline:
                        raise TimeoutError()
                    stop.wait(.01)
                if process.returncode:
                    raise ValueError('worker failed after result')
                return result
            else:
                raise ValueError('invalid worker frame')
    except CancelledError:
        return _failure(id, 'interrupted', 'cancelled')
    except (TimeoutError, subprocess.TimeoutExpired):
        return _failure(id, 'timeout', 'time_budget')
    except (OSError, ValueError, TypeError, queue.Full):
        return _failure(id, 'error', 'worker_protocol_or_execution_failure')
    finally:
        finished.set()
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait()
        for thread in (reader, writer):
            if thread is not None:
                thread.join(1)
        if process is not None:
            for pipe in (process.stdin, process.stdout):
                pipe.close()


def enrich_results(results, config, stop, runtime, *, deadline=None):
    """Only observed open endpoints; no port guesses authorize an additional transport."""
    def endpoint(row):
        end = min(deadline or float('inf'), time.monotonic() + (3 if config.service_profile == 'quick' else 8))
        existing = {r['plugin_id']: r for r in row.plugin_results}
        for id in config.plugins:
            if id in existing and existing[id]['status'] != 'interrupted':
                continue
            if stop.is_set():
                break
            budget = min(end, time.monotonic() + config.plugin_timeout)
            result = run_plugin(row, config, stop, runtime, id, budget)
            existing[id] = result
            row.plugin_results = list(existing.values())
    rows = iter(row for row in results if row.state == 'open')
    workers = min(config.service_workers, config.concurrency, config.per_host)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        pending = set()
        exhausted = False
        while pending or not exhausted:
            while not exhausted and not stop.is_set() and len(pending) < workers:
                row = next(rows, None)
                if row is None:
                    exhausted = True
                else:
                    pending.add(pool.submit(endpoint, row))
            if stop.is_set():
                exhausted = True
            if pending:
                done, pending = wait(pending, timeout=.05, return_when=FIRST_COMPLETED)
                for future in done:
                    future.result()


def annotate(report):
    report.probe_database_version = load_registry().version
    report.plugin_api_version = API_VERSION
    report.plugin_registry_version = REGISTRY_VERSION
    report.scope['plugins'] = policy(report.configuration)
