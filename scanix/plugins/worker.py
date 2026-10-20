"""Fixed builtin worker, API 1. No external module names or executable payloads."""
# -I omits project paths; anchor imports to this installed package, never CWD.
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from dataclasses import asdict
import ipaddress
import json
import threading
import time

from scanix.core.models import ScanConfig, ScanResult
from scanix.core.udp_protocols import udp_payload
from scanix.plugins.registry import API_VERSION, PLUGINS, REGISTRY_VERSION
from scanix.service.engine import Detector
from scanix.service.parsers import protocol_response
from scanix.service.transport import Session

MAX_FRAME = 32768


def send(frame):
    data = (json.dumps(frame, allow_nan=False, separators=(',', ':')) + '\n').encode()
    if len(data) > MAX_FRAME:
        raise ValueError('worker output limit')
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


def receive():
    from scanix.native.adapter import _decode
    data = sys.stdin.buffer.readline(MAX_FRAME + 1)
    if not data.endswith(b'\n') or len(data) > MAX_FRAME:
        raise ValueError('worker input limit')
    return _decode(data)


class Tokens:
    def __init__(self):
        self.count = 0

    def acquire(self, stop, *, deadline=None):
        self.count += 1
        if self.count > 3:
            raise ValueError('worker token limit')
        send({'type': 'token', 'id': self.count})
        if receive() != {'type': 'grant', 'id': self.count}:
            raise ValueError('invalid grant')


def run(request):
    if request['api_version'] != API_VERSION:
        raise ValueError('incompatible plugin API')
    plugin = PLUGINS[request['plugin_id']]
    address = str(ipaddress.ip_address(request['address']))
    config = ScanConfig(address, (request['port'],), **request['configuration'])
    if plugin.intrusive and not config.allow_intrusive_plugins:
        raise ValueError('intrusive plugin not authorized')
    originals = tuple(request['original_targets'])
    if len(originals) > 16 or any(not isinstance(x, str) or len(x) > 253 or any(ord(c) < 33 or ord(c) > 126 for c in x) for x in originals):
        raise ValueError('invalid original hostname associations')
    row = ScanResult(address, address, 'IPv6' if ':' in address else 'IPv4', request['port'],
                     protocol=plugin.transport, state='open', original_targets=originals)
    stop = threading.Event()
    tokens = Tokens()
    detector = Detector(row, config, stop, type('Runtime', (), {'limiter': tokens})())
    budget = dict(connections=plugin.connections, transmissions=plugin.transmissions,
                  receive_bytes=plugin.response_bytes, send_bytes=1024,
                  operation_timeout=config.plugin_timeout, passive_timeout=config.plugin_timeout)
    detector.budget = budget
    detector.deadline = time.monotonic() + config.plugin_timeout
    status, error = 'unknown', None
    try:
        with Session(address, row.port, stop, tokens, detector.report, budget, detector.deadline) as session:
            session.connect(udp=plugin.transport == 'udp')
            if plugin.protocol == 'http':
                detector.http(session)
            elif plugin.protocol == 'tls':
                detector.handshake(session, 'tls.tcp.v1')
            elif plugin.protocol == 'ssh':
                data = session.receive(4096, complete=lambda data: protocol_response('ssh', data) is not None)
                detector.add('ssh', data)
            elif plugin.protocol == 'dns':
                _, payload = udp_payload(53)
                session.send(payload)
                detector.add('dns', session.receive(4096, datagram=True), request=payload)
        if detector.report.observations:
            status = 'complete'
    except (OSError, TimeoutError, RuntimeError):
        status, error = 'error', 'probe_failed'  # Never export exception paths or wire data.
    evidence = asdict(detector.report)
    # TLS errors from OpenSSL may contain peer-controlled or local details.
    for tls in evidence['tls']:
        if tls.get('error'):
            tls['error'] = 'handshake_or_verification_failed'
    return {'plugin_id': plugin.id, 'api_version': API_VERSION, 'registry_version': REGISTRY_VERSION,
            'status': status, 'error': error, 'observations': evidence['observations'], 'tls': evidence['tls'],
            'attempts': evidence['attempts'], 'transmissions': evidence['transmissions'],
            'bytes_received': evidence['bytes_received'], 'bytes_sent': evidence['bytes_sent']}


def main():
    send({'type': 'hello', 'api_version': API_VERSION, 'registry_version': REGISTRY_VERSION})
    try:
        report = run(receive())
        send({'type': 'result', 'report': report})
    except (ValueError, KeyError, TypeError, OSError):
        send({'type': 'error', 'reason': 'invalid_request_or_worker_failure'})
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
