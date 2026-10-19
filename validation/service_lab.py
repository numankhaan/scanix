#!/usr/bin/env python3
"""Unprivileged CLI validation against ephemeral HTTP/TLS loopback endpoints only."""
import argparse
from contextlib import ExitStack, contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import platform
import ssl
import subprocess
import sys
import threading

ROOT = Path(__file__).resolve().parents[1]
TLS = ROOT / 'scanix' / 'tests' / 'fixtures' / 'tls'


class Handler(BaseHTTPRequestHandler):
    server_version = 'ScanixLab/1.0'
    sys_version = ''

    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def log_message(self, *args):
        pass


@contextmanager
def endpoint(certificate=None):
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    if certificate:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(TLS / (certificate+'.pem'), TLS / 'server-TEST-ONLY.key')
        context.set_alpn_protocols(['http/1.1'])
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', help='write JSON evidence; otherwise stdout')
    args = parser.parse_args(argv)
    evidence = dict(platform=platform.platform(), python=platform.python_version(),
                    topology='client and HTTP/TLS servers on 127.0.0.1 ephemeral ports; no external targets', cases=[])
    with ExitStack() as stack:
        plain = stack.enter_context(endpoint())
        trusted = stack.enter_context(endpoint('trusted'))
        selfsigned = stack.enter_context(endpoint('selfsigned'))
        cases = [('plaintext_http', plain, [], 'http', None),
                 ('verified_https_sni', trusted, ['--tls-ca-file',str(TLS/'ca.pem'),'--sni','lab.scanix.invalid'], 'http','verified'),
                 ('selfsigned_rejected', selfsigned, [], None, 'failed'),
                 ('selfsigned_explicit_inspection', selfsigned, ['--tls-insecure'], 'http','disabled')]
        for name, port, options, service, verification in cases:
            command = [sys.executable,'-B','-m','scanix','scan','-t','127.0.0.1','-p',str(port),
                       '--service-detect','--out','json','--out-file','-']+options
            process = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=15)
            if process.returncode:
                raise RuntimeError(process.stderr)
            report = json.loads(process.stdout)
            result = report['results'][0]
            observed = result['service_detection']
            assert result['state'] == 'open', (name, result)
            assert (observed['observations'][-1]['service'] if observed['observations'] else None) == service, (name, observed)
            if verification:
                assert observed['tls'][0]['verification'] == verification, (name, observed)
            evidence['cases'].append(dict(name=name,command=command[3:],expected_port_state='open',
                expected_service=service,expected_verification=verification,observed=result,returncode=process.returncode))
    payload = json.dumps(evidence,indent=2)+'\n'
    if args.output:
        Path(args.output).write_text(payload,encoding='utf-8')
    else:
        print(payload,end='')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
