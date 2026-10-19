"""Deterministic fixtures: only loopback sockets, never public-network scans."""
import csv
import errno
import io
import json
import os
import signal
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import MagicMock, patch
from contextlib import redirect_stderr, redirect_stdout
from concurrent.futures import CancelledError, Future

# Also supports running discovery from the package directory.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scanix.cli import run_cli
from scanix.core.banner import grab_banner_for_port
from scanix.core.models import ResolvedTarget, ScanConfig, ScanReport
from scanix.core.ports import parse_ports
from scanix.core.scanner import new_result, scan_single_port, scan_target
from scanix.output.save_csv import save_csv
from scanix.output.save_html import save_html
from scanix.output.save_json import save_json


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.config = ScanConfig('original.test', (22, 80, 65000), timeout=0.2, concurrency=2)
        self.resolved = ResolvedTarget('127.0.0.1')

    def mocked_probe(self, outcome, *, setup_failure=False):
        sock = MagicMock()
        sock.__enter__.return_value = sock
        if setup_failure:
            sock.settimeout.side_effect = outcome
        elif isinstance(outcome, BaseException):
            sock.connect_ex.side_effect = outcome
        else:
            sock.connect_ex.return_value = outcome
        with patch('scanix.core.scanner.socket.socket', return_value=sock):
            result = scan_single_port(self.config, self.resolved, 80)
        sock.__exit__.assert_called_once()
        sock.getsockopt.assert_not_called()
        return result

    def test_local_open_and_refused(self):
        # A bound non-listening socket can time out on macOS, so release it first.
        # Error classifications are also exhaustively mocked below for portable CI.
        with socket.socket() as server, socket.socket() as refused:
            server.bind(('127.0.0.1', 0))
            server.listen()
            refused.bind(('127.0.0.1', 0))
            open_port, closed_port = server.getsockname()[1], refused.getsockname()[1]
            refused.close()
            config = ScanConfig('127.0.0.1', (open_port, closed_port), timeout=0.5)
            report = scan_target(config)
            results = {r.port: r for r in report.results}
            self.assertEqual(report.completion_status, 'complete')
            self.assertEqual(results[open_port].state, 'open')
            self.assertEqual(results[closed_port].state, 'closed')
            self.assertEqual(results[closed_port].reason, 'connection_refused')
            self.assertIsNotNone(results[closed_port].error_code)
            self.assertEqual([r.port for r in report.results], sorted(config.ports))
            for result in report.results:
                self.assertEqual(result.resolved_ip, '127.0.0.1')
                self.assertEqual(result.address_family, 'IPv4')
                self.assertTrue(result.timestamp.endswith('+00:00'))
                self.assertGreaterEqual(result.connection_elapsed_seconds, 0)
                self.assertIsNone(result.os)

    def test_return_codes_and_exceptions(self):
        cases = [(errno.ECONNREFUSED, 'closed', 'connection_refused'),
                 (errno.ETIMEDOUT, 'unknown', 'timeout'),
                 (errno.EWOULDBLOCK, 'unknown', 'timeout'),
                 (errno.ENETUNREACH, 'error', 'routing_failure'),
                 (errno.EHOSTUNREACH, 'error', 'routing_failure'),
                 (errno.EACCES, 'error', 'permission_denied'),
                 (errno.EMFILE, 'error', 'resource_exhausted'),
                 (errno.ENOBUFS, 'error', 'resource_exhausted'),
                 (errno.EADDRNOTAVAIL, 'error', 'resource_exhausted'),
                 (errno.ECONNRESET, 'error', 'socket_error'),
                 (10061, 'closed', 'connection_refused'),
                 (10060, 'unknown', 'timeout'),
                 (10051, 'error', 'routing_failure'),
                 (10013, 'error', 'permission_denied'),
                 (10055, 'error', 'resource_exhausted')]
        for code, state, reason in cases:
            for outcome in (code, OSError(code, 'mocked error')):
                with self.subTest(code=code, outcome=type(outcome).__name__):
                    result = self.mocked_probe(outcome)
                    self.assertEqual((result.state, result.reason), (state, reason))
                    self.assertEqual(result.error_code, code)
        result = self.mocked_probe(socket.timeout())
        self.assertEqual((result.state, result.reason, result.error_code), ('unknown', 'timeout', None))

    def test_cleanup_on_setup_failure(self):
        result = self.mocked_probe(PermissionError(errno.EACCES, 'denied'), setup_failure=True)
        self.assertEqual(result.reason, 'permission_denied')

    def test_unexpected_socket_failure_still_closes(self):
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.connect_ex.side_effect = RuntimeError('unexpected')
        with patch('scanix.core.scanner.socket.socket', return_value=sock), \
             self.assertRaises(RuntimeError):
            scan_single_port(self.config, self.resolved, 80)
        sock.__exit__.assert_called_once()

    def test_cancelled_worker_cannot_start_a_connection(self):
        stop = threading.Event()
        stop.set()
        with patch('scanix.core.scanner.socket.socket') as sock, self.assertRaises(CancelledError):
            scan_single_port(self.config, self.resolved, 80, stop)
        sock.assert_not_called()

    def test_creation_failure(self):
        with patch('scanix.core.scanner.socket.socket', side_effect=OSError(errno.EMFILE, 'full')):
            result = scan_single_port(self.config, self.resolved, 80)
        self.assertEqual(result.reason, 'resource_exhausted')

    def test_banner_cleanup_and_untrusted_evidence(self):
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.recv.return_value = b'<script>bad()</script>\xff'
        with patch('scanix.core.banner.socket.socket', return_value=sock):
            banner = grab_banner_for_port('127.0.0.1', 80)
        self.assertIn('<script>', banner)
        sock.__exit__.assert_called_once()
        for operation in ('connect', 'sendall', 'recv'):
            sock.reset_mock()
            getattr(sock, operation).side_effect = socket.timeout()
            with patch('scanix.core.banner.socket.socket', return_value=sock):
                self.assertIsNone(grab_banner_for_port('127.0.0.1', 80))
            sock.__exit__.assert_called_once()
            getattr(sock, operation).side_effect = None

    def test_service_guess_is_not_confirmation(self):
        with patch('scanix.core.scanner.grab_banner_for_port', return_value='SSH-2.0-test'):
            config = ScanConfig('target', (22,), banner=True)
            sock = MagicMock()
            sock.__enter__.return_value = sock
            sock.connect_ex.return_value = 0
            with patch('scanix.core.scanner.socket.socket', return_value=sock):
                result = scan_single_port(config, self.resolved, 22)
        self.assertEqual(result.service_name, 'SSH')
        self.assertEqual(result.detection_source, 'port_table')
        self.assertEqual(result.banner, 'SSH-2.0-test')
        self.assertIsNone(result.version_evidence)
        unknown = new_result(config, self.resolved, 65000)
        self.assertIsNone(unknown.service_name)
        self.assertIsNone(unknown.detection_source)

    def test_resolve_once_and_numeric_connections(self):
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.connect_ex.return_value = errno.ECONNREFUSED
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 0))]
        with patch('scanix.core.scanner.socket.getaddrinfo', return_value=addresses) as resolver, \
             patch('scanix.core.scanner.socket.socket', return_value=sock):
            report = scan_target(self.config)
        resolver.assert_called_once_with('original.test', None, socket.AF_INET, socket.SOCK_STREAM)
        self.assertEqual(len(report.results), 3)
        self.assertEqual(report.completion_status, 'complete')
        self.assertTrue(all(r.state == 'closed' for r in report.results))
        for call in sock.connect_ex.call_args_list:
            self.assertEqual(call.args[0][0], '127.0.0.1')
        self.assertEqual({r.target for r in report.results}, {'original.test'})

    def test_resolution_error(self):
        with patch('scanix.core.scanner.socket.getaddrinfo', side_effect=socket.gaierror(-2, 'no host')), \
             patch('scanix.core.scanner.socket.socket') as sock:
            report = scan_target(self.config)
        sock.assert_not_called()
        self.assertEqual(report.completion_status, 'failed')
        self.assertEqual(len(report.results), 3)
        for result in report.results:
            self.assertEqual((result.state, result.reason, result.error_code), ('error', 'resolution_failed', -2))
            self.assertIsNone(result.resolved_ip)
            self.assertIsNone(result.connection_elapsed_seconds)

    def test_worker_exceptions_observed_ordered(self):
        def probe(config, resolved, port, stop):
            if port == 80:
                raise RuntimeError('worker broke')
            time.sleep(0.01 if port == 22 else 0)
            return new_result(config, resolved, port)
        with patch('scanix.core.scanner.resolve_target', return_value=self.resolved), \
             patch('scanix.core.scanner.scan_single_port', side_effect=probe):
            report = scan_target(self.config)
        self.assertEqual([r.port for r in report.results], [22, 80, 65000])
        self.assertEqual(report.results[1].reason, 'worker_exception')
        self.assertEqual(report.completion_status, 'failed')
        self.assertEqual(report.issues[0]['exception_type'], 'RuntimeError')

    def test_cancellation_stops_submission_and_keeps_running_results(self):
        stop = threading.Event()
        config = ScanConfig('target', tuple(range(1, 500)), concurrency=1)
        calls = []
        def probe(config, resolved, port, event):
            calls.append(port)
            event.set()
            return new_result(config, resolved, port)
        with patch('scanix.core.scanner.resolve_target', return_value=self.resolved), \
             patch('scanix.core.scanner.scan_single_port', side_effect=probe):
            report = scan_target(config, stop)
        self.assertEqual(calls, [1])
        self.assertEqual([r.port for r in report.results], [1])
        self.assertEqual(report.completion_status, 'interrupted')
        self.assertTrue(report.to_dict()['incomplete'])

    def test_preset_cancellation_sends_no_traffic(self):
        stop = threading.Event()
        stop.set()
        with patch('scanix.core.scanner.resolve_target') as resolve:
            report = scan_target(self.config, stop)
        resolve.assert_not_called()
        self.assertEqual(report.results, [])
        self.assertEqual(report.completion_status, 'interrupted')

    def test_keyboard_interrupt_cancels_queued_future(self):
        queued = Future()
        executor = MagicMock()
        executor.submit.return_value = queued
        config = ScanConfig('target', (1, 2), concurrency=1)
        with patch('scanix.core.scanner.resolve_target', return_value=self.resolved), \
             patch('scanix.core.scanner.ThreadPoolExecutor', return_value=executor), \
             patch('scanix.core.scanner.wait', side_effect=KeyboardInterrupt):
            report = scan_target(config)
        self.assertTrue(queued.cancelled())
        executor.submit.assert_called_once()
        executor.shutdown.assert_called_once_with(wait=True, cancel_futures=True)
        self.assertEqual(report.completion_status, 'interrupted')

    def test_bounded_futures(self):
        # Model completed futures deterministically and count the outstanding window.
        outstanding = 0
        peak = 0
        class TrackedFuture(Future):
            def result(inner, *args, **kwargs):
                nonlocal outstanding
                outstanding -= 1
                return super().result(*args, **kwargs)
        class Executor:
            def __init__(inner, max_workers):
                self.assertEqual(max_workers, 2)
            def submit(inner, fn, config, resolved, port, stop):
                nonlocal outstanding, peak
                outstanding += 1
                peak = max(peak, outstanding)
                future = TrackedFuture()
                future.set_result(new_result(config, resolved, port))
                return future
            def shutdown(inner, **kwargs):
                pass
        config = ScanConfig('target', tuple(range(1, 1000)), concurrency=2)
        with patch('scanix.core.scanner.resolve_target', return_value=self.resolved), \
             patch('scanix.core.scanner.ThreadPoolExecutor', Executor):
            report = scan_target(config)
        self.assertEqual(peak, 2)
        self.assertEqual(outstanding, 0)
        self.assertEqual(len(report.results), 999)

    def test_local_failures_mark_report_failed(self):
        for reason in ('permission_denied', 'resource_exhausted'):
            result = new_result(self.config, self.resolved, 80)
            result.state, result.reason = 'error', reason
            with patch('scanix.core.scanner.resolve_target', return_value=self.resolved), \
                 patch('scanix.core.scanner.scan_single_port', return_value=result):
                self.assertEqual(scan_target(self.config).completion_status, 'failed')


class InputTests(unittest.TestCase):
    def test_ports(self):
        self.assertEqual(parse_ports('443, 22,80-82,81,1,65535'), (1, 22, 80, 81, 82, 443, 65535))
        self.assertEqual(parse_ports('22'), (22,))
        self.assertEqual(parse_ports('22-22'), (22,))

    def test_invalid_ports(self):
        for value in ('', '0', '65536', '2-1', '1-65536', '1,', ',1', '1,,2', '-1',
                      '1-2-3', 'a', '1.0', '+1', '1 - 2', '１', '9' * 5000):
            with self.subTest(value=value[:20]), self.assertRaises(ValueError):
                parse_ports(value)

    def test_config(self):
        self.assertEqual(ScanConfig('host', (80, 22, 80)).ports, (22, 80))
        for overrides in ({'ports': ()}, {'ports': (0,)}, {'ports': (True,)},
                          {'timeout': 0}, {'timeout': float('nan')}, {'timeout': float('inf')},
                          {'timeout': 301}, {'concurrency': 0}, {'concurrency': 1025},
                          {'target': ''}, {'target': 'a\x00b'}, {'method': 'udp'},
                          {'method': 'syn', 'banner': True}):
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                ScanConfig(**({'target': 'host', 'ports': (80,)} | overrides))


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.config = ScanConfig('<img src=x onerror=bad()>', (80,))
        result = new_result(self.config, ResolvedTarget('127.0.0.1'), 80)
        result.banner = '<script>alert("x")</script>\x1b[31m'
        result.version_evidence = {'raw': '<bad>&"', 'source': 'fixture'}
        self.report = ScanReport(self.config, [result], completion_status='interrupted')
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)

    def test_json_roundtrip(self):
        path = self.path / 'scan.json'
        save_json(self.report, path)
        data = json.loads(path.read_text())
        self.assertEqual(data, self.report.to_dict())
        self.assertIsInstance(data['results'][0]['version_evidence'], dict)
        self.assertIsNone(data['results'][0]['os'])
        self.assertTrue(data['incomplete'])
        self.assertEqual(data['completion_status'], 'interrupted')
        self.assertNotIn('\x1b', path.read_text())  # JSON escapes remote controls.

    def test_csv_roundtrip(self):
        path = self.path / 'scan.csv'
        save_csv(self.report, path)
        with path.open(newline='') as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual(rows[0]['record_type'], 'scan')
        self.assertEqual(rows[0]['completion_status'], 'interrupted')
        self.assertEqual(json.loads(rows[0]['configuration'])['ports'], [80])
        self.assertTrue(json.loads(rows[0]['incomplete']))
        self.assertEqual(json.loads(rows[1]['version_evidence']), self.report.results[0].version_evidence)
        self.assertIsNone(json.loads(rows[1]['os']))
        self.assertEqual(rows[1]['banner'], self.report.results[0].banner)

    def test_html_escaping(self):
        path = self.path / 'scan.html'
        save_html(self.report, path, title='<script>title</script>')
        text = path.read_text()
        self.assertNotIn('<script>', text)
        self.assertNotIn('<img', text)
        self.assertIn('&lt;script&gt;', text)
        self.assertIn('&quot;', text)
        self.assertIn('interrupted', text)

    def test_empty_reports_keep_metadata(self):
        self.report.results = []
        for exporter, extension in ((save_json, 'json'), (save_csv, 'csv'), (save_html, 'html')):
            path = self.path / ('empty.' + extension)
            exporter(self.report, path)
            self.assertIn('interrupted', path.read_text())

    def test_atomic_replace_and_cleanup_on_failure(self):
        path = self.path / 'scan.json'
        path.write_text('original')
        with patch('scanix.output.common.os.replace', side_effect=OSError('mock failure')):
            with self.assertRaises(OSError):
                save_json(self.report, path)
        self.assertEqual(path.read_text(), 'original')
        self.assertEqual(list(self.path.iterdir()), [path])
        save_json(self.report, path)
        self.assertEqual(json.loads(path.read_text()), self.report.to_dict())


class CLITests(unittest.TestCase):
    args = ['scan', '-t', '127.0.0.1', '-p', '22,80-81']

    def invoke(self, extra=(), report=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch('scanix.cli.scan_target', return_value=report or ScanReport(
                ScanConfig('127.0.0.1', (22, 80, 81)))) as scan, \
             redirect_stdout(stdout), redirect_stderr(stderr):
            code = run_cli(self.args + list(extra))
        return code, stdout.getvalue(), stderr.getvalue(), scan

    def test_default_and_explicit_connect(self):
        for extra in ([], ['--connect']):
            code, _, _, scan = self.invoke(extra)
            self.assertEqual(code, 0)
            scan.assert_called_once()
            self.assertEqual(scan.call_args.args[0].method, 'connect')

    def test_invalid_input_sends_no_traffic(self):
        for extra in (['--syn', '--connect'], ['--udp'], ['--timeout', 'nan'],
                      ['--timeout', '-1'], ['--concurrency', '0'], ['--ports', '4-2'],
                      ['--out-file', 'x'], ['--out', 'csv', '--out-file', '-'],
                      ['--syn', '--banner']):
            with self.subTest(extra=extra), patch('scanix.cli.scan_target') as scan, \
                 patch('scanix.core.scanner.socket.getaddrinfo') as resolve, \
                 redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exit:
                run_cli(self.args + extra)
            self.assertEqual(exit.exception.code, 2)
            scan.assert_not_called()
            resolve.assert_not_called()

    def test_udp_message(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit):
            run_cli(self.args + ['--udp'])
        self.assertIn('UDP scanning is not implemented', stderr.getvalue())

    def test_syn_selection_never_connects(self):
        # Stub Scapy module completely: no dependency or raw socket needed in CI.
        module = types.ModuleType('scanix.modules.syn_scan')
        def probe(config, resolved, port, stop):
            return new_result(config, resolved, port)
        module.syn_scan_port = MagicMock(side_effect=probe)
        from scanix.core.scanner import scan_target as real_scan
        with patch.dict(sys.modules, {'scanix.modules.syn_scan': module}), \
             patch('scanix.cli.scan_target', side_effect=real_scan), \
             patch('scanix.core.scanner.resolve_target', return_value=ResolvedTarget('127.0.0.1')), \
             patch('scanix.core.scanner.scan_single_port') as connect, \
             redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
            code = run_cli(self.args + ['--syn'])
        self.assertEqual(code, 0)
        connect.assert_not_called()
        self.assertEqual(module.syn_scan_port.call_count, 3)

    def test_missing_syn_dependency(self):
        with patch.dict(sys.modules, {'scanix.modules.syn_scan': None}), \
             patch('scanix.cli.scan_target') as scan, redirect_stderr(io.StringIO()):
            self.assertEqual(run_cli(self.args + ['--syn']), 1)
        scan.assert_not_called()

    def test_json_stdout_is_clean(self):
        code, stdout, stderr, _ = self.invoke(['--out', 'json', '--out-file', '-'])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout)['completion_status'], 'complete')
        self.assertNotIn('\x1b', stdout)
        self.assertIn('Scan complete', stderr)

    def test_interrupted_partial_export(self):
        config = ScanConfig('127.0.0.1', (22, 80))
        report = ScanReport(config, [new_result(config, ResolvedTarget('127.0.0.1'), 22)],
                            completion_status='interrupted')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'partial.json'
            code, _, _, _ = self.invoke(['--out', 'json', '--out-file', str(path)], report)
            self.assertEqual(code, 130)
            data = json.loads(path.read_text())
            self.assertTrue(data['incomplete'])
            self.assertEqual(len(data['results']), 1)

    def test_failed_report_and_output_failure(self):
        report = ScanReport(ScanConfig('target', (1,)), completion_status='failed')
        self.assertEqual(self.invoke(report=report)[0], 1)
        with patch('scanix.output.save_json.save_json', side_effect=OSError('denied')):
            code, _, stderr, _ = self.invoke(['--out', 'json'])
        self.assertEqual(code, 1)
        self.assertIn('Output failed: denied', stderr)

    def test_ctrl_c_handler_sets_event_and_is_restored(self):
        handler = None
        def install(sig, callback):
            nonlocal handler
            handler = callback
            return 'previous'
        def scanning(config, event):
            handler(None, None)
            self.assertTrue(event.is_set())
            return ScanReport(config, completion_status='interrupted')
        with patch('scanix.cli.signal.signal', side_effect=install) as signals, \
             patch('scanix.cli.scan_target', side_effect=scanning), \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(run_cli(self.args), 130)
        self.assertEqual(signals.call_args.args[1], 'previous')

    @unittest.skipIf(os.name == 'nt', 'POSIX SIGINT subprocess integration')
    def test_actual_sigint_saves_partial_results(self):
        script = """
from pathlib import Path
from unittest.mock import patch
import sys
import time
from scanix.cli import run_cli
from scanix.core.models import ResolvedTarget
from scanix.core.scanner import new_result

def probe(config, resolved, port, event):
    Path(sys.argv[1]).write_text('ready')
    while not event.is_set():
        time.sleep(0.01)
    return new_result(config, resolved, port)

with patch('scanix.core.scanner.resolve_target', return_value=ResolvedTarget('127.0.0.1')), \\
     patch('scanix.core.scanner.scan_single_port', side_effect=probe):
    raise SystemExit(run_cli(['scan', '-t', 'fixture', '-p', '1-100',
                             '--concurrency', '1', '--out', 'json', '--out-file', sys.argv[2]]))
"""
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / 'ready'
            output = Path(directory) / 'partial.json'
            process = subprocess.Popen([sys.executable, '-B', '-c', script, str(ready), str(output)],
                                       cwd=Path(__file__).resolve().parents[2],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 5
                while not ready.exists() and time.monotonic() < deadline and process.poll() is None:
                    time.sleep(0.01)
                self.assertTrue(ready.exists(), 'child did not start the mocked probe')
                process.send_signal(signal.SIGINT)
                stdout, stderr = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 130, stderr)
                self.assertEqual(stdout, '')
                report = json.loads(output.read_text())
                self.assertEqual(report['completion_status'], 'interrupted')
                self.assertTrue(report['incomplete'])
                self.assertEqual([r['port'] for r in report['results']], [1])
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()

    def test_entrypoint_exit_code(self):
        result = subprocess.run([sys.executable, '-B', '-m', 'scanix', 'scan', '-t',
                                 '127.0.0.1', '-p', '80', '--udp'],
                                cwd=Path(__file__).resolve().parents[2], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn('Traceback', result.stderr)


if __name__ == '__main__':
    unittest.main()
