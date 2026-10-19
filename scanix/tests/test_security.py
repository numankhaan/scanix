"""Confirmed security defects, tested without real traceroute or public traffic."""
from contextlib import redirect_stdout
import io
import csv
from pathlib import Path
import tempfile
import ssl
import threading
import time
from unittest.mock import Mock
from scanix.service.transport import Session
from scanix.core.models import ScanConfig, ScanReport, ScanResult
from scanix.output.save_csv import save_csv
import unittest
from unittest.mock import patch
from scanix.core.utils import safe_print
from scanix.modules.traceroute import traceroute
from scanix.output.save_csv import spreadsheet_safe


class SecurityRegressionTests(unittest.TestCase):
    def test_csv_formula_prefixes(self):
        for value in ('=1+1', '+SUM(A1)', '-1+2', '@SUM(A1)', ' \t=1', '\r=1'):
            self.assertTrue(spreadsheet_safe(value).startswith("'"))
        self.assertEqual(spreadsheet_safe('SSH-2.0-fixture'), 'SSH-2.0-fixture')
        self.assertEqual(spreadsheet_safe(1), 1)

    def test_csv_export_neutralizes_remote_banner(self):
        report = ScanReport(ScanConfig('127.0.0.1', (22,)), results=[
            ScanResult('127.0.0.1', '127.0.0.1', 'IPv4', 22, banner='=1+1')])
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)/'report.csv'
            save_csv(report, destination)
            with destination.open(newline='') as source:
                rows = list(csv.DictReader(source))
            self.assertEqual(rows[1]['banner'], "'=1+1")
            self.assertEqual(rows[1]['port'], '22')

    def test_terminal_controls_are_removed(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            safe_print('hello\x1b[31m\x00\u202eend')
        self.assertFalse(any(c in buffer.getvalue() for c in ('\x1b', '\x00', '\u202e')))

    def test_traceroute_rejects_options_and_limits(self):
        for target in ('--help', '-g127.0.0.1', 'localhost\n--help', 'localhost;echo'):
            with self.assertRaises(ValueError):
                traceroute(target)
        for hops in (0, 65, True):
            with self.assertRaises(ValueError):
                traceroute('127.0.0.1', hops)

    def test_tls_boundary_enforces_minimum_even_for_custom_context(self):
        report = Mock(transmissions=0)
        context = Mock(minimum_version=None)
        session = Session('127.0.0.1', 443, threading.Event(), Mock(), report,
                          {'transmissions': 2, 'operation_timeout': .5}, time.monotonic()+1)
        session.sock = Mock()
        wrapped = session.tls(context, 'localhost')
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        context.wrap_socket.assert_called_once()
        wrapped.do_handshake.assert_called_once()

    @patch('scanix.modules.traceroute.shutil.which', return_value='/synthetic/traceroute')
    @patch('scanix.modules.traceroute.subprocess.run')
    def test_traceroute_uses_fixed_resolved_executable_and_timeout(self, run, which):
        run.return_value.stdout = 'synthetic hop\n'
        with patch('scanix.modules.traceroute.platform.system', return_value='Linux'):
            self.assertEqual(traceroute('127.0.0.1', 2), ['synthetic hop'])
        args, kwargs = run.call_args
        self.assertEqual(args[0], ['/synthetic/traceroute', '-n', '-m', '2', '-w', '1', '127.0.0.1'])
        self.assertEqual(kwargs['timeout'], 13)
        self.assertFalse(kwargs.get('shell', False))
