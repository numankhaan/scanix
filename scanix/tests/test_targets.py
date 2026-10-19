import io
import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from contextlib import redirect_stdout, redirect_stderr
from scanix.core.targets import ScopePlan, read_target_file
from scanix.core.models import ScanConfig
from scanix.core.scanner import new_result
from scanix.core.scope_scan import scan_scope
from scanix.cli import run_cli


class TargetTests(unittest.TestCase):
    def test_cidr_dedup_exclusions_and_associations(self):
        plan = ScopePlan(['127.0.0.0/30', '127.0.0.1', '127.0.0.2'], ['127.0.0.2'])
        targets = list(plan)
        self.assertEqual([t.ip for t in targets], ['127.0.0.1'])
        self.assertEqual(targets[0].originals, ('127.0.0.0/30', '127.0.0.1'))
        self.assertEqual(plan.count(), 1)
        self.assertEqual([t.ip for t in ScopePlan(['::/127'], family='6')], ['::', '::1'])
        self.assertEqual([t.ip for t in ScopePlan(['2001:db8::/126'], family='6')],
                         ['2001:db8::1', '2001:db8::2', '2001:db8::3'])
        self.assertEqual(len(list(ScopePlan(['127.0.0.0/31']))), 2)

    def test_ipv6_is_bounded_without_expansion(self):
        for args in [dict(inputs=['::/64'], family='6'), dict(inputs=['127.0.0.0/8']),
                     dict(inputs=['::1']), dict(inputs=['fe80::1%en0'], family='6'),
                     dict(inputs=['127.0.0.1\x1b[31m']), dict(inputs=['999.1.1.1'])]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                ScopePlan(**args)
        plan = ScopePlan(['2001:db8::/112'], family='6', max_targets=65536)
        self.assertEqual(len(plan.sources), 1)  # stores one network, not 65k targets
        self.assertEqual(next(iter(plan)).ip, '2001:db8::1')

    def answers(self, *args):
        return [(socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('::1', 0, 0, 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.2', 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 0))]

    def test_dns_first_all_once_and_exclusion_all_answers(self):
        resolver = MagicMock(side_effect=self.answers)
        plan = ScopePlan(['lab.test', 'lab.test', '127.0.0.1'], family='any', resolver=resolver)
        self.assertEqual([t.ip for t in plan], ['::1', '127.0.0.1'])
        resolver.assert_called_once()
        plan = ScopePlan(['lab.test', '127.0.0.1'], family='any', dns_policy='all', resolver=self.answers)
        self.assertEqual([t.ip for t in plan], ['::1', '127.0.0.1', '127.0.0.2'])
        self.assertEqual(list(plan)[1].originals, ('lab.test', '127.0.0.1'))
        resolver.reset_mock()
        plan = ScopePlan(['lab.test', '127.0.0.1'], ['lab.test'], family='any', resolver=resolver)
        self.assertEqual(list(plan), [])
        resolver.assert_called_once()
        plan = ScopePlan(['lab.test'], family='4', dns_policy='all', resolver=self.answers)
        self.assertEqual([t.ip for t in plan], ['127.0.0.1', '127.0.0.2'])

    def test_target_files_and_untrusted_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp)/'targets.txt'
            file.write_text('# lab\n127.0.0.1 # loopback\n\n::1\n')
            self.assertEqual(read_target_file(file), ['127.0.0.1', '::1'])
            file.write_bytes(b'\xff')
            with self.assertRaises(ValueError):
                read_target_file(file)
            file.write_bytes(b'x' * (1024*1024+1))
            with self.assertRaises(ValueError):
                read_target_file(file)

    def test_offline_preview_never_resolves_or_opens_sockets(self):
        stdout = io.StringIO()
        with patch('socket.getaddrinfo') as dns, patch('socket.socket') as sock, redirect_stdout(stdout):
            code = run_cli(['scan', '-t', '127.0.0.0/30', '-t', 'lab.test', '-p', '22,80',
                            '--exclude', '127.0.0.2', '--syn', '--preview'])
        self.assertEqual(code, 0)
        dns.assert_not_called()
        sock.assert_not_called()
        preview = json.loads(stdout.getvalue())
        self.assertEqual(preview['targets'][0]['ip'], '127.0.0.1')
        self.assertEqual(preview['unresolved_hostnames'], ['lab.test'])
        self.assertFalse(preview['scope_complete'])
        self.assertIsNone(preview['effective_target_count'])
        self.assertEqual(preview['ports'], [22, 80])
        self.assertEqual(preview['timing']['rate'], 10)

    def test_scope_pacing_associations_and_cancellation(self):
        plan = ScopePlan(['127.0.0.1', '127.0.0.2'])
        config = ScanConfig('scope', (22, 80), concurrency=1)
        stop = threading.Event()
        def probe(config, endpoint, port, event):
            event.set()
            return new_result(config, endpoint, port)
        with patch('scanix.core.scanner.scan_single_port', side_effect=probe), \
             patch('scanix.core.scanner.resolve_target') as dns:
            report = scan_scope(config, plan, stop)
        dns.assert_not_called()
        data = report.to_dict()
        self.assertEqual(data['requested_ports'], 4)
        self.assertEqual(data['completed_ports'], 1)
        self.assertTrue(data['incomplete'])
        self.assertEqual(data['results'][0]['original_targets'], ['127.0.0.1'])

    def test_ipv6_connect_family(self):
        from scanix.core.models import ResolvedTarget
        from scanix.core.scanner import scan_single_port
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.connect_ex.return_value = 0
        with patch('scanix.core.scanner.socket.socket', return_value=sock) as factory:
            result = scan_single_port(ScanConfig('::1', (80,)), ResolvedTarget('::1', 'IPv6'), 80)
        factory.assert_called_once_with(socket.AF_INET6, socket.SOCK_STREAM)
        self.assertEqual(result.state, 'open')
