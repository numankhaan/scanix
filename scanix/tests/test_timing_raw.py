import errno
import threading
import unittest
from concurrent.futures import CancelledError
from unittest.mock import MagicMock, patch
from scanix.core.models import ScanConfig, ResolvedTarget
from scanix.core.scanner import scan_target
from scanix.core.timing import RateLimiter, AdaptiveTimeout, Runtime
from scanix.modules.raw_scan import raw_scan_port
from scanix.modules.packets import Evidence, syn_probe
from scanix.modules.transport import PacketTransport, BackendUnavailable


class TimingTests(unittest.TestCase):
    def test_rate_no_burst_and_cancel(self):
        now = [0.0]
        limiter = RateLimiter(2, clock=lambda: now[0], sleeper=lambda delay: now.__setitem__(0, now[0] + delay))
        stop = threading.Event()
        limiter.acquire(stop)
        limiter.acquire(stop)
        self.assertAlmostEqual(now[0], .5)
        now[0] = 10
        limiter.acquire(stop)
        limiter.acquire(stop)
        self.assertAlmostEqual(now[0], 10.5)
        stop.set()
        with self.assertRaises(CancelledError):
            limiter.acquire(stop)

    def test_adaptive_bounds(self):
        timer = AdaptiveTimeout(1, .1, 5)
        self.assertEqual(timer.value(5), 5)
        timer.observe(.001)
        self.assertEqual(timer.value(), .1)
        timer.observe(100)
        self.assertEqual(timer.value(), 5)

    def test_invalid_timing(self):
        for kwargs in ({'rate': 0}, {'rate': float('nan')}, {'rate': float('inf')},
                       {'retries': 6}, {'retries': -1}, {'min_timeout': 0},
                       {'min_timeout': 5, 'max_timeout': 1}, {'per_host': 0}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                ScanConfig('127.0.0.1', (80,), **kwargs)


class RawTests(unittest.TestCase):
    def test_silence_retries_and_conservative_defaults(self):
        for method, state, rate in [('syn', 'unknown', 10), ('udp', 'open|filtered', 1)]:
            config = ScanConfig('127.0.0.1', (53,), method=method, retries=2)
            runtime = Runtime(config)
            self.assertEqual(runtime.limiter.interval, 1/rate)
            transport = MagicMock()
            transport.source = '127.0.0.2'
            transport.exchange.return_value = (None, None, .1)
            with patch('scanix.modules.raw_scan.PacketTransport') as factory:
                factory.return_value.__enter__.return_value = transport
                result = raw_scan_port(config, ResolvedTarget('127.0.0.1'), 53, threading.Event(), runtime)
            self.assertEqual(result.state, state)
            self.assertEqual(result.attempts, 3)
            self.assertEqual(transport.exchange.call_count, 3)
            self.assertEqual(result.probe_type, 'dns' if method == 'udp' else 'tcp_syn')
            self.assertEqual([c.args[2] for c in transport.exchange.call_args_list], [1, 2, 4])

    def test_syn_cleanup_and_completed_result_on_cancel(self):
        config = ScanConfig('127.0.0.1', (80,), method='syn')
        p = syn_probe('127.0.0.2', '127.0.0.1', 80)
        from scapy.all import IP, TCP
        reply = IP(src=p.dst, dst=p.src)/TCP(seq=100, ack=42, flags='SA')
        transport = MagicMock(source='127.0.0.2')
        transport.exchange.return_value = (Evidence('open', 'syn_ack', {}), reply, .02)
        transport.send.side_effect = CancelledError()
        with patch('scanix.modules.raw_scan.PacketTransport') as factory:
            factory.return_value.__enter__.return_value = transport
            result = raw_scan_port(config, ResolvedTarget('127.0.0.1'), 80, threading.Event())
        self.assertEqual(result.state, 'open')
        self.assertFalse(result.evidence['reset_sent'])
        transport.send.assert_called_once()
        self.assertEqual(result.attempts, 1)

    def test_preflight_failure_sends_nothing(self):
        for failure in (PermissionError(errno.EACCES, 'denied'), BackendUnavailable('unsupported')):
            with patch('scanix.core.scanner.resolve_target', return_value=ResolvedTarget('127.0.0.1')), \
                 patch('scanix.modules.transport.PacketTransport', side_effect=failure), \
                 patch('scanix.modules.raw_scan.raw_scan_port') as probe:
                report = scan_target(ScanConfig('127.0.0.1', (80,), method='syn'))
            self.assertEqual(report.completion_status, 'failed')
            probe.assert_not_called()

    def test_transport_filters_unrelated_and_stops_at_first_match(self):
        transport = PacketTransport('127.0.0.1')
        transport.socket = MagicMock()
        transport.socket.select.return_value = [transport.socket]
        transport.socket.recv.side_effect = ['unrelated', 'match', 'duplicate']
        classify = lambda packet: Evidence('open', 'matched', {}) if packet == 'match' else None
        evidence, reply, _ = transport.exchange('probe', classify, .5, MagicMock(), threading.Event())
        self.assertEqual(reply, 'match')
        self.assertEqual(transport.socket.recv.call_count, 2)
        transport.socket.send.assert_called_once_with('probe')

    def test_unsupported_platform_fails_before_open(self):
        with patch('scanix.modules.transport.sys.platform', 'win32'), \
             patch('scanix.modules.transport.conf.L3socket') as sock, self.assertRaises(BackendUnavailable):
            with PacketTransport('127.0.0.1'):
                pass
        sock.assert_not_called()
