"""Opt-in privileged loopback checks. Never sends to external destinations."""
import os
import socket
import threading
import unittest
from scanix.core.models import ScanConfig
from scanix.core.scanner import scan_target


@unittest.skipUnless(os.environ.get('SCANIX_PRIVILEGED_TESTS') == '1',
                     'optional: set SCANIX_PRIVILEGED_TESTS=1 with raw capture privileges')
class RawLoopbackTests(unittest.TestCase):
    def test_syn_listener(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            report = scan_target(ScanConfig('127.0.0.1', (listener.getsockname()[1],),
                                            method='syn', rate=10, retries=0, adaptive=False))
        self.assertEqual(report.completion_status, 'complete', report.to_dict())
        self.assertEqual(report.results[0].state, 'open')
        self.assertTrue(report.results[0].evidence['reset_sent'])

    def test_udp_echo_and_closed(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind(('127.0.0.1', 0))
            server.settimeout(3)
            def echo():
                try:
                    data, peer = server.recvfrom(1024)
                    server.sendto(data, peer)
                except OSError:
                    pass
            worker = threading.Thread(target=echo, daemon=True)
            worker.start()
            report = scan_target(ScanConfig('127.0.0.1', (server.getsockname()[1],),
                                            method='udp', rate=1, retries=0, adaptive=False))
            worker.join(timeout=4)
        self.assertEqual(report.completion_status, 'complete', report.to_dict())
        self.assertEqual(report.results[0].state, 'open')
        # The just-released loopback UDP port should generate a quoted ICMP error.
        report = scan_target(ScanConfig('127.0.0.1', (report.results[0].port,),
                                        method='udp', rate=1, retries=0, adaptive=False))
        self.assertEqual(report.results[0].state, 'closed', report.to_dict())
