from concurrent.futures import Future
from contextlib import redirect_stdout, redirect_stderr
import io
import json
import threading
import unittest
from unittest.mock import MagicMock, patch
from scapy.all import (IP, IPv6, Ether, ARP, ICMP, ICMPv6EchoReply, ICMPv6DestUnreach,
                       ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, Raw)
from scanix.cli import run_cli
from scanix.core.models import ScanConfig
from scanix.core.targets import Target, ScopePlan
from scanix.core.scanner import new_result
from scanix.modules.discovery import (local_link_method, echo_probe, classify_echo,
    link_probe, classify_link, discover_host, discover_targets)


class DiscoveryTests(unittest.TestCase):
    def test_local_and_routed_method_selection(self):
        mac = '02:00:00:00:00:01'
        self.assertIsNone(local_link_method('arp', 'IPv4', '0.0.0.0', mac))
        self.assertIsNone(local_link_method('nd', 'IPv6', '::', mac))
        self.assertEqual(local_link_method('arp', 'IPv4', '127.0.0.2', mac), 'routed_target_not_on_link')
        self.assertEqual(local_link_method('nd', 'IPv6', 'fe80::1', mac), 'routed_target_not_on_link')
        self.assertEqual(local_link_method('arp', 'IPv6', '::', mac), 'arp_requires_ipv4')
        self.assertEqual(local_link_method('nd', 'IPv4', '0.0.0.0', mac), 'nd_requires_ipv6')
        self.assertEqual(local_link_method('arp', 'IPv4', '0.0.0.0', '00:00:00:00:00:00'), 'ethernet_capture_required')

    def test_echo_and_explicit_path_error(self):
        for source, destination in [('127.0.0.1', '127.0.0.2'), ('::1', '::2')]:
            p = echo_probe(source, destination)
            echo = ICMP(type=0, id=p.payload.id, seq=p.payload.seq) if isinstance(p, IP) else ICMPv6EchoReply(id=p.payload.id, seq=p.payload.seq)
            r = p.__class__(src=destination, dst=source)/echo/Raw(bytes(p.payload)[8:])
            r = r.__class__(bytes(r))
            self.assertEqual(classify_echo(p, r).state, 'up')
            r.payload.seq ^= 1
            self.assertIsNone(classify_echo(p, r))
            self.assertIsNone(classify_echo(p, None))
            error = ICMP(type=3, code=1) if isinstance(p, IP) else ICMPv6DestUnreach(code=0)
            r = p.__class__(src=destination, dst=source)/error/p.copy()
            r = r.__class__(bytes(r))
            self.assertEqual(classify_echo(p, r).state, 'unreachable')
            r.payload.payload.payload.id ^= 1
            self.assertIsNone(classify_echo(p, r))

    def test_arp_and_neighbor_validation(self):
        local, remote = '02:00:00:00:00:01', '02:00:00:00:00:02'
        p = link_probe('arp', '127.0.0.1', '127.0.0.2', local)
        r = Ether(src=remote, dst=local)/ARP(op=2, psrc='127.0.0.2', pdst='127.0.0.1', hwsrc=remote, hwdst=local)
        r = Ether(bytes(r))
        self.assertEqual(classify_link(p, r, 'arp', '127.0.0.2').state, 'up')
        r.payload.pdst = '127.0.0.3'
        self.assertIsNone(classify_link(p, r, 'arp', '127.0.0.2'))
        p = link_probe('nd', '2001:db8::1', '2001:db8::2', local)
        self.assertEqual(p.dst, '33:33:ff:00:00:02')
        self.assertEqual(p.payload.hlim, 255)
        r = Ether(src=remote, dst=local)/IPv6(src='2001:db8::2', dst='2001:db8::1', hlim=255)/ICMPv6ND_NA(tgt='2001:db8::2', S=1)/ICMPv6NDOptDstLLAddr(lladdr=remote)
        r = Ether(bytes(r))
        self.assertEqual(classify_link(p, r, 'nd', '2001:db8::2').state, 'up')
        r.payload.hlim = 64
        self.assertIsNone(classify_link(p, r, 'nd', '2001:db8::2'))
        r.payload.hlim = 255
        r.payload.payload.tgt = '2001:db8::3'
        self.assertIsNone(classify_link(p, r, 'nd', '2001:db8::2'))

    def test_tcp_positive_no_response_unreachable_and_error(self):
        target = Target('127.0.0.1', ('lab.test',))
        config = ScanConfig('lab.test', (80,), rate=10000)
        for state, reason, expected in [('open', 'connection_succeeded', 'up'),
                ('closed', 'connection_refused', 'up'), ('unknown', 'timeout', 'no_response'),
                ('error', 'routing_failure', 'unreachable'), ('error', 'permission_denied', 'error')]:
            result = new_result(config, None, 80)
            result.state, result.reason = state, reason
            with patch('scanix.modules.discovery.scan_single_port', return_value=result):
                observed = discover_host(target, ('tcp',), (80,), config, threading.Event())
            self.assertEqual(observed['state'], expected)
            self.assertEqual(observed['evidence'][0]['reason'], reason)

    def test_routed_arp_never_transmits(self):
        transport = MagicMock(source='127.0.0.1', gateway='127.0.0.254', iface='lab0')
        with patch('scanix.modules.transport.PacketTransport') as factory, \
             patch('scapy.all.get_if_hwaddr', return_value='02:00:00:00:00:01'):
            factory.return_value.__enter__.return_value = transport
            result = discover_host(Target('127.0.0.2', ('127.0.0.2',)), ('arp',), (80,),
                                   ScanConfig('lab', (80,)), threading.Event())
        transport.exchange.assert_not_called()
        self.assertEqual(result['state'], 'error')
        self.assertEqual(result['evidence'][0]['reason'], 'routed_target_not_on_link')

    def test_discovery_scheduler_window_worker_failure_and_cancellation(self):
        plan = ScopePlan(['127.0.0.0/29'])
        outstanding, peak = 0, 0
        stop = threading.Event()
        class Tracked(Future):
            def result(inner):
                nonlocal outstanding
                outstanding -= 1
                return super().result()
        class Executor:
            def __init__(inner, max_workers):
                self.assertEqual(max_workers, 2)
            def __enter__(inner):
                return inner
            def __exit__(inner, *_):
                pass
            def submit(inner, fn, target, *args):
                nonlocal outstanding, peak
                outstanding += 1
                peak = max(peak, outstanding)
                future = Tracked()
                if target.ip.endswith('.1'):
                    future.set_exception(RuntimeError('broken worker'))
                else:
                    future.set_result({'ip': target.ip, 'state': 'no_response', 'evidence': []})
                return future
            def shutdown(inner, **kwargs):
                pass
        with patch('scanix.modules.discovery.ThreadPoolExecutor', Executor):
            output = discover_targets(plan, ('tcp',), (80,), ScanConfig('lab', (80,), concurrency=2))
        self.assertEqual(peak, 2)
        self.assertEqual(outstanding, 0)
        self.assertEqual(output['completed_hosts'], 6)
        self.assertEqual(output['completion_status'], 'failed')
        self.assertEqual(output['hosts'][0]['evidence'][0]['reason'], 'worker_exception')
        def probe(target, methods, ports, config, stop, runtime):
            stop.set()
            return {'ip': target.ip, 'state': 'no_response', 'evidence': []}
        with patch('scanix.modules.discovery.discover_host', side_effect=probe):
            output = discover_targets(plan, ('tcp',), (80,), ScanConfig('lab', (80,), concurrency=1), stop)
        self.assertEqual(output['completion_status'], 'interrupted')
        self.assertEqual(output['completed_hosts'], 1)

    def test_discovery_cli_legacy_alias_preview_and_partial_scope(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(run_cli(['discover', '-n', '127.0.0.0/30', '--methods', 'arp', '--preview']), 0)
        self.assertEqual(json.loads(stdout.getvalue())['effective_target_count'], 2)
        from scanix.core.scope_scan import scan_scope
        plan = ScopePlan(['127.0.0.1'])
        with patch('scanix.modules.discovery.discover_host', return_value={'state': 'no_response'}), \
             patch('scanix.core.scope_scan.scan_target') as scan:
            report = scan_scope(ScanConfig('lab', (80,)), plan, discovery_methods=('tcp',))
        scan.assert_not_called()
        self.assertTrue(report.to_dict()['incomplete'])
        self.assertEqual(report.to_dict()['requested_ports'], 1)
