"""Unprivileged checks for lab isolation guards and independent capture validation."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from scapy.all import IP, TCP, UDP, Raw, Ether, ARP
from scanix.modules.packets import syn_probe, udp_probe

spec = importlib.util.spec_from_file_location('scanix_lab', Path(__file__).resolve().parents[2] / 'validation' / 'privileged_lab.py')
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class LabValidationTests(unittest.TestCase):
    def test_preflight_no_network_or_capture_on_unsupported_platform(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(lab.sys, 'platform', 'win32'), \
             patch.object(lab.subprocess, 'run') as process:
            output = Path(directory) / 'evidence'
            self.assertEqual(lab.main(['--output', str(output)]), 2)
            self.assertIn('unavailable', output.joinpath('results.json').read_text())
        process.assert_not_called()

    def test_refuses_existing_network_namespace_or_external_interface(self):
        with patch.object(lab.os, 'readlink', return_value='net:[1]'), self.assertRaises(RuntimeError):
            lab.assert_isolated('net:[1]', ('lo',))
        with patch.object(lab.os, 'readlink', return_value='net:[2]'), \
             patch.object(lab, 'command', return_value='[{"ifname":"lo"},{"ifname":"eth0"}]'), \
             self.assertRaises(RuntimeError):
            lab.assert_isolated('net:[1]', ('lo',))
        with patch.object(lab.os, 'readlink', return_value='net:[2]'), \
             patch.object(lab, 'command', side_effect=['[{"ifname":"lo"}]', 'default via 10.0.0.1']), \
             self.assertRaises(RuntimeError):
            lab.assert_isolated('net:[1]', ('lo',))

    def test_capture_requires_correlated_syn_reply_and_scanix_reset(self):
        probe = syn_probe(lab.V4[0], lab.V4[1], 19000)
        reply = IP(src=probe.dst, dst=probe.src)/TCP(sport=19000, dport=probe.payload.sport,
                    flags='SA', seq=42, ack=(probe.payload.seq+1) % 2**32)
        reset = IP(src=probe.src, dst=probe.dst)/TCP(sport=probe.payload.sport, dport=19000,
                    flags='RA', seq=reply.payload.ack, ack=43)
        case = {'name': 'syn', 'method': 'syn', 'target': lab.V4[1], 'port': 19000,
                'expected': 'open', 'attempts': 1}
        self.assertFalse(lab.capture_evidence([probe, reply], [case])[0]['passed'])
        self.assertTrue(lab.capture_evidence([probe, reply, reset], [case])[0]['passed'])
        reply.payload.ack ^= 1
        self.assertFalse(lab.capture_evidence([probe, reply, reset], [case])[0]['passed'])

    def test_capture_checks_silence_retry_count_and_udp_transaction(self):
        kind, probe = udp_probe(lab.V4[0], lab.V4[1], 53)
        case = {'name': 'dns', 'method': 'udp', 'target': lab.V4[1], 'port': 53,
                'expected': 'open|filtered', 'attempts': 2, 'probe_type': kind}
        self.assertFalse(lab.capture_evidence([probe], [case])[0]['passed'])
        self.assertTrue(lab.capture_evidence([probe, probe.copy()], [case])[0]['passed'])
        response = bytearray(bytes(probe.payload.payload))
        response[2] |= 0x80
        reply = IP(src=probe.dst, dst=probe.src)/UDP(sport=53, dport=probe.payload.sport)/Raw(bytes(response))
        self.assertFalse(lab.capture_evidence([probe, probe.copy(), reply], [case])[0]['passed'])
        case.update(expected='open', attempts=1)
        self.assertTrue(lab.capture_evidence([probe, reply], [case])[0]['passed'])

    def test_routed_arp_requires_zero_outgoing_requests(self):
        case = {'name': 'routed', 'method': 'arp', 'target': lab.ROUTED[0], 'expected': 'error'}
        self.assertTrue(lab.capture_evidence([], [case])[0]['passed'])
        packet = Ether(src='02:00:00:00:00:01', dst='ff:ff:ff:ff:ff:ff')/ARP(op=1, psrc=lab.V4[0], pdst=lab.ROUTED[0])
        self.assertFalse(lab.capture_evidence([packet], [case])[0]['passed'])
