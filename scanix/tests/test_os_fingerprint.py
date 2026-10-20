"""Original synthetic packet fixtures, no privileged or public-network dependency."""
from copy import deepcopy
from dataclasses import replace
from io import StringIO
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch

from scapy.all import IP, IPv6, TCP
from scanix.core.models import ScanConfig, ScanReport, ScanResult, ResolvedTarget
from scanix.core.os_fingerprint import (annotate, database, guess_os_from_ttl, identify,
                                        tcp_features, validate_database)
from scanix.modules.packets import classify_syn, syn_probe


def packet(probe=None, **changes):
    probe=probe or syn_probe('192.0.2.1','192.0.2.2',8080)
    net=IPv6(src=probe.dst,dst=probe.src,hlim=64) if isinstance(probe,IPv6) else IP(src=probe.dst,dst=probe.src,ttl=64,flags='DF')
    fields=dict(sport=8080,dport=probe.payload.sport,seq=123,ack=(probe.payload.seq+1)%2**32,
                flags='SA',window=64240,options=[('MSS',1460)])
    fields.update(changes)
    return probe,net/TCP(**fields)


class RemoteFingerprintTests(unittest.TestCase):
    def test_correlated_capture_multiple_signals_and_default_disabled(self):
        probe,reply=packet()
        self.assertNotIn('remote_tcp',classify_syn(probe,reply).details)
        found=classify_syn(probe,reply,os_evidence=True)
        self.assertEqual(found.state,'open')
        features=found.details['remote_tcp']
        self.assertEqual((features['observed_hop_limit'],features['tcp_window'],features['mss']),(64,64240,1460))
        self.assertEqual(features['source'],'matched_remote_syn_ack')
        detection=identify(features)
        self.assertEqual(detection['status'],'experimental_match')
        self.assertEqual(detection['confidence'],'experimental')
        self.assertGreaterEqual(len(detection['candidates'][0]['matched_signals']),4)
        self.assertIsNone(detection['candidates'][0]['version'])
        self.assertFalse(detection['authenticated'])

    def test_ttl_alone_and_conflicting_signals_are_inconclusive(self):
        probe,reply=packet();features=classify_syn(probe,reply,os_evidence=True).details['remote_tcp']
        for ttl in range(256):self.assertIsNone(guess_os_from_ttl(ttl))
        for features in (None,{'observed_hop_limit':64}, {**features,'tcp_window':8192},
                         {**features,'dont_fragment':False},{**features,'observed_hop_limit':128},
                         {**features,'mss':1400},{**features,'option_kinds':[2,1]}):
            with self.subTest(features=features):
                self.assertEqual(identify(features)['status'],'inconclusive')
                self.assertEqual(identify(features)['candidates'],[])

    def test_mismatches_and_closed_do_not_collect_OS_evidence(self):
        probe,reply=packet()
        for change in (dict(ack=0),dict(dport=80),dict(sport=80)):
            _,wrong=packet(probe,**change)
            self.assertIsNone(classify_syn(probe,wrong,os_evidence=True))
        _,closed=packet(probe,flags='RA')
        self.assertNotIn('remote_tcp',classify_syn(probe,closed,os_evidence=True).details)
        reply.src=probe.src
        self.assertIsNone(classify_syn(probe,reply,os_evidence=True))

    def test_ipv6_captured_but_no_supported_fingerprint(self):
        probe=syn_probe('2001:db8::1','2001:db8::2',8080)
        probe,reply=packet(probe)
        features=classify_syn(probe,reply,os_evidence=True).details['remote_tcp']
        self.assertEqual(features['ip_version'],6)
        self.assertIsNone(features['dont_fragment'])
        self.assertEqual(identify(features)['reason'],'unsupported_fingerprint_family')

    def test_option_order_bounds_and_no_uptime_values(self):
        header=bytes(TCP(flags='SA',window=64240,options=[('MSS',1460),('NOP',None),('WScale',7),('SAckOK',b''),('Timestamp',(12345,67890))]))
        features=tcp_features(4,64,True,header)
        self.assertEqual(features['option_kinds'][:5],[2,1,3,4,8])
        self.assertEqual(features['window_scale'],7)
        self.assertTrue(features['timestamps'])
        self.assertNotIn('12345',json.dumps(features))
        self.assertNotIn('67890',json.dumps(features))
        self.assertIsNone(tcp_features(4,64,True,header*2))
        bad=bytearray(header);bad[21]=0
        self.assertIsNone(tcp_features(4,64,True,bytes(bad)))
        bad=bytearray(header);bad[12]=0xf0
        self.assertIsNone(tcp_features(4,64,True,bytes(bad)))

    def test_duplicate_malformed_and_unknown_options(self):
        for options in ([('MSS',1460),('MSS',1400)],[('WScale',15)],[('SAckOK',b''),('SAckOK',b'')]):
            header=bytes(TCP(flags='SA',options=options))
            self.assertIsNone(tcp_features(4,64,True,header))
        for length in range(20):self.assertIsNone(tcp_features(4,64,True,b'\0'*length))
        for bad in (0,256,True):self.assertIsNone(tcp_features(4,bad,True,bytes(TCP(flags='SA'))))
        header=bytes(TCP(flags='SA',options=[(30,b'xx')]))
        self.assertIn(30,tcp_features(4,64,True,header)['option_kinds'])

    def test_registry_validation_and_conflicts(self):
        base=deepcopy(database())
        for bad in (None,{}, {**base,'schema_version':True},{**base,'profiles':[]},
                    {**base,'profiles':[{'id':'arbitrary/module'}]}):
            with self.assertRaises(ValueError):validate_database(bad)
        other=deepcopy(base['profiles'][0]);other['id']+='-conflict';base['profiles'].append(other)
        probe,reply=packet();features=classify_syn(probe,reply,os_evidence=True).details['remote_tcp']
        self.assertEqual(identify(features,registry=base)['reason'],'conflicting_profiles')
        self.assertEqual(identify(features,registry=base)['candidates'],[])

    def test_failed_enrichment_preserves_observed_open(self):
        result=ScanResult('synthetic','192.0.2.2','IPv4',8080,state='open')
        with patch('scanix.core.os_fingerprint.database',side_effect=ValueError('synthetic')):
            annotate(result)
        self.assertEqual(result.state,'open');self.assertIsNone(result.os)
        self.assertEqual(result.evidence['os_detection']['status'],'error')

    def test_raw_integration_no_additional_probes_and_partial_export(self):
        from scanix.modules.raw_scan import raw_scan_port
        from scanix.output.save_json import save_json
        probe,reply=packet()
        evidence=classify_syn(probe,reply,os_evidence=True)
        config=ScanConfig('192.0.2.2',(8080,),method='syn',os_detect=True)
        with patch('scanix.modules.raw_scan.PacketTransport') as factory:
            transport=factory.return_value.__enter__.return_value
            transport.source='192.0.2.1';transport.exchange.return_value=(evidence,reply,.01)
            result=raw_scan_port(config,ResolvedTarget('192.0.2.2'),8080,threading.Event())
        self.assertEqual(transport.exchange.call_count,1)
        self.assertEqual(transport.send.call_count,1)  # Existing successful-probe reset only.
        self.assertEqual(result.evidence['os_detection']['status'],'experimental_match')
        self.assertIsNone(result.os)
        with tempfile.TemporaryDirectory() as temp:
            file=Path(temp)/'synthetic.json';save_json(ScanReport(config,[result],completion_status='interrupted'),file)
            data=json.loads(file.read_text())
            self.assertTrue(data['incomplete']);self.assertEqual(data['results'][0]['evidence']['remote_tcp']['source'],'matched_remote_syn_ack')

    def test_cli_preview_and_unsupported_engine_methods_before_traffic(self):
        from scanix.cli import run_cli
        output=StringIO()
        with patch('sys.stdout',output),patch('socket.socket',side_effect=AssertionError('traffic')):
            code=run_cli(['scan','-t','192.0.2.2','-p','8080','--syn','--os-detect','--preview'])
        self.assertEqual(code,0);self.assertTrue(json.loads(output.getvalue())['os_detection']['enabled'])
        for engine,method in (('native','syn'),('python','connect'),('python','udp')):
            with self.assertRaises(ValueError):ScanConfig('192.0.2.2',(8080,),engine=engine,method=method,os_detect=True)

    def test_all_exports_and_console_preserve_experimental_qualification(self):
        from scanix.output.save_csv import save_csv
        from scanix.output.save_html import save_html
        from scanix.output.save_json import save_json
        from scanix.cli import run_cli
        probe,reply=packet();features=classify_syn(probe,reply,os_evidence=True).details['remote_tcp']
        cfg=ScanConfig('192.0.2.2',(8080,),method='syn',os_detect=True)
        row=ScanResult('synthetic','192.0.2.2','IPv4',8080,state='open',evidence={'remote_tcp':features})
        annotate(row);report=ScanReport(cfg,[row])
        with tempfile.TemporaryDirectory() as temp:
            for export,suffix in ((save_csv,'csv'),(save_html,'html'),(save_json,'json')):
                file=Path(temp)/('synthetic.'+suffix);export(report,file)
                text=file.read_text();self.assertIn('experimental_match',text);self.assertIn('Linux-compatible',text)
        output=StringIO()
        with patch('sys.stdout',output),patch('scanix.cli.scan_target',return_value=report),patch('socket.socket',side_effect=AssertionError('unexpected traffic')):
            code=run_cli(['scan','-t','192.0.2.2','-p','8080','--syn','--os-detect'])
        self.assertEqual(code,0);self.assertIn('experimental_match',output.getvalue())
        self.assertIn('[experimental]',output.getvalue());self.assertIsNone(row.os)

    def test_database_content_changes_checkpoint_identity(self):
        from scanix.native.checkpoint import implementation_digest, file_digest
        original=implementation_digest()
        def changed(filename,limit=64*1024*1024):
            return 'synthetic different fingerprint database' if Path(filename).name=='os-fingerprints-v1.json' else file_digest(filename,limit)
        with patch('scanix.native.checkpoint.file_digest',side_effect=changed):
            self.assertNotEqual(implementation_digest(),original)

    def test_cancellation_retains_completed_remote_evidence(self):
        from concurrent.futures import CancelledError
        from scanix.modules.raw_scan import raw_scan_port
        probe,reply=packet();evidence=classify_syn(probe,reply,os_evidence=True)
        config=ScanConfig('192.0.2.2',(8080,),method='syn',os_detect=True)
        stop=threading.Event()
        def matched(*args):stop.set();return evidence,reply,.01
        with patch('scanix.modules.raw_scan.PacketTransport') as factory:
            transport=factory.return_value.__enter__.return_value
            transport.source='192.0.2.1';transport.exchange.side_effect=matched
            transport.send.side_effect=CancelledError()
            result=raw_scan_port(config,ResolvedTarget('192.0.2.2'),8080,stop)
        self.assertEqual(result.state,'open');self.assertFalse(result.evidence['reset_sent'])
        self.assertEqual(result.evidence['os_detection']['status'],'experimental_match')
