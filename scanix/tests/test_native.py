"""Protocol fixtures need no compiler; real native loopback tests are explicit CI coverage."""
from contextlib import contextmanager
from dataclasses import replace
from io import StringIO
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from scanix.core.models import ScanConfig
from scanix.core.targets import ScopePlan
from scanix.native.adapter import scan_native,_decode

HELLO={'type':'hello','protocol':1,'engine':'scanix-rust','engine_version':'0.4.0','capabilities':['connect']}
ROW={'type':'result','id':0,'target_index':0,'ip':'127.0.0.1','port':443,
     'state':'open','reason':'connection_succeeded','error_code':None,'elapsed_seconds':.001}
DONE={'type':'done','status':'complete','requested':1,'completed':1,'attempted':1,'peak_outstanding':1,'elapsed_seconds':.01,'reason':None}


@contextmanager
def fake_engine(frames, *, code=0, delay=0, raw=None):
    with tempfile.TemporaryDirectory() as folder:
        script=Path(folder)/'engine.py'
        lines=[json.dumps(frame)+'\n' for frame in frames]
        script.write_text('import sys,time,json\n'+
            'for line in sys.stdin:\n if json.loads(line)["type"]=="run":break\n'+
            'sys.stdout.write('+repr(raw if raw is not None else ''.join(lines))+');sys.stdout.flush()\n'+
            'time.sleep('+repr(delay)+')\nsys.exit('+str(code)+')\n')
        real=subprocess.Popen
        with patch('scanix.native.adapter.subprocess.Popen',side_effect=lambda *a,**kw:real([sys.executable,str(script)],**kw)):
            yield


class NativeWireTests(unittest.TestCase):
    def config(self,**kw):return ScanConfig('127.0.0.1',(443,),engine='native',**kw)
    def scan(self,**kw):return scan_native(self.config(),ScopePlan(['127.0.0.1']),binary='fixture',**kw)
    def test_valid_stream_and_export_metadata(self):
        with fake_engine([HELLO,{'type':'ready','requested':1},ROW,DONE]):report=self.scan()
        self.assertEqual(report.completion_status,'complete');self.assertEqual(report.results[0].state,'open')
        self.assertEqual(report.implementation['engine'],'native')
        self.assertEqual(report.implementation['engine_version'],'0.4.0')
        self.assertEqual(report.to_dict()['schema_version'],4)
        self.assertEqual(report.results[0].original_targets,('127.0.0.1',))
        self.assertFalse(report.to_dict()['incomplete'])

    def test_scope_duplicates_and_failure_preserve_completed_rows(self):
        for bad in ({**ROW,'ip':'127.0.0.2'},{**ROW,'port':444},{**ROW,'id':True},ROW):
            with self.subTest(bad=bad),fake_engine([HELLO,{'type':'ready','requested':1},ROW,bad,DONE]):
                report=self.scan()
                self.assertEqual(report.completion_status,'failed');self.assertEqual(len(report.results),1)
                self.assertEqual(report.results[0].state,'open');self.assertTrue(report.to_dict()['incomplete'])

    def test_incompatible_unsupported_and_contradictory_completion(self):
        cases=[([{**HELLO,'protocol':999}],0),([{**HELLO,'capabilities':['syn']}],0),
               ([HELLO,{'type':'ready','requested':2}],0),
               ([HELLO,{'type':'ready','requested':1},ROW,{**DONE,'completed':0}],0),
               ([HELLO,{'type':'ready','requested':1},ROW,DONE],3),
               ([HELLO,{'type':'ready','requested':1},ROW],0),
               ([HELLO,{'type':'diagnostic','code':'unsupported_method','fatal':True}],4)]
        for frames,code in cases:
            with self.subTest(frames=frames),fake_engine(frames,code=code):
                report=self.scan();self.assertEqual(report.completion_status,'failed');self.assertTrue(report.issues)

    def test_oversized_malformed_and_duplicate_json(self):
        for data in (b'{"type":"hello","type":"done"}\n',b'{"value":NaN}\n',b'[]\n'):
            with self.assertRaises(ValueError):_decode(data)
        with fake_engine([],raw='x'*65537+'\n'):
            report=self.scan();self.assertEqual(report.completion_status,'failed')

    def test_pre_cancel_and_missing_backend_never_fall_back(self):
        stop=threading.Event();stop.set()
        with patch('subprocess.Popen',side_effect=AssertionError('process started')):
            report=self.scan(stop=stop)
        self.assertEqual(report.completion_status,'interrupted');self.assertFalse(report.results)
        with patch('scanix.core.scanner.scan_single_port',side_effect=AssertionError('Python fallback')):
            report=scan_native(self.config(),ScopePlan(['127.0.0.1']),binary='/does-not-exist/scanix-engine')
        self.assertEqual(report.completion_status,'failed');self.assertFalse(report.results)

    def test_unresponsive_child_cancellation_is_bounded(self):
        stop=threading.Event();started=time.monotonic()
        with fake_engine([HELLO,{'type':'ready','requested':1},ROW],delay=10):
            report=self.scan(stop=stop,progress=lambda done,total:stop.set())
        self.assertLess(time.monotonic()-started,4)
        self.assertEqual(report.completion_status,'interrupted');self.assertEqual(report.results[0].state,'open')

    def test_cli_preview_and_explicit_backend_rejections(self):
        from scanix.cli import run_cli
        from scanix.core.scanner import scan_target
        output=StringIO()
        with patch('subprocess.Popen',side_effect=AssertionError('process')),patch('socket.socket',side_effect=AssertionError('traffic')),patch('sys.stdout',output):
            self.assertEqual(run_cli(['scan','-t','127.0.0.1','-p','443','--engine','native','--preview']),0)
        policy=json.loads(output.getvalue())['implementation']
        self.assertEqual(policy['engine'],'native');self.assertFalse(policy['fallback'])
        for kw in ({'method':'syn'},{'method':'udp'},{'banner':True},{'engine_timeout':float('nan')}):
            with self.subTest(kw=kw),self.assertRaises(ValueError):self.config(**kw)
        with self.assertRaises(ValueError):scan_target(self.config())


@unittest.skipUnless(os.environ.get('SCANIX_NATIVE_ENGINE'),'native integration: set SCANIX_NATIVE_ENGINE to built executable')
class NativeLoopbackTests(unittest.TestCase):
    def test_open_refused_and_python_agreement(self):
        from scanix.tests.test_service_engine import lab,http
        from scanix.core.scanner import scan_target
        with lab(http) as port:
            with socket.socket() as unused:unused.bind(('127.0.0.1',0));closed=unused.getsockname()[1]
            config=ScanConfig('127.0.0.1',tuple(sorted((port,closed))),engine='native',adaptive=False,timeout=5,rate=1000)
            native=scan_native(config,ScopePlan(['127.0.0.1']))
            python=scan_target(replace(config,engine='python'))
        self.assertEqual(native.completion_status,'complete',native.issues)
        self.assertEqual([(r.port,r.state,r.reason) for r in native.results],[(r.port,r.state,r.reason) for r in python.results])
        self.assertEqual({r.port:r.state for r in native.results},{port:'open',closed:'closed'})
        self.assertLessEqual(native.implementation['metrics']['peak_outstanding'],2)

    def test_exclusions_and_ipv6(self):
        from scanix.tests.test_service_engine import lab,http
        try:
            with socket.socket(socket.AF_INET6,socket.SOCK_STREAM) as probe:probe.bind(('::1',0))
        except OSError as exc:self.skipTest('IPv6 loopback unavailable: '+str(exc))
        with lab(http,family=socket.AF_INET6) as port:
            config=ScanConfig('::1',(port,),engine='native')
            report=scan_native(config,ScopePlan(['::1'],family='6'))
            excluded=scan_native(config,ScopePlan(['::1'],['::1'],family='6'))
        self.assertEqual(report.results[0].state,'open',report.issues)
        self.assertEqual(report.results[0].address_family,'IPv6')
        self.assertEqual(excluded.completion_status,'complete');self.assertFalse(excluded.results)
        self.assertEqual(excluded.implementation['metrics']['attempted'],0)

    def test_completed_results_retained_on_cancel(self):
        from scanix.tests.test_service_engine import lab,http
        with lab(http) as port:
            if port==65535:self.skipTest('ephemeral port leaves no higher comparison port')
            config=ScanConfig('127.0.0.1',(port,port+1),engine='native',rate=1)
            stop=threading.Event()
            report=scan_native(config,ScopePlan(['127.0.0.1']),stop,progress=lambda done,total:stop.set())
        self.assertEqual(report.completion_status,'interrupted',report.issues)
        self.assertEqual(report.results[0].state,'open');self.assertTrue(report.to_dict()['incomplete'])
        self.assertGreaterEqual(report.implementation['metrics']['completed'],1)

    def test_service_stage_uses_hostname_sni_and_retains_port(self):
        from scanix.tests.test_service_engine import lab,http,TLS
        name='lab.scanix.invalid'
        resolver=lambda *args:[(socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',0))]
        with lab(http,'trusted') as port:
            config=ScanConfig(name,(port,),engine='native',service_detect=True,tls_ca_file=str(TLS/'ca.pem'),rate=1000)
            report=scan_native(config,ScopePlan([name],resolver=resolver))
        self.assertEqual(report.results[0].state,'open',report.issues)
        tls=report.results[0].service_detection.tls[0]
        self.assertEqual((tls.sni,tls.verification),(name,'verified'))
        self.assertEqual(report.results[0].service_detection.observations[-1].service,'http')
