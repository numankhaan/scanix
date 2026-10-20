"""Synthetic and owned loopback fixtures; no public traffic or elevated privileges."""
from dataclasses import asdict, replace
from io import StringIO
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from scanix.core.models import ScanConfig, ScanReport, ScanResult, ResolvedTarget
from scanix.core.scanner import scan_target
from scanix.core.timing import Runtime
from scanix.service.models import ServiceEvidence
from scanix.plugins.engine import _validate, enrich_results, run_plugin
from scanix.plugins.registry import API_VERSION, PLUGINS, Plugin, permitted, policy, select
from scanix.tests.test_service_engine import TLS, lab, http


def row(port, protocol='tcp'):
    return ScanResult('127.0.0.1','127.0.0.1','IPv4',port,state='open',protocol=protocol,original_targets=('localhost',))


def run(port, name, protocol='tcp', **options):
    config=ScanConfig('127.0.0.1',(port,),plugins=(name,),rate=10000,method='udp' if protocol=='udp' else 'connect',**options)
    result=row(port,protocol)
    enrich_results([result],config,threading.Event(),Runtime(config))
    return result


class BuiltinTests(unittest.TestCase):
    def test_http_unusual_port_and_sensitive_headers(self):
        with lab(http) as port:
            result=run(port,'http')
        report=result.plugin_results[0]
        self.assertEqual(report['status'],'complete')
        self.assertEqual(report['observations'][0]['service'],'http')
        self.assertNotIn('hidden',json.dumps(report))
        self.assertEqual((report['attempts'],report['transmissions']),(1,1))
        self.assertEqual(result.state,'open')

    def test_ssh_passive_and_malformed(self):
        for payload, expected in ((b'SSH-2.0-TestSSH_1.2 lab\r\n','complete'),
                                  (b'HTTP/1.1 200 OK\r\n\r\n','unknown'),
                                  (b'SSH-2.0-truncated','unknown'),(b'x'*5000,'unknown')):
            seen=[]
            def handler(sock):
                sock.sendall(payload)
                try:seen.append(sock.recv(1024))
                except (ConnectionResetError, TimeoutError):seen.append(b'')  # Bounded truncation can reset unread data.
            with self.subTest(expected=expected), lab(handler) as port:
                report=run(port,'ssh').plugin_results[0]
            self.assertEqual(report['status'],expected)
            self.assertLessEqual(report['bytes_received'],4096)
            self.assertEqual(report['transmissions'],0)
            if len(payload)<=4096:self.assertEqual(seen,[b''])

    def test_tls_trust_sni_and_insecure_modes(self):
        for certificate, options, expected in (
            ('trusted',{'tls_ca_file':str(TLS/'ca.pem')},'verified'),
            ('selfsigned',{'tls_insecure':True},'disabled'),
            ('selfsigned',{},'failed'),
            ('trusted',{'tls_ca_file':str(TLS/'ca.pem'),'sni':'wrong.invalid'},'failed')):
            names=[]
            with self.subTest(mode=expected), lab(lambda sock:None,certificate=certificate,names=names) as port:
                report=run(port,'tls',**options).plugin_results[0]
            self.assertEqual(report['tls'][0]['verification'],expected)
            self.assertEqual(names,[options.get('sni','localhost')])
            self.assertEqual(report['status'],'error' if expected=='failed' else 'complete')

    def test_dns_correlated_nonstandard_port(self):
        for matching in (True,False):
            sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.bind(('127.0.0.1',0));sock.settimeout(3)
            def server():
                request,peer=sock.recvfrom(4096)
                reply=(request[:2] if matching else bytes(x^255 for x in request[:2]))+b'\x80\x00'+request[4:]
                sock.sendto(reply,peer)
            thread=threading.Thread(target=server);thread.start()
            try:
                result=run(sock.getsockname()[1],'dns',protocol='udp').plugin_results[0]
                self.assertEqual(result['status'],'complete' if matching else 'unknown')
            finally:
                thread.join(3);sock.close()

    def test_failed_enrichment_preserves_open_and_no_authentication(self):
        def malformed(sock):
            sock.recv(1024);sock.sendall(b'not HTTP\r\n')
        with lab(malformed) as port:
            result=run(port,'http')
        self.assertEqual(result.state,'open')
        self.assertEqual(result.plugin_results[0]['status'],'unknown')

    def test_scan_target_integration(self):
        with lab(http) as port:
            cfg=ScanConfig('127.0.0.1',(port,),plugins=('http',),rate=10000)
            report=scan_target(cfg,endpoint=ResolvedTarget('127.0.0.1'),originals=('localhost',))
        self.assertEqual(report.results[0].plugin_results[0]['status'],'complete')
        self.assertEqual(report.plugin_api_version,API_VERSION)
        self.assertEqual(report.schema_version,5)
        self.assertEqual(report.to_dict()['configuration']['plugins'],['http.info.v1'])

    def test_actual_cli_http_result_and_ipv6_fixture(self):
        from scanix.cli import run_cli
        for family,address in ((socket.AF_INET,'127.0.0.1'),(socket.AF_INET6,'::1')):
            if family==socket.AF_INET6 and not socket.has_ipv6:
                continue
            with self.subTest(family=family),lab(http,family=family) as port:
                output=StringIO()
                with patch('sys.stdout',output):
                    code=run_cli(['scan','-t',address,'--family','6' if family==socket.AF_INET6 else '4','-p',str(port),'--plugins','http','--rate','10000','--out','json','--out-file','-'])
                self.assertEqual(code,0)
                report=json.loads(output.getvalue())
                self.assertEqual(report['results'][0]['plugin_results'][0]['status'],'complete')
                self.assertEqual(report['plugin_api_version'],1)


class PolicyTests(unittest.TestCase):
    def test_selection_and_intrusive_contract(self):
        self.assertEqual(select('http,http.info.v1,tls'),('http.info.v1','tls.info.v1'))
        for bad in ('unknown','http,','../external.py'):
            with self.assertRaises(ValueError):select(bad)
        cfg=ScanConfig('127.0.0.1',(80,))
        intrusive=Plugin('synthetic.v1','http','tcp',('synthetic',),True)
        self.assertFalse(permitted(intrusive,cfg))
        self.assertTrue(permitted(intrusive,replace(cfg,allow_intrusive_plugins=True)))
        self.assertIn('not a sandbox',policy(cfg)['isolation'])

    def test_exclusions_transport_and_closed_before_spawn(self):
        cfg=ScanConfig('127.0.0.1',(9100,),plugins=('http','dns'))
        with patch('scanix.plugins.engine.subprocess.Popen') as spawn:
            result=row(9100)
            enrich_results([result],cfg,threading.Event(),Runtime(cfg))
            self.assertEqual([p['error'] for p in result.plugin_results],['sensitive_port','transport_mismatch'])
            result.state='closed';result.plugin_results=[]
            enrich_results([result],cfg,threading.Event(),Runtime(cfg))
            self.assertEqual(result.plugin_results,[])
            spawn.assert_not_called()

    def test_cancellation_and_partial_evidence(self):
        stop=threading.Event()
        with lab(lambda sock:time.sleep(.5)) as port:
            cfg=ScanConfig('127.0.0.1',(port,),plugins=('ssh',),plugin_timeout=5)
            result=row(port)
            timer=threading.Timer(.15,stop.set);timer.start()
            try:
                begin=time.monotonic();enrich_results([result],cfg,stop,Runtime(cfg))
                self.assertLess(time.monotonic()-begin,2)
            finally:timer.join()
        self.assertEqual(result.state,'open')
        self.assertEqual(result.plugin_results[0]['status'],'interrupted')
        self.assertIsNone(result.plugin_results[0]['attempts'])

    def test_shared_parent_pacing_and_timeout(self):
        class Limiter:
            def __init__(self):self.calls=0
            def acquire(self,stop,*,deadline):self.calls+=1
        limiter=Limiter()
        with lab(http) as port:
            cfg=ScanConfig('127.0.0.1',(port,),plugins=('http',))
            runtime=Runtime(cfg,limiter=limiter)
            result=run_plugin(row(port),cfg,threading.Event(),runtime,'http.info.v1',time.monotonic()+2)
        self.assertEqual(result['status'],'complete')
        self.assertEqual(limiter.calls,2)
        with lab(lambda sock:time.sleep(.4)) as port:
            result=run(port,'ssh',plugin_timeout=.1).plugin_results[0]
        self.assertIn(result['status'],('timeout','unknown'))

    def test_workers_and_endpoint_budget(self):
        cfg=ScanConfig('127.0.0.1',(80,),plugins=('http','tls','ssh'),service_workers=8,per_host=2)
        lock=threading.Lock();active=maximum=0
        def fake(row,config,stop,runtime,id,deadline):
            nonlocal active,maximum
            with lock:active+=1;maximum=max(active,maximum)
            time.sleep(.01)
            with lock:active-=1
            return {'plugin_id':id,'status':'complete'}
        with patch('scanix.plugins.engine.run_plugin',side_effect=fake):
            enrich_results([row(80) for _ in range(5)],cfg,threading.Event(),Runtime(cfg))
        self.assertEqual(maximum,2)

    def test_retain_completed_only_retry_interrupted(self):
        cfg=ScanConfig('127.0.0.1',(80,),plugins=('http','ssh'))
        result=row(80);result.plugin_results=[{'plugin_id':'http.info.v1','status':'complete'},{'plugin_id':'ssh.info.v1','status':'interrupted'}]
        with patch('scanix.plugins.engine.run_plugin',return_value={'plugin_id':'ssh.info.v1','status':'unknown'}) as probe:
            enrich_results([result],cfg,threading.Event(),Runtime(cfg))
        self.assertEqual(probe.call_count,1)
        self.assertEqual(len(result.plugin_results),2)

    def test_result_contract_counters_and_sanitization(self):
        report={'plugin_id':'ssh.info.v1','api_version':1,'registry_version':'1.0.0','status':'complete','error':None,
                'observations':[asdict(ServiceEvidence('ssh',confidence='protocol',evidence={'synthetic':'\x1b<script>'}))],'tls':[],'attempts':1,'transmissions':0,'bytes_received':32,'bytes_sent':0}
        valid=_validate(report,PLUGINS['ssh.info.v1'])
        self.assertNotIn('\x1b',str(valid))
        for bad in ({**report,'attempts':2},{**report,'api_version':2},{**report,'bytes_received':4097},{**report,'extra':1}):
            with self.assertRaises(ValueError):_validate(bad,PLUGINS['ssh.info.v1'])

    def test_exports_and_preview(self):
        from scanix.output.save_json import save_json
        from scanix.output.save_csv import save_csv
        from scanix.output.save_html import save_html
        result=row(80);result.plugin_results=[{'plugin_id':'http.info.v1','status':'complete','evidence':'<script>'}]
        cfg=ScanConfig('127.0.0.1',(80,),plugins=('http',))
        report=ScanReport(cfg,[result],plugin_api_version=1,plugin_registry_version='1.0.0')
        with tempfile.TemporaryDirectory() as temp:
            for function,suffix in ((save_json,'json'),(save_csv,'csv'),(save_html,'html')):
                path=Path(temp)/('synthetic.'+suffix);function(report,path)
                text=path.read_text();self.assertIn('http.info.v1',text)
                if suffix=='html':self.assertNotIn('<script>',text)
        from scanix.cli import run_cli
        output=StringIO()
        with patch('sys.stdout',output),patch('scanix.plugins.engine.subprocess.Popen') as spawn:
            run_cli(['scan','-t','127.0.0.1','-p','80','--plugins','http,tls','--preview'])
            spawn.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())['plugins']['api_version'],1)


class WorkerBoundaryTests(unittest.TestCase):
    def test_faulty_workers_are_bounded_and_redacted(self):
        import subprocess
        import sys
        real_popen=subprocess.Popen
        hello="print('{\"type\":\"hello\",\"api_version\":1,\"registry_version\":\"1.0.0\"}',flush=True)"
        cases=("print('{}',flush=True)",
               hello+";print('x'*40000,flush=True)",
               hello+";print('{\"type\":\"token\",\"id\":4}',flush=True)",
               hello+";print('{\"a\":1,\"a\":2}',flush=True)",
               "import time;time.sleep(10)")
        cfg=ScanConfig('127.0.0.1',(80,),plugins=('http',),plugin_timeout=.2)
        children=[]
        for code in cases:
            def spawn(args,**kwargs):
                child=real_popen([sys.executable,'-I','-u','-c',code],**kwargs)
                children.append(child);return child
            with self.subTest(case=cases.index(code)),patch('scanix.plugins.engine.subprocess.Popen',side_effect=spawn):
                started=time.monotonic()
                result=run_plugin(row(80),cfg,threading.Event(),Runtime(cfg),'http.info.v1',started+.3)
                self.assertIn(result['status'],('error','timeout'))
                self.assertLess(time.monotonic()-started,2)
                self.assertIsNotNone(children[-1].poll())
        self.assertFalse(any(t.name.startswith('plugin-reader') for t in threading.enumerate()))

    def test_expired_budget_has_no_spawn_and_oversized_request_fails(self):
        cfg=ScanConfig('127.0.0.1',(80,),plugins=('http',))
        with patch('scanix.plugins.engine.subprocess.Popen') as spawn:
            result=run_plugin(row(80),cfg,threading.Event(),Runtime(cfg),'http.info.v1',time.monotonic()-1)
            self.assertEqual(result['status'],'timeout')
            spawn.assert_not_called()
            huge=replace(cfg,tls_ca_file='x'*40000)
            result=run_plugin(row(80),huge,threading.Event(),Runtime(huge),'http.info.v1',time.monotonic()+1)
            self.assertEqual(result['error'],'request_limit')
            spawn.assert_not_called()

    def test_native_aggregate_plugin_integration(self):
        import os
        if not os.environ.get('SCANIX_NATIVE_ENGINE'):
            self.skipTest('set SCANIX_NATIVE_ENGINE for real native integration')
        from scanix.native.adapter import scan_native
        from scanix.core.targets import ScopePlan
        with lab(http) as port:
            cfg=ScanConfig('127.0.0.1',(port,),engine='native',plugins=('http',),rate=10000)
            report=scan_native(cfg,ScopePlan(['127.0.0.1']))
        self.assertEqual(report.completion_status,'complete',report.issues)
        self.assertEqual(report.results[0].plugin_results[0]['status'],'complete')
        self.assertEqual(report.plugin_registry_version,'1.0.0')
