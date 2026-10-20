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

HELLO={'type':'hello','protocol':3,'engine':'scanix-rust','engine_version':'0.4.2','capabilities':['connect']}
ROW={'type':'result','id':0,'target_index':0,'ip':'127.0.0.1','port':443,
     'state':'open','reason':'connection_succeeded','error_code':None,'elapsed_seconds':.001}
DONE={'type':'done','status':'complete','requested':1,'completed':1,'attempted':1,'peak_outstanding':1,'elapsed_seconds':.01,'reason':None}


@contextmanager
def fake_engine(frames, *, code=0, delay=0, raw=None, stderr=''):
    with tempfile.TemporaryDirectory() as folder:
        script=Path(folder)/'engine.py'
        lines=[json.dumps(frame)+'\n' for frame in frames]
        first=lines[0] if lines else (raw or '')
        rest=''.join(lines[1:]) if lines else ''
        script.write_text('import sys,time,json\n'+
            'sys.stdout.write('+repr(first)+');sys.stdout.flush()\n'+
            ('for line in sys.stdin:\n if json.loads(line)["type"]=="run":break\n' if lines else '')+
            'sys.stdout.write('+repr(rest)+');sys.stdout.flush()\n'+
            'sys.stderr.write('+repr(stderr)+');sys.stderr.flush()\n'+
            'time.sleep('+repr(delay)+')\nsys.exit('+str(code)+')\n')
        real=subprocess.Popen
        sent=[]
        def launch(*args,**kwargs):
            process=real([sys.executable,str(script)],**kwargs)
            stream=process.stdin
            class ObservedInput:
                def write(self,data):
                    sent.append(bytes(data))
                    return stream.write(data)
                def close(self):stream.close()
            process.stdin=ObservedInput()
            return process
        with patch('scanix.native.adapter.subprocess.Popen',side_effect=launch):
            yield sent


class NativeWireTests(unittest.TestCase):
    def config(self,**kw):return ScanConfig('127.0.0.1',(443,),engine='native',**kw)
    def scan(self,**kw):return scan_native(self.config(),ScopePlan(['127.0.0.1']),binary='fixture',**kw)
    def test_selected_ids_stream_without_retaining_results(self):
        from scanix.native.selection import Selection
        cfg=ScanConfig('127.0.0.1',(80,443),engine='native')
        row={**ROW,'id':1}
        selection=Selection(2,1,2)
        observed=[]
        with fake_engine([HELLO,{'type':'ready','requested':1},row,DONE]) as sent:
            report=scan_native(cfg,ScopePlan(['127.0.0.1']),binary='fixture',selection=selection,
                               on_result=observed.append,retain=False)
        self.assertEqual(report.completion_status,'complete')
        self.assertFalse(report.results);self.assertEqual(len(observed),1)
        self.assertEqual(report.to_dict()['completed_ports'],1)
        self.assertFalse(report.to_dict()['incomplete'])
        self.assertEqual(json.loads(sent[0])['shard_index'],1)
        # An unselected, otherwise valid response cannot be exported.
        with fake_engine([HELLO,{'type':'ready','requested':1},{**ROW,'port':80},DONE]):
            report=scan_native(cfg,ScopePlan(['127.0.0.1']),binary='fixture',selection=selection,retain=False)
        self.assertEqual(report.completion_status,'failed');self.assertEqual(report.completed_probes,0)

    def test_inline_exporters_reject_nonretained_summaries_without_writing_files(self):
        from scanix.output.save_json import save_json
        from scanix.output.save_csv import save_csv
        from scanix.output.save_html import save_html
        with fake_engine([HELLO,{'type':'ready','requested':1},ROW,DONE]):
            report=scan_native(self.config(),ScopePlan(['127.0.0.1']),binary='fixture',retain=False)
        with tempfile.TemporaryDirectory() as folder:
            for name,save in [('json',save_json),('csv',save_csv),('html',save_html)]:
                path=Path(folder)/('synthetic.'+name)
                with self.assertRaises(ValueError):save(report,path)
                self.assertFalse(path.exists())

    def test_nonretained_permission_failure_keeps_failed_semantics(self):
        row={**ROW,'state':'error','reason':'permission_denied','error_code':13}
        with fake_engine([HELLO,{'type':'ready','requested':1},row,DONE]):
            report=scan_native(self.config(),ScopePlan(['127.0.0.1']),binary='fixture',retain=False)
        self.assertEqual(report.completion_status,'failed');self.assertEqual(report.completed_probes,1)
        self.assertFalse(report.results)

    def test_resume_registration_is_bounded_and_completed_ids_rejected(self):
        from scanix.native.selection import Selection
        selected=Selection(1,completed=bytes([1]))
        done={**DONE,'requested':0,'completed':0,'attempted':0,'peak_outstanding':0}
        with fake_engine([HELLO,{'type':'ready','requested':0},done]) as sent:
            report=scan_native(self.config(),ScopePlan(['127.0.0.1']),binary='fixture',selection=selected,retain=False)
        self.assertEqual(report.completion_status,'complete')
        self.assertIn({'type':'completed','ids':[0]},[json.loads(frame) for frame in sent])
        with fake_engine([HELLO,{'type':'ready','requested':0},ROW,done]):
            report=scan_native(self.config(),ScopePlan(['127.0.0.1']),binary='fixture',selection=selected,retain=False)
        self.assertEqual(report.completion_status,'failed')

    def test_valid_stream_and_export_metadata(self):
        with fake_engine([HELLO,{'type':'ready','requested':1},ROW,DONE]):report=self.scan()
        self.assertEqual(report.completion_status,'complete');self.assertEqual(report.results[0].state,'open')
        self.assertEqual(report.implementation['engine'],'native')
        self.assertEqual(report.implementation['engine_version'],'0.4.2')
        self.assertEqual(report.to_dict()['schema_version'],5)
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

    def test_handshake_rejection_precedes_scope_transmission(self):
        for hello in ({**HELLO,'protocol':True},{**HELLO,'protocol':999},
                      {**HELLO,'capabilities':['syn']}):
            with self.subTest(hello=hello),fake_engine([hello]) as sent:
                report=self.scan()
            self.assertEqual(report.completion_status,'failed')
            self.assertFalse(sent,'scope/start sent to incompatible peer')

    def test_deep_json_and_extreme_numeric_values_fail_privately(self):
        with self.assertRaises(ValueError):_decode(b'{"a":'+b'['*2000+b'0'+b']'*2000+b'}')
        for row in ({**ROW,'elapsed_seconds':10**1000},{**ROW,'ip':2130706433}):
            with self.subTest(field='numeric boundary'),fake_engine([HELLO,{'type':'ready','requested':1},row,DONE]):
                report=self.scan()
            self.assertEqual(report.completion_status,'failed')
            self.assertFalse(report.results)

    def test_no_stderr_or_extra_completion_payload_is_exported(self):
        marker='synthetic-private-diagnostic-marker'
        with fake_engine([HELLO,{'type':'ready','requested':1},ROW,{**DONE,'unexpected':marker}],stderr=marker*1000):
            report=self.scan()
        self.assertEqual(report.completion_status,'complete')
        self.assertNotIn(marker,json.dumps(report.to_dict()))
        issue=next(x for x in report.issues if x['reason']=='native_stderr')
        self.assertEqual(issue['bytes_drained'],len(marker)*1000)

    def test_partial_native_exports_keep_results_and_implementation(self):
        from scanix.output.save_json import save_json
        from scanix.output.save_csv import save_csv
        from scanix.output.save_html import save_html
        with fake_engine([HELLO,{'type':'ready','requested':1},ROW,{**DONE,'completed':0}]):
            report=self.scan()
        with tempfile.TemporaryDirectory() as folder:
            for extension,save in [('json',save_json),('csv',save_csv),('html',save_html)]:
                output=Path(folder)/('partial.'+extension);save(report,output)
                self.assertIn('native',output.read_text())
            data=json.loads((Path(folder)/'partial.json').read_text())
            self.assertTrue(data['incomplete']);self.assertEqual(data['results'][0]['state'],'open')

    def test_scope_pair_ceiling_rejects_before_process_start(self):
        config=ScanConfig('127.0.0.0/23',tuple(range(1,4097)),engine='native')
        with patch('subprocess.Popen',side_effect=AssertionError('process started')):
            report=scan_native(config,ScopePlan(['127.0.0.0/23']))
        self.assertEqual(report.completion_status,'failed')
        self.assertFalse(report.results)
        self.assertGreater(report.requested_probes,1_000_000)

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
        for kw in ({'method':'udp'},{'banner':True},{'engine_timeout':float('nan')}):
            with self.subTest(kw=kw),self.assertRaises(ValueError):self.config(**kw)
        with self.assertRaises(ValueError):scan_target(self.config())
        with self.assertRaises(ValueError):ScanConfig('127.0.0.1',tuple(range(1,4098)),engine='native')


class NativeSynWireTests(unittest.TestCase):
    def scan(self,row,done=None,**options):
        hello={**HELLO,'capabilities':['connect','syn_ipv4']}
        metrics={**DONE,'syn_sent':1,'retries_sent':0,'resets_sent':int(row['state']=='open'),
                 'send_errors':0,'capture_drops':0,'queue_drops':0,**(done or {})}
        config=ScanConfig('127.0.0.1',(443,),engine='native',method='syn')
        with patch('scanix.native.adapter.sys.platform','linux'),fake_engine([hello,{'type':'ready','requested':1},row,metrics],**options):
            return scan_native(config,ScopePlan(['127.0.0.1']),binary='fixture')
    def row(self,state='open',reason='syn_ack',**kw):
        return {**ROW,'state':state,'reason':reason,'attempts':1,
                'evidence':{'matched_response':True,'icmp_code':None,'reset_sent':state=='open','reset_error_code':None},**kw}
    def test_positive_states_and_no_response_retry_evidence(self):
        rows=[self.row(),self.row('closed','syn_rst_ack'),
              self.row('filtered','icmp_administratively_prohibited',evidence={'matched_response':True,'icmp_code':13,'reset_sent':False}),
              self.row('unknown','icmp_unreachable_or_path_error',evidence={'matched_response':True,'icmp_code':1,'reset_sent':False})]
        for row in rows:
            with self.subTest(state=row['state']):
                report=self.scan(row);self.assertEqual(report.completion_status,'complete',report.issues)
                self.assertEqual(report.results[0].state,row['state']);self.assertEqual(report.results[0].probe_type,'syn')
        row=self.row('unknown','no_response',attempts=2,evidence={'matched_response':False,'icmp_code':None,'reset_sent':False})
        report=self.scan(row,{'syn_sent':2,'retries_sent':1})
        self.assertEqual(report.completion_status,'complete',report.issues);self.assertEqual(report.results[0].attempts,2)
    def test_false_evidence_and_raw_metrics_fail_closed(self):
        cases=[(self.row(attempts=0),{}),
               (self.row('unknown','no_response',evidence={'matched_response':False,'reset_sent':False}),{}),(self.row(evidence={'matched_response':False,'reset_sent':True}),{}),
               (self.row(),{'capture_drops':'synthetic-private-marker'}),(self.row(),{'capture_drops':1}),
               (self.row(),{'syn_sent':True}),(self.row('open','no_response'),{}),
               (self.row('filtered','icmp_administratively_prohibited',evidence={'matched_response':True,'icmp_code':1,'reset_sent':False}),{})]
        for row,metrics in cases:
            with self.subTest(kind='invalid evidence'):
                report=self.scan(row,metrics);self.assertEqual(report.completion_status,'failed')
                self.assertNotIn('synthetic-private-marker',json.dumps(report.to_dict()))
    def test_setup_cancellation_preserves_scope_without_requiring_capture_metrics(self):
        hello={**HELLO,'capabilities':['connect','syn_ipv4']}
        done={**DONE,'status':'interrupted','requested':0,'completed':0,'attempted':0,
              'peak_outstanding':0,'reason':'cancelled_during_setup'}
        config=ScanConfig('127.0.0.1',(443,),engine='native',method='syn')
        with patch('scanix.native.adapter.sys.platform','linux'),fake_engine([hello,done],code=130):
            report=scan_native(config,ScopePlan(['127.0.0.1']),binary='fixture')
        self.assertEqual(report.completion_status,'interrupted');self.assertFalse(report.issues)
        self.assertEqual(report.requested_probes,1);self.assertFalse(report.results)
    def test_retry_failure_preserves_observed_open(self):
        row=self.row(attempts=2,evidence={'matched_response':True,'icmp_code':None,'reset_sent':True,'send_error_code':13})
        report=self.scan(row,{'status':'failed','reason':'transmission_failure','send_errors':1},code=3)
        self.assertEqual(report.completion_status,'failed');self.assertEqual(report.results[0].state,'open')
        self.assertEqual(report.results[0].evidence['send_error_code'],13)

    def test_capture_loss_retains_positive_port(self):
        report=self.scan(self.row(),{'status':'failed','reason':'capture_loss','capture_drops':1},code=3)
        self.assertEqual(report.completion_status,'failed');self.assertEqual(report.results[0].state,'open')
        self.assertEqual(report.implementation['metrics']['capture_drops'],1)
    def test_unsupported_platform_and_ipv6_fail_before_process(self):
        with patch('subprocess.Popen',side_effect=AssertionError('started')):
            for platform,address,family in [('darwin','127.0.0.1','4'),('win32','127.0.0.1','4'),('linux','::1','6')]:
                with self.subTest(platform=platform),patch('scanix.native.adapter.sys.platform',platform):
                    config=ScanConfig(address,(443,),engine='native',method='syn')
                    report=scan_native(config,ScopePlan([address],family=family))
                    self.assertEqual(report.completion_status,'failed');self.assertFalse(report.results)
                    self.assertIn({'reason':'native_syn_requires_linux_ipv4'},report.issues)


@unittest.skipUnless(os.environ.get('SCANIX_NATIVE_ENGINE'),'native integration: set SCANIX_NATIVE_ENGINE to built executable')
class NativeLoopbackTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform=='linux','native SYN backend is Linux-only')
    def test_syn_empty_scope_and_unprivileged_preflight(self):
        config=ScanConfig('127.0.0.1',(443,),engine='native',method='syn')
        empty=scan_native(config,ScopePlan(['127.0.0.1'],['127.0.0.1']))
        self.assertEqual(empty.completion_status,'complete',empty.issues)
        self.assertEqual(empty.implementation['metrics']['syn_sent'],0)
        caps=int(next(line.split()[1] for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('CapEff:')),16)
        if caps & (1<<13):self.skipTest('privileged SYN traffic belongs to isolated opt-in lab')
        report=scan_native(config,ScopePlan(['127.0.0.1']))
        self.assertEqual(report.completion_status,'failed')
        self.assertEqual(report.implementation['metrics']['syn_sent'],0)
        self.assertIn({'reason':'native_raw_privilege_required'},report.issues)

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

    def test_session_budget_limits_pacing_and_retains_completed_work(self):
        from scanix.tests.test_service_engine import lab,http
        with lab(http) as port:
            if port==65535:self.skipTest('ephemeral port leaves no higher comparison port')
            config=ScanConfig('127.0.0.1',(port,port+1),
                              engine='native',rate=.1,engine_timeout=.5,adaptive=False,timeout=5)
            started=time.monotonic()
            report=scan_native(config,ScopePlan(['127.0.0.1']))
        self.assertLess(time.monotonic()-started,4)
        self.assertEqual(report.completion_status,'failed',report.issues)
        metrics=report.implementation['metrics']
        self.assertEqual((metrics['requested'],metrics['attempted'],metrics['completed']),(2,1,1))
        self.assertEqual(metrics['reason'],'session_budget_exhausted')
        self.assertTrue(report.to_dict()['incomplete'])

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
