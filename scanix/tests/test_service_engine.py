from contextlib import contextmanager
from dataclasses import replace
from io import StringIO
import json
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from scanix.core.models import ScanConfig, ScanReport, ScanResult, ResolvedTarget
from scanix.core.scanner import scan_target
from scanix.core.timing import RateLimiter, Runtime
from scanix.service.engine import Detector, enrich_results, policy, verification_name
from scanix.service.models import ServiceEvidence, DetectionReport

TLS=Path(__file__).with_name('fixtures')/'tls'


@contextmanager
def lab(handler, certificate=None, names=None, family=socket.AF_INET):
    """Ephemeral loopback listener only; bounded clients and timeout on every I/O."""
    listener=socket.socket(family,socket.SOCK_STREAM);listener.bind(('::1' if family==socket.AF_INET6 else '127.0.0.1',0));listener.listen(8);listener.settimeout(.05)
    port=listener.getsockname()[1];stop=threading.Event();children=[];errors=[]
    context=None
    if certificate:
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(TLS/(certificate+'.pem'),TLS/'server-TEST-ONLY.key')
        context.set_alpn_protocols(['http/1.1'])
        if names is not None:
            context.set_servername_callback(lambda sock,name,ctx: names.append(name))
    def client(sock):
        try:
            sock.settimeout(1)
            if context:
                sock=context.wrap_socket(sock,server_side=True)
            handler(sock)
        except (OSError,TimeoutError):
            pass  # Probe mismatch, verification rejection and early close are expected.
        except Exception as exc:
            errors.append(exc)
        finally:
            sock.close()
    def accept():
        while not stop.is_set():
            try:
                sock,_=listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            child=threading.Thread(target=client,args=(sock,));children.append(child);child.start()
    thread=threading.Thread(target=accept);thread.start()
    try:
        yield port
    finally:
        stop.set();thread.join(2);listener.close()
        for child in children:
            child.join(2)
        if errors:
            raise errors[0]


def detect(port, address='127.0.0.1', **options):
    config=ScanConfig(address,(port,),service_detect=True,rate=10000,**options)
    result=ScanResult(address,address,'IPv6' if ':' in address else 'IPv4',port,state='open',original_targets=(address,))
    Detector(result,config,threading.Event(),Runtime(config)).run()
    return result.service_detection


def http(sock):
    data=sock.recv(4096)
    if data.startswith(b'HEAD '):
        sock.sendall(b'HTTP/1.1 200 OK\r\nServer: LocalHTTP/1.2\r\nSet-Cookie: hidden\r\nContent-Length: 0\r\n\r\n')


class LocalIdentificationTests(unittest.TestCase):
    def test_http_on_unusual_port_and_plaintext_tls_mismatch(self):
        with lab(http) as port:
            evidence=detect(port)
        self.assertEqual(evidence.status,'identified')
        found=evidence.observations[-1]
        self.assertEqual((found.service,found.product,found.version,found.transport),('http','LocalHTTP','1.2','tcp'))
        self.assertNotIn('hidden',str(found.evidence))
        self.assertLessEqual(evidence.attempts,3)
        self.assertTrue(evidence.tls and evidence.tls[0].handshake=='failed')

    def test_ssh_nonstandard_port_no_authentication(self):
        seen=[]
        def ssh(sock):
            sock.sendall(b'SSH-2.0-OpenSSH_9.7 lab\r\n');seen.append(sock.recv(1024))
        with lab(ssh) as port:
            report=detect(port)
        self.assertEqual(report.observations[0].service,'ssh')
        self.assertEqual(report.observations[0].version,'9.7')
        self.assertEqual(seen,[b''])

    def test_ftp_smtp_pop_imap_deep(self):
        cases=(('ftp',b'220 (vsFTPd 3.0.5)\r\n',b'FEAT\r\n',b'211-Features\r\n UTF8\r\n211 End\r\n'),
               ('smtp',b'220 ready\r\n',b'EHLO scanix.invalid\r\n',b'250-lab\r\n250 HELP\r\n'),
               ('pop3',b'+OK Dovecot ready.\r\n',b'CAPA\r\n',b'+OK capabilities\r\nUIDL\r\n.\r\n'),
               ('imap',b'* OK Dovecot ready.\r\n',b'a001 CAPABILITY\r\n',b'* CAPABILITY IMAP4rev1\r\na001 OK done\r\n'))
        for protocol,greeting,command,response in cases:
            seen=[]
            def handler(sock):
                sock.sendall(greeting);seen.append(sock.recv(1024));sock.sendall(response)
            with self.subTest(protocol=protocol),lab(handler) as port:
                report=detect(port,service_profile='deep')
                self.assertEqual(report.observations[-1].service,protocol)
                self.assertEqual(report.observations[-1].confidence,'protocol')
                self.assertEqual(seen,[command])

    def test_udp_dns_on_unusual_port(self):
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.bind(('127.0.0.1',0));sock.settimeout(2)
        def respond():
            data,address=sock.recvfrom(512);sock.sendto(data[:2]+b'\x80'+data[3:],address)
        thread=threading.Thread(target=respond);thread.start()
        try:
            port=sock.getsockname()[1];config=ScanConfig('127.0.0.1',(port,),method='udp',service_detect=True,rate=10000)
            result=ScanResult('127.0.0.1','127.0.0.1','IPv4',port,protocol='udp',state='open')
            report=Detector(result,config,threading.Event(),Runtime(config)).run()
            self.assertEqual(report.observations[0].service,'dns')
        finally:
            thread.join(3);sock.close()

    def test_tls_ca_sni_ip_selfsigned_mismatch_expired(self):
        cases=(('trusted',{},True,'verified'),('trusted',{'sni':'lab.scanix.invalid'},True,'verified'),
               ('selfsigned',{},False,'failed'),('selfsigned',{'tls_insecure':True},True,'disabled'),
               ('trusted',{'sni':'wrong.invalid'},False,'failed'),('expired',{},False,'failed'))
        for certificate,options,success,verification in cases:
            names=[]
            if not options.get('tls_insecure'):
                options['tls_ca_file']=str(TLS/'ca.pem')
            with self.subTest(certificate=certificate,options=options),lab(http,certificate,names) as port:
                report=detect(port,**options)
                tls=report.tls[0]
                self.assertEqual(tls.verification,verification)
                self.assertEqual(tls.handshake=='succeeded',success)
                self.assertEqual(names,[options.get('sni')])
                if success:
                    self.assertEqual(report.observations[-1].service,'http')
                    self.assertEqual(report.observations[-1].transport,'tls')
                    self.assertTrue(tls.version and tls.cipher)
                    self.assertEqual(tls.alpn,'http/1.1')
                    self.assertIn('sha256',tls.certificate)
                    self.assertNotIn('notAfter',tls.certificate) if verification=='disabled' else self.assertIn('notAfter',tls.certificate)
                else:
                    self.assertFalse(report.observations)
                    self.assertEqual(report.attempts,2)  # passive greeting, then verified TLS; no downgrade

    def test_starttls_success_refusal_and_failed_upgrade(self):
        for mode in ('success','refusal','failed'):
            commands=[]
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(TLS/'trusted.pem',TLS/'server-TEST-ONLY.key')
            def smtp(sock):
                sock.sendall(b'220 lab.invalid ESMTP Postfix\r\n')
                commands.append(sock.recv(1024));sock.sendall(b'250-lab.invalid\r\n250 STARTTLS\r\n')
                commands.append(sock.recv(1024))
                if mode=='refusal':
                    sock.sendall(b'454 unavailable\r\n');return
                sock.sendall(b'220 Ready\r\n')
                if mode=='failed':
                    sock.sendall(b'no TLS here\r\n');return
                with context.wrap_socket(sock,server_side=True) as secured:
                    commands.append(secured.recv(1024));secured.sendall(b'250 lab.invalid\r\n')
            with self.subTest(mode=mode),lab(smtp) as port:
                report=detect(port,starttls=True,tls_ca_file=str(TLS/'ca.pem'))
                self.assertEqual(commands[:2],[b'EHLO scanix.invalid\r\n',b'STARTTLS\r\n'])
                if mode=='success':
                    self.assertEqual(report.tls[0].verification,'verified')
                    self.assertEqual(commands[2],b'EHLO scanix.invalid\r\n')
                    self.assertEqual(report.observations[-1].transport,'tls')
                else:
                    self.assertEqual(len(commands),2)
                    self.assertTrue(report.issues)
                    self.assertEqual(report.attempts,1)


class ResourceAndReportTests(unittest.TestCase):
    def test_guesses_not_confirmed_and_closed_not_enriched(self):
        result=ScanResult('lab','127.0.0.1','IPv4',22,service_name='ssh',detection_source='port_table',state='closed')
        config=ScanConfig('lab',(22,),service_detect=True)
        with patch('scanix.service.engine.Detector') as detector:
            enrich_results([result],config,threading.Event(),Runtime(config))
        detector.assert_not_called()
        self.assertIsNone(result.service_detection)
        self.assertEqual(result.service_name,'ssh')

    def test_excluded_printer_and_explicit_override(self):
        config=ScanConfig('127.0.0.1',(9100,),service_detect=True)
        result=ScanResult('lab','127.0.0.1','IPv4',9100,state='open')
        with patch.object(Detector,'tcp') as tcp:
            Detector(result,config,threading.Event(),Runtime(config)).run()
            tcp.assert_not_called()
            self.assertEqual(result.service_detection.status,'excluded')
            enabled=replace(config,allow_excluded_probes=True)
            Detector(result,enabled,threading.Event(),Runtime(enabled)).run()
            tcp.assert_called_once()
        self.assertEqual(result.state,'open')

    def test_timeout_silence_malformed_and_oversized_preserve_open(self):
        for payload in (b'', b'not a service\x1b\r\n', b'x'*20000):
            def slow(sock):
                if payload:
                    sock.sendall(payload)
                time.sleep(.25)
            with self.subTest(length=len(payload)),lab(slow) as port:
                started=time.monotonic();report=detect(port,service_timeout=.15)
                self.assertLess(time.monotonic()-started,.6)
                self.assertFalse(report.observations)
                self.assertLessEqual(report.bytes_received,8192)
                self.assertLessEqual(report.attempts,3)
                self.assertLessEqual(report.transmissions,6)

    def test_pacing_deadline_and_deterministic_rate(self):
        class Clock:
            now=0.
            def clock(self):return self.now
            def sleep(self,seconds):self.now+=seconds
        clock=Clock();limiter=RateLimiter(2,clock.clock,clock.sleep);stop=threading.Event()
        limiter.acquire(stop);limiter.acquire(stop)
        self.assertAlmostEqual(clock.now,.5)
        with self.assertRaises(TimeoutError):
            limiter.acquire(stop,deadline=.6)
        self.assertAlmostEqual(clock.now,.6)
        # A lower global rate cannot trap the next service behind the previous waiter.
        limiter=RateLimiter(.01);limiter.acquire(stop)
        config=ScanConfig('127.0.0.1',(22,),service_detect=True,service_timeout=.1)
        result=ScanResult('lab','127.0.0.1','IPv4',22,state='open')
        started=time.monotonic();Detector(result,config,stop,Runtime(config,limiter)).run()
        self.assertLess(time.monotonic()-started,.5)
        self.assertEqual(result.state,'open')
        self.assertEqual(result.service_detection.attempts,0)

    def test_bounded_workers_cancellation_and_worker_failure(self):
        config=ScanConfig('lab',tuple(range(10000,10010)),service_detect=True,service_workers=4,per_host=2)
        results=[ScanResult('lab','127.0.0.1','IPv4',p,state='open') for p in config.ports]
        stop=threading.Event();lock=threading.Lock();active=peak=completed=0
        def work(detector):
            nonlocal active,peak,completed
            with lock:active+=1;peak=max(active,peak)
            time.sleep(.02)
            detector.report.status='identified'
            detector.report.observations.append(ServiceEvidence('ssh'))
            with lock:
                active-=1;completed+=1
                if completed==2:stop.set()
        with patch.object(Detector,'run',work):
            enrich_results(results,config,stop,Runtime(config))
        self.assertLessEqual(peak,2)
        self.assertTrue(any(r.service_detection.status=='not_attempted' for r in results))
        self.assertTrue(any(r.service_detection.observations for r in results))
        self.assertTrue(all(r.state=='open' for r in results))
        # Worker exceptions are recorded by Detector, without erasing the result.
        stop.clear()
        with patch.object(Detector,'tcp',side_effect=RuntimeError('worker failed')):
            Detector(results[0],config,stop,Runtime(config)).run()
        self.assertEqual(results[0].service_detection.status,'error')
        self.assertIn('RuntimeError',results[0].service_detection.issues[0])

    def test_interrupt_running_io_preserves_partial_export(self):
        stop=threading.Event()
        def silent(sock):time.sleep(.3)
        with lab(silent) as port:
            config=ScanConfig('127.0.0.1',(port,),service_detect=True)
            timer=threading.Timer(.1,stop.set);timer.start()
            report=scan_target(config,stop)
            timer.join()
        self.assertEqual(report.completion_status,'interrupted')
        self.assertEqual(report.results[0].state,'open')
        self.assertEqual(report.results[0].service_detection.status,'interrupted')
        self.assertTrue(report.to_dict()['incomplete'])

    def test_original_hostname_and_sni_override_do_not_change_endpoint(self):
        result=ScanResult('127.0.0.0/30','127.0.0.1','IPv4',443,original_targets=('127.0.0.0/30','localhost'))
        self.assertEqual(verification_name(result),'localhost')
        self.assertEqual(verification_name(result,'override.invalid'),'override.invalid')
        self.assertEqual(result.resolved_ip,'127.0.0.1')
        with lab(http,'trusted') as port:
            config=ScanConfig('127.0.0.0/30',(port,),service_detect=True,tls_ca_file=str(TLS/'ca.pem'))
            report=scan_target(config,endpoint=ResolvedTarget('127.0.0.1'), originals=('127.0.0.0/30','localhost'))
            self.assertEqual(report.results[0].service_detection.tls[0].sni,'localhost')

    def test_export_schema_nested_evidence_and_html_escaping(self):
        from scanix.output.save_csv import save_csv
        from scanix.output.save_html import save_html
        from scanix.output.save_json import save_json
        import csv
        config=ScanConfig('lab',(22,),service_detect=True)
        result=ScanResult('lab','127.0.0.1','IPv4',22,state='open',service_name='ssh',detection_source='port_table')
        result.service_detection=DetectionReport('1.0.0','quick',observations=[ServiceEvidence('http',product='<script>')])
        report=ScanReport(config,results=[result],completion_status='interrupted',probe_database_version='1.0.0')
        with tempfile.TemporaryDirectory() as folder:
            for name,save in (('json',save_json),('csv',save_csv),('html',save_html)):
                save(report,Path(folder)/('report.'+name))
            data=json.loads((Path(folder)/'report.json').read_text())
            self.assertEqual(data['schema_version'],3)
            self.assertEqual(data['probe_database_version'],'1.0.0')
            self.assertTrue(data['incomplete'])
            self.assertEqual(data['results'][0]['service_name'],'ssh')
            with (Path(folder)/'report.csv').open(newline='') as stream:rows=list(csv.DictReader(stream))
            self.assertEqual(rows[0]['probe_database_version'],'1.0.0')
            self.assertIn('observations',json.loads(rows[1]['service_detection']))
            html=(Path(folder)/'report.html').read_text()
            self.assertNotIn('<script>',html);self.assertIn('&lt;script&gt;',html)

    def test_cli_help_preview_no_traffic_and_invalid_flags(self):
        from scanix.cli import run_cli, build_parser
        help_text=build_parser()._subparsers._group_actions[0].choices['scan'].format_help()
        for flag in ('--service-detect','--service-profile','--tls-insecure','--tls-ca-file','--sni','--starttls','--allow-excluded-probes','--banner'):
            self.assertIn(flag,help_text)
        output=StringIO()
        with patch('socket.socket',side_effect=AssertionError('traffic')),patch('sys.stdout',output):
            self.assertEqual(run_cli(['scan','-t','127.0.0.1','-p','443','--service-detect','--service-profile','deep','--preview']),0)
        planned=json.loads(output.getvalue())['service_detection']
        self.assertEqual(planned['budget']['connections'],5)
        self.assertEqual(planned['tls_verification'],'required')
        for options in ({'service_profile':'invalid'},{'service_timeout':float('nan')},{'service_workers':65},{'sni':'bad\r\nHost: evil'},{'tls_insecure':True,'tls_ca_file':'file'}):
            with self.subTest(options=options),self.assertRaises(ValueError):ScanConfig('lab',(22,),**options)

    def test_pop3_imap_starttls_and_no_insecure_fallback(self):
        cases=(('pop3',b'+OK ready\r\n',b'CAPA\r\n',b'+OK capability\r\nSTLS\r\n.\r\n',b'STLS\r\n',b'+OK begin TLS\r\n',b'-ERR refused\r\n'),
               ('imap',b'* OK ready\r\n',b'a001 CAPABILITY\r\n',b'* CAPABILITY IMAP4rev1 STARTTLS\r\na001 OK done\r\n',b'a002 STARTTLS\r\n',b'a002 OK begin TLS\r\n',b'a002 NO refused\r\n'))
        for protocol,greeting,capability,response,upgrade,accepted,refused in cases:
            for mode in ('success','refusal','failed'):
                commands=[]
                context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(TLS/'trusted.pem',TLS/'server-TEST-ONLY.key')
                def handler(sock):
                    sock.sendall(greeting);commands.append(sock.recv(1024));sock.sendall(response)
                    commands.append(sock.recv(1024));sock.sendall(refused if mode=='refusal' else accepted)
                    if mode=='refusal':return
                    if mode=='failed':sock.sendall(b'not TLS\r\n');return
                    with context.wrap_socket(sock,server_side=True) as secured:
                        commands.append(secured.recv(1024));secured.sendall(response)
                with self.subTest(protocol=protocol,mode=mode),lab(handler) as port:
                    report=detect(port,starttls=True,tls_ca_file=str(TLS/'ca.pem'))
                    self.assertEqual(commands[:2],[capability,upgrade])
                    self.assertEqual(report.attempts,1)
                    if mode=='success':
                        self.assertEqual(commands,[capability,upgrade,capability])
                        self.assertEqual(report.tls[0].verification,'verified')
                        self.assertEqual(report.observations[-1].transport,'tls')
                    else:
                        self.assertEqual(len(commands),2)
                        self.assertTrue(report.issues)

    def test_registry_fallback_cycles_are_bounded_and_data_driven(self):
        from scanix.service.registry import load_registry
        registry=load_registry()
        self.assertEqual([p['id'] for p in registry.fallback_chain('tls.tcp.v1',100)],['tls.tcp.v1','http.tcp.v1'])
        self.assertEqual(len(registry.fallback_chain('dns.udp.v1',1)),1)

    def test_phase2_udp_evidence_reuse_sends_nothing(self):
        config=ScanConfig('127.0.0.1',(53,),method='udp',service_detect=True)
        result=ScanResult('lab','127.0.0.1','IPv4',53,protocol='udp',state='open',probe_type='dns',reason='udp_response',evidence={'transaction_validated':True})
        with patch('socket.socket',side_effect=AssertionError('unexpected socket')):
            report=Detector(result,config,threading.Event(),Runtime(config)).run()
        self.assertEqual(report.attempts,0)
        self.assertEqual(report.observations[0].detection_method,'scan_response')

    def test_connection_and_transmission_budgets_are_hard_limits(self):
        from scanix.service.transport import Session, BudgetExceeded
        config=ScanConfig('127.0.0.1',(22,),service_detect=True)
        result=ScanResult('lab','127.0.0.1','IPv4',22,state='open')
        detector=Detector(result,config,threading.Event(),Runtime(config))
        detector.report.attempts=3
        with detector.session() as session,self.assertRaises(BudgetExceeded):session.connect()
        detector.report.transmissions=6
        with detector.session() as session,self.assertRaises(BudgetExceeded):session.send(b'x')
        detector.report.transmissions=0;detector.report.bytes_sent=2048
        with detector.session() as session,self.assertRaises(BudgetExceeded):session.send(b'x')
        detector.report.bytes_received=8192
        with detector.session() as session,self.assertRaises(BudgetExceeded):session.receive(1)

    def test_fragmented_ssh_preamble_and_smtp_multiline(self):
        def ssh(sock):
            sock.sendall(b'Local lab notice\r\n');time.sleep(.02);sock.sendall(b'SSH-2.0-OpenSSH_9.7\r\n')
        with lab(ssh) as port:
            report=detect(port)
        self.assertEqual(report.observations[-1].service,'ssh')
        seen=[]
        def smtp(sock):
            sock.sendall(b'220-lab.invalid ESMTP Postfix\r\n');time.sleep(.02)
            sock.sendall(b'220 ready\r\n');seen.append(sock.recv(1024));sock.sendall(b'250 HELP\r\n')
        with lab(smtp) as port:
            report=detect(port,service_profile='deep')
        self.assertEqual(report.observations[-1].confidence,'protocol')
        self.assertEqual(seen,[b'EHLO scanix.invalid\r\n'])

    def test_ntp_deep_fallback_and_quick_udp_budget(self):
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.bind(('127.0.0.1',0));sock.settimeout(.05)
        stop=threading.Event();requests=[]
        def respond():
            while not stop.is_set():
                try:data,address=sock.recvfrom(512)
                except socket.timeout:continue
                requests.append(data)
                if len(data)==48 and data[0]&7==3:
                    reply=bytearray(48);reply[0]=0x24;reply[24:32]=data[40:48];sock.sendto(reply,address)
        thread=threading.Thread(target=respond);thread.start()
        try:
            for profile,count,service in (('quick',1,None),('deep',2,'ntp')):
                config=ScanConfig('127.0.0.1',(sock.getsockname()[1],),method='udp',service_detect=True,service_profile=profile,rate=10000)
                result=ScanResult('lab','127.0.0.1','IPv4',config.ports[0],protocol='udp',state='open')
                report=Detector(result,config,threading.Event(),Runtime(config)).run()
                self.assertEqual(report.attempts,count)
                self.assertEqual(report.observations[-1].service if report.observations else None,service)
            self.assertEqual([len(r) for r in requests], [32,32,48])
        finally:
            stop.set();thread.join(2);sock.close()

    def test_ipv6_tls_ip_san(self):
        if not socket.has_ipv6:
            self.skipTest('IPv6 is unavailable on this platform')
        try:
            check=socket.socket(socket.AF_INET6,socket.SOCK_STREAM)
            with check:check.bind(('::1',0))
        except OSError as exc:
            self.skipTest('IPv6 loopback unavailable: '+str(exc))
        names=[]
        with lab(http,'trusted',names,family=socket.AF_INET6) as port:
            report=detect(port,address='::1',tls_ca_file=str(TLS/'ca.pem'))
        self.assertEqual(report.tls[0].verification,'verified')
        self.assertEqual(report.tls[0].verification_name,'::1')
        self.assertEqual(names,[None])
        self.assertEqual(report.observations[-1].service,'http')

    def test_tls_alone_does_not_claim_https_and_all_operations_are_paced(self):
        class Counter:
            count=0
            def acquire(self,stop,*,deadline=None):self.count+=1
        limiter=Counter()
        def raw_tls(sock):sock.recv(1024)
        with lab(raw_tls,'trusted') as port:
            config=ScanConfig('127.0.0.1',(port,),service_detect=True,tls_ca_file=str(TLS/'ca.pem'))
            result=ScanResult('127.0.0.1','127.0.0.1','IPv4',port,state='open')
            report=Detector(result,config,threading.Event(),Runtime(config,limiter)).run()
        self.assertEqual([o.service for o in report.observations],['tls'])
        self.assertEqual(limiter.count,report.attempts+report.transmissions)

    def test_failed_followup_never_opens_plaintext_fallback_after_evidence(self):
        def smtp(sock):
            sock.sendall(b'220 lab.invalid ESMTP Postfix\r\n');sock.recv(1024)
        with lab(smtp) as port,patch.object(Detector,'capabilities',side_effect=ConnectionResetError('peer reset')):
            report=detect(port,service_profile='deep',starttls=True)
        self.assertEqual(report.attempts,1)
        self.assertEqual([o.service for o in report.observations],['smtp'])
        self.assertFalse(report.tls)
        self.assertIn('ConnectionResetError',report.issues[0])
        with lab(http,'trusted') as port,patch.object(Detector,'http',side_effect=ConnectionResetError('peer reset')):
            report=detect(port,tls_ca_file=str(TLS/'ca.pem'))
        self.assertEqual(report.attempts,2)  # passive, then TLS; no plaintext fallback
        self.assertEqual([o.service for o in report.observations],['tls'])

    def test_pacing_samples_time_after_acquiring_scheduling_lock(self):
        class Clock:
            now=0.
            def clock(self):return self.now
        clock=Clock()
        class DelayedLock:
            def __enter__(self):clock.now=2.
            def __exit__(self,*args):pass
        limiter=RateLimiter(2,clock.clock)
        limiter.lock=DelayedLock()  # Deterministically emulate pre-lock descheduling.
        limiter.acquire(threading.Event())
        self.assertEqual(limiter.next_time,2.5)
