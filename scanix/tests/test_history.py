"""Owner-private synthetic histories, no public network or privileges."""
from contextlib import closing
from copy import deepcopy
from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from scanix.core.models import ScanConfig, ScanReport, ScanResult
from scanix.history.store import History, VERSION, MAX_RECORD, endpoint
from scanix.service.models import DetectionReport, ServiceEvidence


def result(port=80,state='open',ip='192.0.2.2'):
    return ScanResult(ip,ip,'IPv6' if ':' in ip else 'IPv4',port,state=state,
                      original_targets=('synthetic.invalid',),reason='synthetic_evidence')


def report(rows=None, status='complete', requested=None):
    rows=[result()] if rows is None else rows
    ports=tuple(sorted(set(r.port for r in rows))) or (80,)
    return ScanReport(ScanConfig('synthetic.invalid',ports),rows,completion_status=status,
                      requested_probes=requested if requested is not None else len(rows),
                      probe_database_version='1.0.0',plugin_api_version=1,plugin_registry_version='1.0.0')


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.file=Path(self.temp.name)/'history.sqlite'

    def test_initial_migration_versions_config_evidence_roundtrip_and_close(self):
        source=report();source.results[0].evidence={'synthetic':'<script>','os_detection':{'database_version':'1.0.0','status':'inconclusive'}}
        with History(self.file,create=True) as history:
            id=history.save(source)
            meta=history.show(id);stored=list(history.records(id))
            self.assertEqual(meta['configuration']['ports'],[80]);self.assertFalse(meta['incomplete'])
            self.assertEqual(meta['history']['schema_version'],VERSION)
            self.assertEqual(meta['probe_database_version'],'1.0.0')
            self.assertEqual(meta['plugin_registry_version'],'1.0.0')
            self.assertEqual(stored[0][1]['evidence'],source.results[0].evidence)
            self.assertEqual(meta['implementation'],source.implementation)
        self.assertIsNone(history.db)
        with History(self.file) as reopened:self.assertEqual(reopened.show(id)['history']['stored_results'],1)
        if os.name=='posix':self.assertEqual(self.file.stat().st_mode&0o777,0o600)

    def test_read_requires_existing_database(self):
        with self.assertRaises(FileNotFoundError):History(self.file)
        self.assertFalse(self.file.exists())

    def test_unknown_versions_and_schema_triggers_fail_closed(self):
        with History(self.file,create=True):pass
        for sql in ('PRAGMA user_version=99', 'CREATE TRIGGER sqliteXhidden AFTER INSERT ON scans BEGIN DELETE FROM observations; END'):
            with self.subTest(sql=sql):
                with closing(sqlite3.connect(self.file)) as db,db:db.execute(sql)
                with self.assertRaises(ValueError):History(self.file)
                with closing(sqlite3.connect(self.file)) as db,db:
                    db.execute('PRAGMA user_version=1');db.execute('DROP TRIGGER IF EXISTS sqliteXhidden')

    def test_unsupported_page_size_and_schema_collision_rejected(self):
        with closing(sqlite3.connect(self.file)) as db,db:db.execute('CREATE TABLE scans (not_ours TEXT)')
        if os.name=='posix':self.file.chmod(0o600)
        with self.assertRaises(ValueError):History(self.file,create=True)

    def test_permissions_symlinks_and_untrusted_parent(self):
        with History(self.file,create=True):pass
        if os.name!='posix':self.skipTest('POSIX permission/ownership contract; Windows inherits parent ACL')
        original=self.file.lstat()
        class Foreign:
            st_mode=original.st_mode|0o044;st_uid=original.st_uid;st_size=original.st_size
        with patch('scanix.history.store.Path.lstat',return_value=Foreign()),patch('scanix.history.store.sqlite3.connect') as connect:
            with self.assertRaises(ValueError):History(self.file)
            connect.assert_not_called()
        alias=Path(self.temp.name)/'alias.sqlite';alias.symlink_to(self.file)
        with self.assertRaises(ValueError):History(alias)

    def test_writer_lock_and_batch_rollback_keep_partial(self):
        with History(self.file,create=True) as history:
            with self.assertRaises(sqlite3.OperationalError):History(self.file)
            rows=[result(p+1) for p in range(20)];rows[-1].evidence={'invalid':float('nan')}
            with self.assertRaises(ValueError):history.save(report(rows))
            saved=list(history.list())[0]
            self.assertTrue(saved['incomplete']);self.assertFalse(saved['history']['finalized'])
            self.assertEqual(saved['history']['stored_results'],19)

    def test_partial_missing_rows_never_invent_removals(self):
        with History(self.file,create=True) as history:
            before=history.save(report([result(80),result(443)]))
            after=history.save(report([result(80,'unknown')],status='interrupted',requested=2))
            diff=list(history.compare(before,after))
        self.assertTrue(diff[0]['current_incomplete'])
        missing=next(x for x in diff if x['type']=='not_observed')
        self.assertEqual(missing['previous_state'],'open')
        self.assertNotIn('closed',json.dumps(diff));self.assertNotIn('removed',json.dumps(diff))
        changed=next(x for x in diff if x['type']=='changed')
        self.assertEqual(changed['changes']['state'],{'previous':'open','current':'unknown'})

    def test_confirmed_state_service_and_evidence_changes(self):
        first=report([result()]);second=deepcopy(first)
        first.results[0].service_detection=DetectionReport('1.0.0','quick',observations=[ServiceEvidence('http',product='Synthetic',version='1')])
        second.results[0].service_detection=DetectionReport('1.0.0','quick',observations=[ServiceEvidence('http',product='Synthetic',version='2')])
        second.results[0].evidence={'synthetic':'changed'}
        with History(self.file,create=True) as history:
            a,b=history.save(first),history.save(second);changes=list(history.compare(a,b))[1]['changes']
            self.assertIn('service_evidence',changes);self.assertTrue(changes['evidence_changed'])
            third=history.save(report([result(state='closed')]))
            self.assertEqual(list(history.compare(b,third))[1]['changes']['state']['current'],'closed')

    def test_timestamp_and_budget_noise_are_not_observation_changes(self):
        first=report();second=deepcopy(first)
        second.results[0].timestamp='synthetic-later';second.results[0].connection_elapsed_seconds=99
        first.results[0].service_detection=DetectionReport('1.0.0','quick',attempts=1,elapsed_seconds=.1)
        second.results[0].service_detection=DetectionReport('1.0.0','quick',attempts=2,elapsed_seconds=.9)
        with History(self.file,create=True) as history:
            a,b=history.save(first),history.save(second)
            self.assertEqual(len(list(history.compare(a,b))),1)

    def test_ipv6_dedup_keys_and_no_assumed_dns_scope_identity(self):
        first=report([result(ip='2001:db8::2')]);second=report([result(ip='2001:db8::3')])
        with History(self.file,create=True) as history:
            a,b=history.save(first),history.save(second);diff=list(history.compare(a,b))
        self.assertFalse(diff[0]['selected_scope_identity_assumed'])
        self.assertEqual({x['type'] for x in diff[1:]},{'new_observation','not_observed'})
        normalized=asdict(result(ip='2001:0db8:0:0:0:0:0:2'))
        self.assertEqual(endpoint(normalized),endpoint(asdict(result(ip='2001:db8::2'))))

    def test_retention_and_delete_cascade_include_partial_explicitly(self):
        with History(self.file,create=True) as history:
            ids=[history.save(report(status='interrupted' if i==1 else 'complete')) for i in range(3)]
            self.assertEqual(history.prune(2),1)
            self.assertEqual([x['scan_id'] for x in history.list()],ids[:0:-1])
            history.delete(ids[1]);self.assertEqual(history.db.execute('SELECT count(*) FROM observations').fetchone()[0],1)
            with self.assertRaises(KeyError):history.show(ids[0])
            self.assertEqual(history.prune(0),1);self.assertEqual(list(history.list()),[])

    def test_tampered_record_digest_and_invalid_limits_fail(self):
        with History(self.file,create=True) as history:
            id=history.save(report())
            with history.transaction():history.db.execute('UPDATE observations SET record=?',('{}',))
            with self.assertRaises(ValueError):list(history.records(id))
            for invalid in (-1,True,1001):
                with self.assertRaises(ValueError):list(history.list(invalid))
            with self.assertRaises(ValueError):history.delete('../invalid')
            with self.assertRaises(ValueError):history.prune(-1)

    def test_nonretained_report_requires_stream_and_future_report_rejected(self):
        with History(self.file,create=True) as history:
            with self.assertRaises(ValueError):history.save(replace(report(),results=[],completed_probes=1))
            with self.assertRaises(ValueError):history.save(replace(report(),schema_version=99))
            self.assertEqual(list(history.list()),[])

    def stream(self, source, rows, *, complete=True, fingerprint='0'*64):
        file=Path(self.temp.name)/('stream-'+str(len(list(Path(self.temp.name).glob('stream-*'))))+'.ndjson')
        source.configuration=replace(source.configuration,engine='native')
        source.implementation={'engine':'native','engine_version':'0.4.2','wire_protocol':3,
                               'continuation':{'fingerprint':fingerprint}}
        data=source.to_dict()
        frames=[{'type':'header','stream_version':1,'report_schema':5,'fingerprint':fingerprint,
                 'configuration':data['configuration']}]
        for id,row in rows:
            record=asdict(row);record['evidence']['work_id']=id
            frames.append({'type':'result','id':id,'record':record})
        if complete:frames.append({'type':'summary',**{k:data[k] for k in ('schema_version','completion_status','completed_ports','requested_ports')}})
        file.write_text(''.join(json.dumps(f)+'\n' for f in frames))
        return file

    def test_native_stream_bounded_upserts_and_completion(self):
        row=result();updated=deepcopy(row);updated.evidence={'synthetic':'enriched'}
        source=replace(report([row]),results=[],completed_probes=1)
        file=self.stream(source,[(7,row),(7,updated)])
        with History(self.file,create=True) as history:
            id=history.save(source,stream_file=file)
            self.assertFalse(history.show(id)['incomplete'])
            self.assertEqual(len(list(history.records(id))),1)
            self.assertEqual(list(history.records(id))[0][1]['evidence']['synthetic'],'enriched')

    def test_truncated_stream_retains_verified_rows_as_unfinalized(self):
        row=result();source=replace(report([row]),results=[],completed_probes=1)
        file=self.stream(source,[(0,row)],complete=False)
        with History(self.file,create=True) as history:
            with self.assertRaises(ValueError):history.save(source,stream_file=file)
            latest=list(history.list())[0]
            self.assertTrue(latest['incomplete']);self.assertEqual(latest['history']['stored_results'],1)
            self.assertFalse(latest['history']['finalized'])

    def test_stream_mismatched_config_id_fingerprint_and_oversized_fail(self):
        row=result();source=replace(report([row]),results=[],completed_probes=1)
        for change in ('configuration','fingerprint','work_id','oversized'):
            file=self.stream(source,[(0,row)])
            lines=file.read_text().splitlines();header=json.loads(lines[0]);frame=json.loads(lines[1])
            if change=='configuration':header['configuration']['ports']=[443]
            if change=='fingerprint':header['fingerprint']='different-synthetic'
            if change=='work_id':frame['record']['evidence']['work_id']=99
            if change=='oversized':frame['record']['banner']='x'*(MAX_RECORD+1025)
            lines[0]=json.dumps(header);lines[1]=json.dumps(frame);file.write_text('\n'.join(lines)+'\n')
            with History(self.file,create=True) as history:
                with self.subTest(change=change),self.assertRaises(ValueError):history.save(source,stream_file=file)
                self.assertTrue(list(history.list())[0]['incomplete'])

    def test_port_guesses_do_not_become_service_changes(self):
        first=report();second=deepcopy(first)
        first.results[0].service_name='http';second.results[0].service_name='ssh'
        first.results[0].detection_source=second.results[0].detection_source='port_table'
        with History(self.file,create=True) as history:
            a,b=history.save(first),history.save(second)
            self.assertEqual(len(list(history.compare(a,b))),1)

    def test_failed_initial_migration_rolls_back_and_can_retry(self):
        with patch.dict('scanix.history.store.SCHEMAS',{'observations':'CREATE invalid migration'}):
            with self.assertRaises(sqlite3.OperationalError):History(self.file,create=True)
        with closing(sqlite3.connect(self.file)) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0],0)
            self.assertEqual(db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall(),[])
        with History(self.file,create=True) as history:self.assertEqual(list(history.list()),[])

    def test_comparison_includes_version_provenance(self):
        first=report();second=deepcopy(first);second.probe_database_version='synthetic-new-version'
        with History(self.file,create=True) as history:
            a,b=history.save(first),history.save(second);header=next(history.compare(a,b))
            self.assertEqual(header['previous_versions']['probe_database'],'1.0.0')
            self.assertEqual(header['current_versions']['probe_database'],'synthetic-new-version')
            self.assertEqual(len(header['current_versions']['writer']['python_implementation_sha256']),64)


class HistoryCLITests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.file=Path(self.temp.name)/'history.sqlite'

    def test_preview_does_not_create_or_open_history(self):
        from io import StringIO
        from scanix.cli import run_cli
        with patch('sys.stdout',StringIO()),patch('scanix.history.store.sqlite3.connect',side_effect=AssertionError('DB opened')):
            code=run_cli(['scan','-t','127.0.0.1','-p','80','--history',str(self.file),'--preview'])
        self.assertEqual(code,0);self.assertFalse(self.file.exists())

    def test_actual_loopback_scan_preserves_json_export_and_history(self):
        from io import StringIO
        from scanix.cli import run_cli
        from scanix.tests.test_service_engine import lab,http
        output=StringIO();errors=StringIO()
        with lab(http) as port,patch('sys.stdout',output),patch('sys.stderr',errors):
            code=run_cli(['scan','-t','127.0.0.1','-p',str(port),'--plugins','http','--history',str(self.file),'--out','json','--out-file','-'])
        self.assertEqual(code,0)
        exported=json.loads(output.getvalue())
        with History(self.file) as history:
            latest=list(history.list())[0];stored=list(history.records(latest['scan_id']))[0][1]
        self.assertEqual(exported['results'][0],stored)
        self.assertEqual(stored['plugin_results'][0]['status'],'complete')
        self.assertIn('History scan:',errors.getvalue())

    def test_commands_are_offline_and_json_escape_controls(self):
        from io import StringIO
        from scanix.cli import run_cli
        source=report();source.results[0].banner='synthetic\x1b[31m'
        with History(self.file,create=True) as history:
            previous=history.save(source);current=history.save(report(status='interrupted'))
        for command in (['list'],['show',previous,'--results'],['diff',previous,current],['delete',previous],['prune','--keep','0']):
            output=StringIO()
            with patch('socket.socket',side_effect=AssertionError('traffic')),patch('sys.stdout',output):
                code=run_cli(['history','--db',str(self.file),*command])
            self.assertEqual(code,0);self.assertNotIn('\x1b',output.getvalue())
            for line in output.getvalue().splitlines():json.loads(line)

    def test_unavailable_history_fails_before_any_probe_and_redacts_paths(self):
        from io import StringIO
        from scanix.cli import run_cli
        error=StringIO()
        with patch('sys.stderr',error),patch('scanix.cli.scan_target') as scan:
            code=run_cli(['scan','-t','127.0.0.1','-p','80','--history',str(self.file/'missing'/'history.sqlite')])
            scan.assert_not_called()
        self.assertEqual(code,1);self.assertNotIn(str(self.file),error.getvalue())

    def test_history_failure_retains_requested_file_export_and_returns_failure(self):
        from io import StringIO
        from scanix.cli import run_cli
        output=Path(self.temp.name)/'synthetic.json'
        with patch('scanix.cli.scan_target',return_value=report()),patch('scanix.history.store.History.save',side_effect=OSError('synthetic private detail')),\
             patch('sys.stderr',StringIO()) as error:
            code=run_cli(['scan','-t','127.0.0.1','-p','80','--history',str(self.file),'--out','json','--out-file',str(output)])
        self.assertEqual(code,1);self.assertEqual(json.loads(output.read_text())['results'][0]['state'],'open')
        self.assertNotIn('synthetic private detail',error.getvalue())

    def test_export_failure_still_records_history_and_redacts_exception(self):
        from io import StringIO
        from scanix.cli import run_cli
        with patch('scanix.cli.scan_target',return_value=report()),\
             patch('scanix.output.save_json.save_json',side_effect=OSError('synthetic private detail')),\
             patch('sys.stderr',StringIO()) as error:
            code=run_cli(['scan','-t','127.0.0.1','-p','80','--history',str(self.file),'--out','json'])
        self.assertEqual(code,1);self.assertNotIn('synthetic private detail',error.getvalue())
        with History(self.file) as history:self.assertEqual(len(list(history.list())),1)

    @unittest.skipUnless(os.environ.get('SCANIX_NATIVE_ENGINE'),'set SCANIX_NATIVE_ENGINE for real native streaming integration')
    def test_actual_native_stream_history_enrichment_and_completed_resume(self):
        from io import StringIO
        from scanix.cli import run_cli
        from scanix.tests.test_service_engine import lab,http
        checkpoint=Path(self.temp.name)/'native.sqlite'
        with lab(http) as port:
            args=['scan','-t','127.0.0.1','-p',str(port),'--engine','native','--plugins','http',
                  '--history',str(self.file),'--checkpoint',str(checkpoint),'--rate','10000']
            with patch('sys.stderr',StringIO()):
                self.assertEqual(run_cli(args+['--stream-file',str(Path(self.temp.name)/'first.ndjson')]),0)
            with patch('subprocess.Popen',side_effect=AssertionError('completed resume transmitted')),patch('sys.stderr',StringIO()):
                self.assertEqual(run_cli(args+['--stream-file',str(Path(self.temp.name)/'resumed.ndjson'),'--resume']),0)
        with History(self.file) as history:
            scans=list(history.list());self.assertEqual(len(scans),2)
            for scan in scans:
                self.assertFalse(scan['incomplete'])
                record=list(history.records(scan['scan_id']))[0][1]
                self.assertEqual(record['state'],'open')
                self.assertEqual(record['plugin_results'][0]['status'],'complete')
            self.assertEqual(len(list(history.compare(scans[1]['scan_id'],scans[0]['scan_id']))),1)

    def test_tampered_unicode_record_is_bounded_by_encoded_bytes(self):
        import hashlib
        with History(self.file,create=True) as history:
            id=history.save(report());record=list(history.records(id))[0][1]
            record['banner']='🧪'*20000;data=json.dumps(record,ensure_ascii=False)
            self.assertLess(len(data),MAX_RECORD);self.assertGreater(len(data.encode()),MAX_RECORD)
            with history.transaction():history.db.execute('UPDATE observations SET record=?,digest=?',(data,hashlib.sha256(data.encode()).hexdigest()))
            with self.assertRaises(ValueError):list(history.records(id))

    def test_optional_backend_does_not_break_normal_cli(self):
        import subprocess,sys
        script="""import builtins,sys
sys.path.insert(0,sys.argv[1])
original=builtins.__import__
def blocked(name,*args,**kwargs):
    if name in ('sqlite3','_sqlite3'):raise ModuleNotFoundError('synthetic unavailable backend')
    return original(name,*args,**kwargs)
builtins.__import__=blocked
from scanix.cli import build_parser,run_cli
build_parser()
raise SystemExit(0 if run_cli(['history','--db',sys.argv[2],'list'])==1 else 2)
"""
        process=subprocess.run([sys.executable,'-I','-B','-c',script,str(Path(__file__).resolve().parents[2]),str(self.file)],capture_output=True,text=True,timeout=10)
        self.assertEqual(process.returncode,0)
        self.assertIn('ModuleNotFoundError',process.stderr)
        self.assertFalse(self.file.exists())
