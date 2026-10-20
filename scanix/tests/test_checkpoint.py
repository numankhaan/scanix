"""Private synthetic resume fixtures; no credentials, captures or external traffic."""
from contextlib import closing
from dataclasses import replace
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from scanix.core.models import ScanConfig, ResolvedTarget
from scanix.core.scanner import new_result
from scanix.core.targets import ScopePlan
from scanix.native.checkpoint import Checkpoint, ResultStream, manifest
from scanix.native.selection import Selection


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)/'resume.sqlite'
        self.binary = Path(self.tmp.name)/'trusted-binary'
        self.binary.write_bytes(b'synthetic engine bytes')
        self.config = ScanConfig('127.0.0.1', (80,443), engine='native')
        self.plan = ScopePlan(['127.0.0.1'])
        self.targets = list(self.plan)
        self.identity = manifest(self.config,self.plan,self.targets,self.binary,0,1)

    def open(self, **kw):
        return Checkpoint(self.path,self.identity,self.config,self.targets,**kw)

    def result(self,id=0):
        row = new_result(self.config,ResolvedTarget('127.0.0.1'),self.config.ports[id])
        row.original_targets=('127.0.0.1',);row.evidence={'engine':'native','work_id':id,'wire_protocol':3}
        row.state='open';row.reason='connection_succeeded'
        return row

    def test_committed_results_survive_restart_and_lock_is_exclusive(self):
        with self.open() as state:
            state.add(self.result());self.assertEqual(state.completed,1)
            with self.assertRaises(sqlite3.OperationalError):self.open(resume=True)
            with self.assertRaises(ValueError):state.add(self.result())
            state.finish({'completion_status':'interrupted'})
        with self.open(resume=True) as state:
            self.assertEqual(state.selection.remaining,1)
            self.assertFalse(state.selection.selected(0));self.assertTrue(state.selection.selected(1))
            self.assertEqual(len(list(state.records())),1)
        if os.name=='posix':self.assertEqual(self.path.stat().st_mode & 0o777,0o600)

    def test_batch_flush_deadline_and_cancellation_flush_use_deterministic_clock(self):
        from scanix.native.checkpoint import DurableBatch
        from unittest.mock import Mock
        clock=[0.0];stream=Mock()
        with self.open() as state:
            batch=DurableBatch(state,stream,16,clock=lambda:clock[0])
            batch.submit(self.result());self.assertEqual(state.completed,0)
            clock[0]=.249;batch.tick();self.assertEqual(state.completed,0)
            clock[0]=.25;batch.tick();self.assertEqual(state.completed,1)
            stream.result.assert_called_once()
            batch.submit(self.result(1));self.assertEqual(state.completed,1)
            batch.flush();self.assertEqual(state.completed,2)
            self.assertFalse(batch.pending)

    def test_atomic_bounded_batch_and_invalid_record_roll_back_all_work(self):
        with self.open() as state:
            with self.assertRaises(ValueError):
                state.add_batch([self.result(),replace(self.result(1),resolved_ip='127.0.0.2')])
            self.assertEqual(state.completed,0);self.assertEqual(list(state.records()),[])
            rows=state.add_batch([self.result(),self.result(1)])
            self.assertEqual(len(rows),2);self.assertEqual(state.completed,2)
            self.assertEqual(state.commit_count,1)
            with self.assertRaises(ValueError):state.add_batch([])
            with self.assertRaises(ValueError):state.add_batch([self.result()]*65)

    def test_crash_replays_only_uncommitted_work(self):
        # Child commits one fixture then exits without closing SQLite. OS releases the lock.
        with self.open():pass
        program='''import os,sys
from pathlib import Path
from scanix.tests.test_checkpoint import CheckpointTests
from scanix.native.checkpoint import Checkpoint
case=CheckpointTests();case.setUp()
state=Checkpoint(sys.argv[1],case.identity,case.config,case.targets,resume=True)
state.begin()
state.add(case.result())
os._exit(23)
'''
        result=subprocess.run([sys.executable,'-B','-c',program,str(self.path)],capture_output=True)
        self.assertEqual(result.returncode,23)
        with self.open(resume=True) as state:
            self.assertEqual(state.completed,1);self.assertEqual(state.selection.remaining,1)
            self.assertTrue(state.metrics_unknown())

    def test_manifest_rejects_scope_exclusions_dns_associations_policy_and_binary_changes(self):
        with self.open():pass
        cases=[manifest(replace(self.config,timeout=2),self.plan,self.targets,self.binary,0,1),
               manifest(self.config,ScopePlan(['127.0.0.1'],['127.0.0.2']),self.targets,self.binary,0,1),
               manifest(self.config,self.plan,self.targets,self.binary,1,2)]
        self.binary.write_bytes(b'changed engine')
        cases.append(manifest(self.config,self.plan,self.targets,self.binary,0,1))
        from scanix.core.targets import Target
        cases.append(manifest(self.config,self.plan,[Target('127.0.0.1',('lab.invalid',))],self.binary,0,1))
        for identity in cases:
            with self.subTest(field='compatibility'),self.assertRaises(ValueError):
                Checkpoint(self.path,identity,self.config,self.targets,resume=True)

    def test_resume_with_zero_completed_rows_still_waits_for_previous_possible_sends(self):
        from unittest.mock import Mock,patch
        from scanix.core.models import ScanReport
        from scanix.native.session import scan_session
        config=replace(self.config,rate=2)
        identity=manifest(config,self.plan,self.targets,self.binary,0,1)
        with Checkpoint(self.path,identity,config,self.targets):pass
        stop=Mock();stop.is_set.return_value=False;stop.wait.return_value=False
        partial=ScanReport(config,completion_status='failed',completed_probes=0,requested_probes=2)
        with patch('scanix.native.session.scan_native',return_value=partial) as native:
            report=scan_session(config,self.plan,self.path,Path(self.tmp.name)/'guard.ndjson',
                                resume=True,binary=str(self.binary),stop=stop)
        stop.wait.assert_called_once_with(.5)
        self.assertEqual(native.call_count,1);self.assertEqual(report.completed_probes,0)
        self.assertLess(native.call_args.args[0].engine_timeout,config.engine_timeout)

    def test_python_registry_and_custom_ca_changes_invalidate_resume(self):
        from unittest.mock import patch
        original=self.identity
        with patch('scanix.native.checkpoint.implementation_digest',return_value='changed-synthetic-fingerprint'):
            changed=manifest(self.config,self.plan,self.targets,self.binary,0,1)
        self.assertNotEqual(original,changed)
        ca=Path(self.tmp.name)/'synthetic-ca.txt';ca.write_text('synthetic CA bytes, not a certificate')
        config=replace(self.config,tls_ca_file=str(ca))
        first=manifest(config,self.plan,self.targets,self.binary,0,1)
        ca.write_text('different synthetic CA bytes')
        self.assertNotEqual(first,manifest(config,self.plan,self.targets,self.binary,0,1))
        from scanix.native.checkpoint import file_digest
        def changed_registry(filename,limit=64*1024*1024):
            return 'changed registry' if Path(filename).name=='probes-v1.json' else file_digest(filename,limit)
        with patch('scanix.native.checkpoint.file_digest',side_effect=changed_registry):
            self.assertNotEqual(manifest(self.config,self.plan,self.targets,self.binary,0,1),original)

    def test_untrusted_schema_record_and_permissions_fail_closed(self):
        with self.open() as state:state.add(self.result())
        with closing(sqlite3.connect(self.path)) as db, db:db.execute("UPDATE results SET record='{}'")
        with self.assertRaises(ValueError):self.open(resume=True)
        with closing(sqlite3.connect(self.path)) as db, db:db.execute('CREATE VIEW unexpected AS SELECT 1')
        with self.assertRaises(ValueError):self.open(resume=True)
        if os.name=='posix':
            from types import SimpleNamespace
            from unittest.mock import patch
            status=self.path.stat()
            unsafe=SimpleNamespace(st_mode=status.st_mode | 0o040,st_size=status.st_size,st_uid=status.st_uid)
            with patch.object(Path,'lstat',return_value=unsafe),patch('sqlite3.connect') as connect:
                with self.assertRaises(ValueError):self.open(resume=True)
                connect.assert_not_called()

    def test_schema_name_collisions_cannot_hide_triggers(self):
        with self.open():pass
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("CREATE TRIGGER meta AFTER INSERT ON results BEGIN SELECT RAISE(ABORT,'synthetic trigger'); END")
        with self.assertRaises(ValueError):self.open(resume=True)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM results').fetchone()[0],0)

    def test_no_overwrite_symlink_or_out_of_scope_record(self):
        with self.open() as state:
            with self.assertRaises(FileExistsError):self.open()
            with self.assertRaises(ValueError):state.add(replace(self.result(),resolved_ip='127.0.0.2'))
            with self.assertRaises(ValueError):state.add(replace(self.result(),evidence={'work_id':99}))
        if os.name=='posix':
            link=Path(self.tmp.name)/'link.sqlite';link.symlink_to(self.path)
            with self.assertRaises(ValueError):Checkpoint(link,self.identity,self.config,self.targets,resume=True)

    def test_stream_is_bounded_private_and_terminal_safe_json(self):
        path=Path(self.tmp.name)/'results.ndjson'
        stream=ResultStream(path,{'fingerprint':'synthetic'})
        record={'banner':'\x1b[31m\r\nsynthetic'}
        stream.result(1,record)
        with self.assertRaises(ValueError):stream.write({'oversized':'x'*70000})
        stream.close()
        payload=path.read_bytes();self.assertNotIn(b'\x1b',payload)
        self.assertEqual(json.loads(payload.splitlines()[1])['record'],record)
        with self.assertRaises(FileExistsError):ResultStream(path,{})


class SelectionTests(unittest.TestCase):
    def test_shards_cover_exactly_once_and_completed_bitmaps_are_bounded(self):
        for total in (0,1,17,101):
            coverage=[0]*total
            for index in range(7):
                selected=Selection(total,index,7)
                self.assertEqual(sum(selected.selected(id) for id in range(total)),selected.requested)
                for id in range(total):coverage[id]+=selected.selected(id)
            self.assertEqual(coverage,[1]*total)
        self.assertEqual(len(Selection(1_000_000).completed),1_000_000)
        for args in ((1,1,1),(1,0,0),(1,0,1025),(1_000_001,0,1),(True,0,1)):
            with self.assertRaises(ValueError):Selection(*args)
        with self.assertRaises(ValueError):Selection(2,0,2,bytes([0,1]))


@unittest.skipUnless(os.environ.get('SCANIX_NATIVE_ENGINE'),'build native engine and set SCANIX_NATIVE_ENGINE')
class ResumeLoopbackTests(unittest.TestCase):
    def setUp(self):
        import socket,threading
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.stop=threading.Event();self.listeners=[];self.threads=[];self.accepts={}
        for _ in range(4):
            listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(8);listener.settimeout(.05)
            self.listeners.append(listener);port=listener.getsockname()[1];self.accepts[port]=0
            def serve(sock=listener,port=port):
                while not self.stop.is_set():
                    try:
                        connection,_=sock.accept();self.accepts[port]+=1;connection.close()
                    except socket.timeout:continue
                    except OSError:break
            thread=threading.Thread(target=serve);thread.start();self.threads.append(thread)
        self.addCleanup(self.cleanup_lab)
        self.config=ScanConfig('127.0.0.1',tuple(self.accepts),engine='native',rate=20,concurrency=1,per_host=1)
        self.plan=ScopePlan(['127.0.0.1'])
        self.db=Path(self.tmp.name)/'scan.sqlite'

    def cleanup_lab(self):
        self.stop.set()
        for listener in self.listeners:listener.close()
        for thread in self.threads:thread.join(1)

    def test_actual_cancel_resume_and_completed_resume_emit_no_repeated_completed_connections(self):
        import threading
        from unittest.mock import patch
        from scanix.native.session import scan_session
        cancelled=threading.Event()
        first=Path(self.tmp.name)/'partial.ndjson'
        report=scan_session(self.config,self.plan,self.db,first,stop=cancelled,
                            progress=lambda done,total:cancelled.set())
        self.assertEqual(report.completion_status,'interrupted')
        rows=[x for x in map(json.loads,first.read_text().splitlines()) if x['type']=='result']
        self.assertGreaterEqual(len(rows),1);self.assertLess(len(rows),4)
        prior={x['record']['port']:self.accepts[x['record']['port']] for x in rows}
        output=Path(self.tmp.name)/'resumed.ndjson'
        report=scan_session(self.config,self.plan,self.db,output,resume=True)
        self.assertEqual(report.completion_status,'complete',report.issues)
        self.assertFalse(report.results);self.assertEqual(report.completed_probes,4)
        restored=[x for x in map(json.loads,output.read_text().splitlines()) if x['type']=='result']
        self.assertEqual(sorted(x['id'] for x in restored),list(range(4)))
        for port,accepts in prior.items():self.assertEqual(self.accepts[port],accepts)
        # No-remaining-work resume replays the durable export without launching a process.
        with patch('scanix.native.adapter.subprocess.Popen',side_effect=AssertionError('unexpected child')):
            report=scan_session(self.config,self.plan,self.db,Path(self.tmp.name)/'complete.ndjson',resume=True)
        self.assertEqual(report.completion_status,'complete');self.assertEqual(report.completed_probes,4)

    def test_stream_write_failure_preserves_committed_result_and_marks_unknown_metrics(self):
        from unittest.mock import patch
        from scanix.native.session import scan_session
        with patch('scanix.native.checkpoint.ResultStream.result',side_effect=OSError('synthetic write failure')):
            report=scan_session(replace(self.config,checkpoint_batch=1),self.plan,self.db,Path(self.tmp.name)/'broken.ndjson')
        self.assertEqual(report.completion_status,'failed');self.assertGreater(report.completed_probes,0)
        output=Path(self.tmp.name)/'recovered.ndjson'
        report=scan_session(replace(self.config,checkpoint_batch=1),self.plan,self.db,output,resume=True)
        self.assertEqual(report.completed_probes,4)
        self.assertTrue(report.implementation['continuation']['prior_session_metrics_unknown'])
        self.assertIsNone(report.implementation['continuation']['coverage_loss'])

    def test_batched_stream_failure_keeps_every_committed_record(self):
        from unittest.mock import patch
        from scanix.native.session import scan_session
        with patch('scanix.native.checkpoint.ResultStream.result',side_effect=OSError('synthetic write failure')):
            with self.assertRaises(OSError):
                scan_session(self.config,self.plan,self.db,Path(self.tmp.name)/'batch-broken.ndjson')
        with closing(sqlite3.connect(self.db)) as db, db:self.assertEqual(db.execute('SELECT count(*) FROM results').fetchone()[0],4)
        report=scan_session(self.config,self.plan,self.db,Path(self.tmp.name)/'batch-recovered.ndjson',resume=True)
        self.assertEqual(report.completed_probes,4)
        self.assertTrue(report.implementation['continuation']['prior_session_metrics_unknown'])

    def test_actual_cli_stream_and_summary(self):
        from io import StringIO
        from unittest.mock import patch
        from scanix.cli import run_cli
        output=Path(self.tmp.name)/'cli.ndjson';stderr=StringIO()
        with patch('sys.stderr',stderr):
            code=run_cli(['scan','-t','127.0.0.1','-p',','.join(map(str,self.config.ports)),
                          '--engine','native','--checkpoint',str(self.db),'--stream-file',str(output)])
        self.assertEqual(code,0);self.assertIn('4/4',stderr.getvalue())
        summary=json.loads(output.read_text().splitlines()[-1])
        self.assertEqual(summary['type'],'summary');self.assertFalse(summary['incomplete'])

    def test_actual_shard_union_has_exact_coverage(self):
        from scanix.native.adapter import scan_native
        ids=[]
        for index in range(3):
            rows=[]
            report=scan_native(self.config,self.plan,selection=Selection(4,index,3),on_result=rows.append,retain=False)
            self.assertEqual(report.completion_status,'complete',report.issues)
            ids.extend(row.evidence['work_id'] for row in rows)
        self.assertEqual(sorted(ids),list(range(4)))

    def test_incompatible_resume_rejected_before_child_and_existing_output_not_overwritten(self):
        from unittest.mock import patch
        from scanix.native.session import scan_session
        scan_session(self.config,self.plan,self.db,Path(self.tmp.name)/'first.ndjson')
        with patch('scanix.native.adapter.subprocess.Popen',side_effect=AssertionError('unexpected child')):
            with self.assertRaises(ValueError):
                scan_session(replace(self.config,timeout=2),self.plan,self.db,Path(self.tmp.name)/'bad.ndjson',resume=True)
            with self.assertRaises(FileExistsError):
                scan_session(self.config,self.plan,self.db,Path(self.tmp.name)/'first.ndjson',resume=True)

    def test_actual_separate_service_stage_preserves_open_and_records_evidence(self):
        from scanix.native.session import scan_session
        # Listeners accept then close; protocol identification stays unknown while ports stay open.
        cfg=replace(self.config,service_detect=True,service_timeout=.1,engine_timeout=10)
        output=Path(self.tmp.name)/'services.ndjson'
        report=scan_session(cfg,self.plan,self.db,output)
        self.assertEqual(report.completion_status,'complete',report.issues)
        rows=[x for x in map(json.loads,output.read_text().splitlines()) if x['type']=='result']
        latest={row['id']:row['record'] for row in rows}
        self.assertEqual(len(latest),4)
        self.assertTrue(all(row['state']=='open' and row['service_detection'] for row in latest.values()))


class ContinuationCLITests(unittest.TestCase):
    def test_preview_is_offline_and_does_not_read_or_create_checkpoint(self):
        from io import StringIO
        from unittest.mock import patch
        from scanix.cli import run_cli
        output=StringIO()
        with patch('socket.socket',side_effect=AssertionError('traffic')),patch('sys.stdout',output),\
             patch('scanix.native.checkpoint.sqlite3.connect',side_effect=AssertionError('checkpoint opened')):
            code=run_cli(['scan','-t','127.0.0.0/30','-p','80,443','--engine','native',
                          '--checkpoint','unused.sqlite','--stream-file','unused.ndjson','--resume',
                          '--shard','1/3','--preview'])
        self.assertEqual(code,0)
        policy=json.loads(output.getvalue())['continuation']
        self.assertEqual(policy['selected_pairs'],1);self.assertFalse(policy['validated'])

    def test_invalid_combinations_fail_before_traffic(self):
        from io import StringIO
        from unittest.mock import patch
        from scanix.cli import run_cli
        for options in (['--resume'],['--shard','1/1'],['--shard','-1/2'],['--checkpoint','unused.sqlite'],
                        ['--checkpoint','unused.sqlite','--stream-file','unused.ndjson','--out','json']):
            with self.subTest(options=options),patch('socket.socket',side_effect=AssertionError('traffic')),\
                 patch('sys.stderr',StringIO()),self.assertRaises(SystemExit) as exit:
                run_cli(['scan','-t','127.0.0.1','-p','80','--engine','native',*options])
            self.assertEqual(exit.exception.code,2)
