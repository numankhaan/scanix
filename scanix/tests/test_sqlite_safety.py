"""Synthetic SQLite schema names must not bypass the literal reserved-prefix rule."""
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest

from scanix.core.models import ScanConfig
from scanix.core.targets import ScopePlan
from scanix.native.checkpoint import Checkpoint, manifest


class SQLiteSchemaSafetyTests(unittest.TestCase):
    def test_checkpoint_rejects_trigger_named_like_a_reserved_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory);binary=folder/'synthetic-engine';binary.write_bytes(b'synthetic not executable')
            file=folder/'checkpoint.sqlite';config=ScanConfig('127.0.0.1',(80,),engine='native')
            plan=ScopePlan(['127.0.0.1']);targets=list(plan)
            identity=manifest(config,plan,targets,binary,0,1)
            with Checkpoint(file,identity,config,targets):pass
            with closing(sqlite3.connect(file)) as db,db:
                db.execute('CREATE TRIGGER sqliteXhidden AFTER INSERT ON results BEGIN DELETE FROM results; END')
            with self.assertRaises(ValueError):
                Checkpoint(file,identity,config,targets,resume=True)

    def test_checkpoint_record_limit_counts_utf8_bytes_not_characters(self):
        import hashlib,json
        from scanix.core.scanner import new_result
        from scanix.core.models import ResolvedTarget
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory);binary=folder/'synthetic-engine';binary.write_bytes(b'synthetic not executable')
            file=folder/'checkpoint.sqlite';config=ScanConfig('127.0.0.1',(80,),engine='native')
            plan=ScopePlan(['127.0.0.1']);targets=list(plan);identity=manifest(config,plan,targets,binary,0,1)
            row=new_result(config,ResolvedTarget('127.0.0.1'),80)
            row.original_targets=('127.0.0.1',);row.evidence={'work_id':0};row.state='open'
            with Checkpoint(file,identity,config,targets) as state:state.add(row)
            with closing(sqlite3.connect(file)) as db,db:
                record=json.loads(db.execute('SELECT record FROM results').fetchone()[0])
                record['banner']='🧪'*20000;data=json.dumps(record,ensure_ascii=False)
                self.assertLess(len(data),65536);self.assertGreater(len(data.encode()),65536)
                db.execute('UPDATE results SET record=?,digest=?',(data,hashlib.sha256(data.encode()).hexdigest()))
            with self.assertRaises(ValueError):Checkpoint(file,identity,config,targets,resume=True)
