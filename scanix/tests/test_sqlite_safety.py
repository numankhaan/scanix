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
