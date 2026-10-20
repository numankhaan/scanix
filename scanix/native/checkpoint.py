"""Private, single-writer resume state, not scan history or an authenticity boundary."""
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import time

from .adapter import _decode
from .selection import Selection

FORMAT = 1
MAX_RECORD = 65536
SCHEMAS = {
    'meta': 'CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)',
    'results': 'CREATE TABLE results (id INTEGER PRIMARY KEY, record TEXT NOT NULL, digest TEXT NOT NULL)',
}


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def manifest(config, plan, targets, binary, index, count):
    """Hash resolved associations, inputs/exclusions, policy and trusted binary bytes."""
    digest = hashlib.sha256()
    with open(binary, 'rb') as stream:
        while chunk := stream.read(65536):
            digest.update(chunk)
    identity = {'format': FORMAT, 'schema': 4, 'wire': 3,
                'engine_sha256': digest.hexdigest(), 'configuration': asdict(config),
                'scope': plan.preview(config.ports, config.method, limit=0),
                'shard_index': index, 'shard_count': count}
    scope = hashlib.sha256(encode(identity).encode())
    # Incremental hashing avoids one large serialized scope allocation.
    for target in targets:
        scope.update(b'\n'); scope.update(encode(asdict(target)).encode())
    return {'format': FORMAT, 'fingerprint': scope.hexdigest(), 'engine_sha256': digest.hexdigest()}


def private_create(filename):
    """Never overwrite a report/checkpoint; require trusted existing parent directory."""
    return os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)


class Checkpoint:
    def __init__(self, filename, identity, config, targets, *, resume=False, index=0, count=1):
        if sqlite3.sqlite_version_info < (3,31,0):
            raise ValueError('checkpoint requires SQLite 3.31 or newer')
        self.db = None
        self.commit_seconds=0.0
        self.commit_count=0
        self.filename = Path(filename)
        self.config, self.targets = config, targets
        self.selection = Selection(len(targets)*len(config.ports), index, count)
        if resume:
            status = self.filename.lstat()
            if status.st_size > 1024**3 or not stat.S_ISREG(status.st_mode):
                raise ValueError('checkpoint must be a regular file')
            if os.name == 'posix' and (status.st_uid != os.getuid() or status.st_mode & 0o077):
                raise ValueError('checkpoint requires owner-only permissions')
        else:
            os.close(private_create(self.filename))
        try:
            self.db = sqlite3.connect(self.filename, timeout=0)
            # No extensions, arbitrary SQL or callbacks are accepted from the database.
            self.db.execute('PRAGMA trusted_schema=OFF')
            if self.db.execute('PRAGMA trusted_schema').fetchone() != (0,):
                raise ValueError('checkpoint backend cannot disable trusted schema')
            self.db.execute('PRAGMA cache_size=-2048')
            self.db.execute('PRAGMA mmap_size=0')
            self.db.execute('PRAGMA temp_store=MEMORY')
            self.db.execute('PRAGMA locking_mode=EXCLUSIVE')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('PRAGMA fullfsync=ON')
            # A resumed database must contain exactly these ordinary tables, no triggers/views.
            if resume:
                objects = dict(self.db.execute("SELECT name,CASE WHEN length(sql)<4096 THEN sql END FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' LIMIT 8"))
                if objects != SCHEMAS:
                    raise ValueError('unsupported checkpoint schema')
            else:
                for sql in SCHEMAS.values():
                    self.db.execute(sql)
                self.db.execute('INSERT INTO meta VALUES (?,?)', ('identity', encode(identity)))
                self.db.commit()
            if self.db.execute('PRAGMA journal_mode=DELETE').fetchone()[0] != 'delete':
                raise ValueError('checkpoint requires rollback journal support')
            if self.db.execute('PRAGMA page_size').fetchone()[0] != 4096:
                raise ValueError('unsupported checkpoint page size')
            self.db.execute('PRAGMA max_page_count=262144')  # <=1 GiB for new 4 KiB pages
            self.db.execute('BEGIN EXCLUSIVE')
            row = self.db.execute("SELECT CASE WHEN length(value)<=4096 THEN value END FROM meta WHERE key='identity'").fetchone()
            if row is None or row[0] != encode(identity):
                raise ValueError('checkpoint configuration, scope or implementation mismatch')
            self.db.commit()  # EXCLUSIVE mode retains the process lock between durable commits.
            size, maximum = self.db.execute('SELECT count(*),max(length(record)) FROM results').fetchone()
            if size > self.selection.requested or (maximum or 0) > MAX_RECORD:
                raise ValueError('checkpoint exceeds record limits')
            observed_loss=False
            for id, record in self.records():
                self._validate(id, record)
                self.selection.completed[id] = 1
                observed_loss |= self.record_loss(record)
            self._done = size
            if observed_loss:self.set_loss()
            if self.db.execute("SELECT value FROM meta WHERE key='active_session'").fetchone():
                with self.db:
                    self.db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)', ('metrics_unknown','true'))
        except BaseException:
            self.close()
            raise

    def _validate(self, id, record):
        if not self.selection.in_shard(id):
            raise ValueError('checkpoint work ID outside selected scope')
        target = self.targets[id // len(self.config.ports)]
        if (record.get('resolved_ip') != target.ip or record.get('target') != target.originals[0]
            or record.get('original_targets') != list(target.originals)
            or record.get('port') != self.config.ports[id % len(self.config.ports)]
            or record.get('scan_method') != self.config.method
            or record.get('protocol') != 'tcp' or record.get('address_family') != target.family
            or not isinstance(record.get('evidence'),dict) or record['evidence'].get('work_id') != id
            or record.get('state') not in ('open', 'closed', 'filtered', 'unknown', 'error')):
            raise ValueError('checkpoint record does not match selected probe')

    def records(self, *, after=-1):
        """Keyset iteration: at most one response-sized record outside SQLite's cache."""
        while True:
            row = self.db.execute('SELECT id,CASE WHEN length(record)<=? THEN record END,digest '
                                  'FROM results WHERE id>? ORDER BY id LIMIT 1', (MAX_RECORD, after)).fetchone()
            if row is None:
                return
            id, data, digest = row
            if data is None or hashlib.sha256(data.encode()).hexdigest() != digest:
                raise ValueError('checkpoint record integrity failure')
            record = _decode(data)
            yield id, record
            after = id

    @staticmethod
    def record_loss(record):
        data=record.get('evidence',{})
        return (data.get('send_error_code') is not None or data.get('reset_error_code') is not None
                or record.get('reason') in ('permission_denied','resource_exhausted'))

    def begin(self):
        with self.db:
            self.db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)', ('active_session','true'))

    def mark_metrics_unknown(self):
        with self.db:
            self.db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)', ('metrics_unknown','true'))

    def metrics_unknown(self):
        return self.db.execute("SELECT value FROM meta WHERE key='metrics_unknown'").fetchone() is not None

    def add(self, result):
        return self.add_batch([result])[0]

    def add_batch(self, results):
        if not 1 <= len(results) <= 64:
            raise ValueError('checkpoint batch exceeds record bound')
        rows=[];records=[];ids=set()
        for result in results:
            record=asdict(result)
            record['original_targets']=list(result.original_targets)
            data=encode(record)
            if len(data.encode()) > MAX_RECORD:
                raise ValueError('checkpoint result exceeds record limit')
            id=record['evidence']['work_id']
            self._validate(id,record)
            if self.selection.completed[id] or id in ids:
                raise ValueError('duplicate checkpoint result')
            ids.add(id);records.append(record)
            rows.append((id,data,hashlib.sha256(data.encode()).hexdigest()))
        started=time.monotonic()
        with self.db:
            self.db.executemany('INSERT INTO results VALUES (?,?,?)',rows)
        self.commit_seconds+=time.monotonic()-started
        self.commit_count+=1
        for id in ids:self.selection.completed[id]=1
        self._done+=len(ids)
        if any(self.record_loss(record) for record in records):self.set_loss()
        return records

    def update_enrichment(self, id, result):
        record = _decode(encode(asdict(result)))
        self._validate(id, record)
        data = encode(record)
        if not self.selection.completed[id] or len(data.encode()) > MAX_RECORD:
            raise ValueError('invalid enrichment checkpoint')
        with self.db:
            self.db.execute('UPDATE results SET record=?,digest=? WHERE id=?', (data, hashlib.sha256(data.encode()).hexdigest(), id))
        return record

    def set_loss(self):
        with self.db:
            self.db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)', ('coverage_loss','true'))

    def has_loss(self):
        return self.db.execute("SELECT value FROM meta WHERE key='coverage_loss'").fetchone() is not None

    def finish(self, summary):
        payload = encode(summary)
        if len(payload) > MAX_RECORD:
            raise ValueError('checkpoint summary exceeds limit')
        with self.db:
            self.db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)', ('last_session', payload))
            self.db.execute("DELETE FROM meta WHERE key='active_session'")

    @property
    def completed(self):
        return self._done

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class ResultStream:
    """Version-1 NDJSON: stable ID upserts, followed by a coverage summary."""
    def __init__(self, filename, header):
        self.stream = os.fdopen(private_create(filename), 'w', encoding='utf-8')
        try:
            self.write({'type': 'header', 'stream_version': 1, 'report_schema': 4, **header})
        except BaseException:
            self.stream.close()
            raise

    def write(self, frame):
        payload = encode(frame)
        # Header has no expanded scope/record payload; every frame is bounded.
        if len(payload.encode()) > MAX_RECORD + 1024:
            raise ValueError('stream frame exceeds limit')
        self.stream.write(payload + '\n')
        self.stream.flush()

    def result(self, id, record):
        self.write({'type': 'result', 'id': id, 'record': record})

    def close(self):
        if not self.stream.closed:
            try:
                self.stream.flush()
                os.fsync(self.stream.fileno())
            finally:
                self.stream.close()


class DurableBatch:
    """Bounded count and monotonic flush deadline; no SQLite work on extra threads."""
    def __init__(self, state, stream, limit, *, clock=time.monotonic, interval=.25):
        if type(limit) is not int or not 1 <= limit <= 64:
            raise ValueError('invalid durable batch limit')
        self.state,self.stream,self.limit=state,stream,limit
        self.clock,self.interval=clock,interval
        self.pending=[]
        self.started=None

    def submit(self, row):
        if not self.pending:self.started=self.clock()
        self.pending.append(row)
        if len(self.pending)>=self.limit:self.flush()
        else:self.tick()

    def tick(self):
        if self.pending and self.clock()-self.started>=self.interval:self.flush()

    def flush(self):
        if not self.pending:return
        batch=self.pending.copy();self.pending.clear();self.started=None
        for record in self.state.add_batch(batch):
            self.stream.result(record['evidence']['work_id'],record)
