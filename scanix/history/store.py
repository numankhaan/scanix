"""Versioned SQLite observations with bounded ingestion and conservative comparisons."""
from contextlib import contextmanager
from dataclasses import asdict, replace
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import uuid

from ..core.models import utc_now
from ..native.adapter import _decode
from ..native.checkpoint import private_create, implementation_digest
from .. import __version__

VERSION = 1
MAX_RECORD = 65536
MAX_METADATA = 4 * 1024 * 1024
MAX_PAIRS = 1_000_000
BATCH = 16
SCHEMAS = {
    'scans': 'CREATE TABLE scans (sequence INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT UNIQUE NOT NULL, saved_at TEXT NOT NULL, metadata TEXT NOT NULL, finalized INTEGER NOT NULL DEFAULT 0)',
    'observations': 'CREATE TABLE observations (scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE, endpoint TEXT NOT NULL, work_id INTEGER NOT NULL, record TEXT NOT NULL, digest TEXT NOT NULL, PRIMARY KEY (scan_id, endpoint), UNIQUE (scan_id, work_id))',
}


def encode(value, limit):
    data = json.dumps(value, allow_nan=False, ensure_ascii=True, sort_keys=True, separators=(',', ':'))
    if len(data.encode()) > limit:
        raise ValueError('history record exceeds limit')
    return data


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{32}', value):
        raise ValueError('invalid history scan identifier')
    return value


def endpoint(record):
    if not isinstance(record, dict):
        raise ValueError('invalid history observation')
    raw_ip=record.get('resolved_ip')
    if raw_ip is not None and not isinstance(raw_ip,str):
        raise ValueError('invalid history numeric address')
    address = ipaddress.ip_address(raw_ip) if raw_ip else None
    if (type(record.get('port')) is not int or not 1 <= record['port'] <= 65535 or
            record.get('protocol') not in ('tcp', 'udp') or
            record.get('scan_method') not in ('connect','syn','udp') or
            record.get('protocol') != ('udp' if record['scan_method']=='udp' else 'tcp') or
            record.get('state') not in ('open','closed','unknown','error','filtered','open|filtered') or
            not isinstance(record.get('evidence'), dict) or
            address is not None and record.get('address_family') != 'IPv'+str(address.version)):
        raise ValueError('invalid history observation fields')
    detection=record.get('service_detection')
    if detection is not None and (not isinstance(detection,dict) or
            not isinstance(detection.get('observations',[]),list) or
            any(not isinstance(x,dict) for x in detection.get('observations',[]))):
        raise ValueError('invalid service history evidence')
    plugins=record.get('plugin_results',[])
    if (not isinstance(plugins,list) or len(plugins)>4 or any(not isinstance(p,dict) or
            not isinstance(p.get('observations',[]),list) or
            any(not isinstance(x,dict) for x in p.get('observations',[])) for p in plugins)):
        raise ValueError('invalid plugin history evidence')
    # Resolution failures retain the original target, but never compare as numeric hosts.
    target = record.get('target')
    if not isinstance(target, str) or not 1 <= len(target) <= 4096:
        raise ValueError('invalid history target')
    return encode([str(address) if address else None, target if address is None else None,
                   record['port'], record['protocol']], 8192)


def metadata(report):
    if report.schema_version != 5 or report.completion_status not in ('complete','failed','interrupted'):
        raise ValueError('unsupported report schema for history')
    data = asdict(replace(report, results=[]))
    data.pop('results')
    requested = report.requested_probes if report.requested_probes is not None else len(report.configuration.ports)
    completed = report.completed_probes if report.completed_probes is not None else len(report.results)
    if (type(requested) is not int or type(completed) is not int or
            not 0 <= completed <= requested <= MAX_PAIRS):
        raise ValueError('invalid history coverage')
    data['history_writer']={'schema_version':VERSION,'package_version':__version__,
                            'python_implementation_sha256':implementation_digest(),
                            'sqlite_version':sqlite3.sqlite_version}
    data.update(requested_ports=requested, completed_ports=completed,
                incomplete=report.completion_status!='complete' or completed<requested)
    return data


def service_identity(record):
    found = []
    detection = record.get('service_detection') or {}
    observations = list(detection.get('observations', []))
    for plugin in record.get('plugin_results', []):
        observations.extend(plugin.get('observations', []))
    for observation in observations:
        item = {key: observation.get(key) for key in ('service','product','version','transport','confidence')}
        if item not in found:
            found.append(item)
    return sorted(found, key=lambda item: encode(item, MAX_RECORD))


def stable_evidence(record):
    detection = record.get('service_detection') or {}
    return {'banner': record.get('banner'), 'version_evidence': record.get('version_evidence'),
            'evidence': {k:v for k,v in record.get('evidence',{}).items() if k not in ('engine','work_id','wire_protocol')},
            'service': {k:detection.get(k) for k in ('status','observations','tls','issues')},
            'plugins': [{k:p.get(k) for k in ('plugin_id','status','error','observations','tls')}
                        for p in record.get('plugin_results',[])]}


class History:
    def __init__(self, filename, *, create=False):
        self.db = None
        self.filename = Path(filename)
        if sqlite3.sqlite_version_info < (3,31,0):
            raise ValueError('history requires SQLite 3.31 or newer')
        parent = self.filename.parent.stat()
        if os.name=='posix' and (parent.st_uid != os.getuid() or parent.st_mode & 0o022):
            raise ValueError('history requires a trusted owner-controlled parent directory')
        try:
            status = self.filename.lstat()
        except FileNotFoundError:
            if not create:
                raise
            os.close(private_create(self.filename))
            status = self.filename.lstat()
        if not stat.S_ISREG(status.st_mode) or status.st_size > 1024**3:
            raise ValueError('history must be a bounded regular file')
        if os.name=='posix' and (status.st_uid != os.getuid() or status.st_mode & 0o077):
            raise ValueError('history requires owner-only file permissions')
        try:
            self.db = sqlite3.connect(self.filename, timeout=0, isolation_level=None)
            self.db.execute('PRAGMA trusted_schema=OFF')
            self.db.execute('PRAGMA foreign_keys=ON')
            if self.db.execute('PRAGMA trusted_schema').fetchone() != (0,) or self.db.execute('PRAGMA foreign_keys').fetchone() != (1,):
                raise ValueError('history backend safety capabilities unavailable')
            self.db.execute('PRAGMA cache_size=-2048')
            self.db.execute('PRAGMA mmap_size=0')
            self.db.execute('PRAGMA temp_store=FILE')
            self.db.execute('PRAGMA locking_mode=EXCLUSIVE')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('PRAGMA fullfsync=ON')
            if self.db.execute('PRAGMA page_size').fetchone() != (4096,):
                raise ValueError('unsupported history page size')
            if self.db.execute('PRAGMA max_page_count=262144').fetchone()[0] > 262144:
                raise ValueError('history exceeds page budget')
            version = self.db.execute('PRAGMA user_version').fetchone()[0]
            objects = self.db.execute("SELECT type,name,CASE WHEN length(sql)<4096 THEN sql END FROM sqlite_master WHERE substr(name,1,7)!='sqlite_' LIMIT 8").fetchall()
            if version==0 and not objects and create:
                # Only migration0->1 exists. Unknown layouts/versions never run arbitrary SQL.
                with self.transaction():
                    for sql in SCHEMAS.values():self.db.execute(sql)
                    self.db.execute('PRAGMA user_version=1')
            elif version!=VERSION or sorted(objects)!=sorted(('table',name,sql) for name,sql in SCHEMAS.items()):
                raise ValueError('unsupported history version or schema')
            if self.db.execute('PRAGMA journal_mode=DELETE').fetchone() != ('delete',):
                raise ValueError('unsupported history journal mode')
        except BaseException:
            self.close()
            raise

    @contextmanager
    def transaction(self):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            yield
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None

    def __enter__(self):return self
    def __exit__(self,*args):self.close()

    def _metadata(self, id):
        row = self.db.execute('SELECT CASE WHEN length(CAST(metadata AS BLOB))<=? THEN metadata END,finalized FROM scans WHERE scan_id=?',
                              (MAX_METADATA,identifier(id))).fetchone()
        if row is None:raise KeyError('history scan not found')
        if not isinstance(row[0],str):raise ValueError('history metadata exceeds limit')
        data = _decode(row[0])
        count = self.db.execute('SELECT count(*) FROM observations WHERE scan_id=?',(id,)).fetchone()[0]
        if (data.get('schema_version')!=5 or type(data.get('incomplete')) is not bool or
                type(data.get('requested_ports')) is not int or type(data.get('completed_ports')) is not int or
                not 0<=data['completed_ports']<=data['requested_ports']<=MAX_PAIRS or
                data.get('completion_status') not in ('complete','failed','interrupted')):
            raise ValueError('invalid history metadata')
        data['history'] = {'schema_version':VERSION, 'scan_id':id, 'finalized':bool(row[1]), 'stored_results':count}
        data['incomplete'] |= not bool(row[1]) or count != data['completed_ports']
        return data

    def list(self, limit=20):
        if type(limit) is not int or not 1 <= limit <= 1000:raise ValueError('history list limit must be1–1000')
        rows = self.db.execute('SELECT scan_id,saved_at FROM scans ORDER BY sequence DESC LIMIT ?',(limit,))
        for id,saved_at in rows:
            data=self._metadata(id)
            yield {'scan_id':id,'saved_at':saved_at,'completion_status':data['completion_status'],
                   'requested_ports':data['requested_ports'],'completed_ports':data['completed_ports'],
                   'incomplete':data['incomplete'],'history':data['history']}

    def show(self, id):return self._metadata(id)

    def records(self, id):
        identifier(id)
        cursor=self.db.execute('SELECT endpoint,CASE WHEN length(CAST(record AS BLOB))<=? THEN record END,digest FROM observations WHERE scan_id=? ORDER BY endpoint', (MAX_RECORD,id))
        for key,record,digest in cursor:
            if not isinstance(record,str) or hashlib.sha256(record.encode()).hexdigest()!=digest:
                raise ValueError('history observation integrity failure')
            data=_decode(record)
            if endpoint(data)!=key:raise ValueError('history observation key mismatch')
            yield key,data

    def _insert_batch(self, id, pending, *, upserts=False):
        with self.transaction():
            for work_id,record in pending:
                if type(work_id) is not int or not 0 <= work_id < MAX_PAIRS:
                    raise ValueError('invalid history work ID')
                key=endpoint(record);data=encode(record,MAX_RECORD)
                old=self.db.execute('SELECT endpoint FROM observations WHERE scan_id=? AND work_id=?',(id,work_id)).fetchone()
                if old is not None:
                    if not upserts or old[0]!=key:raise ValueError('duplicate or conflicting history work ID')
                    self.db.execute('UPDATE observations SET record=?,digest=? WHERE scan_id=? AND work_id=?',
                        (data,hashlib.sha256(data.encode()).hexdigest(),id,work_id))
                else:
                    self.db.execute('INSERT INTO observations VALUES (?,?,?,?,?)',
                        (id,key,work_id,data,hashlib.sha256(data.encode()).hexdigest()))

    def _stream(self, filename, expected):
        """Bounded existing NDJSON format; final marker is mandatory for sealing."""
        with open(filename,'rb') as stream:
            first=True;finished=False
            while line:=stream.readline(MAX_RECORD+1025):
                if len(line)>MAX_RECORD+1024 or not line.endswith(b'\n'):
                    raise ValueError('truncated or oversized history stream')
                frame=_decode(line)
                if first:
                    first=False
                    if (frame.get('type')!='header' or frame.get('stream_version')!=1 or frame.get('report_schema')!=5 or
                            encode(frame.get('configuration'),MAX_METADATA)!=encode(expected['configuration'],MAX_METADATA) or
                            frame.get('fingerprint')!=expected['implementation'].get('continuation',{}).get('fingerprint')):
                        raise ValueError('incompatible history stream header')
                elif finished:raise ValueError('history stream data after summary')
                elif frame.get('type')=='result':
                    if set(frame)!={'type','id','record'}:
                        raise ValueError('invalid history result frame')
                    yield frame['id'],frame['record']
                elif frame.get('type')=='summary':
                    if any(frame.get(k)!=expected[k] for k in ('schema_version','completion_status','completed_ports','requested_ports')):
                        raise ValueError('history stream summary mismatch')
                    finished=True
                else:raise ValueError('invalid history stream frame')
            if first or not finished:raise ValueError('history stream missing final summary')

    def save(self, report, *, stream_file=None):
        meta=metadata(report)
        if stream_file is not None:
            fingerprint=meta['implementation'].get('continuation',{}).get('fingerprint')
            if (report.configuration.engine!='native' or not isinstance(fingerprint,str) or
                    not re.fullmatch('[0-9a-f]{64}',fingerprint)):
                raise ValueError('history stream requires native continuation identity')
        if self.db.execute('SELECT count(*) FROM scans').fetchone()[0]>=10000:
            raise ValueError('history scan limit reached; prune explicitly')
        if stream_file is None and meta['completed_ports']!=len(report.results):
            raise ValueError('nonretained reports require the matching result stream')
        id=uuid.uuid4().hex
        with self.transaction():
            self.db.execute('INSERT INTO scans (scan_id,saved_at,metadata) VALUES (?,?,?)',(id,utc_now(),encode(meta,MAX_METADATA)))
        rows=self._stream(stream_file,meta) if stream_file is not None else ((i,asdict(row)) for i,row in enumerate(report.results))
        pending=[]
        try:
            for item in rows:
                work_id,record=item
                endpoint(record);encode(record,MAX_RECORD)
                if record['port'] not in report.configuration.ports or record['scan_method']!=report.configuration.method:
                    raise ValueError('history result outside configured ports/method')
                if stream_file is not None and record['evidence'].get('work_id')!=work_id:
                    raise ValueError('history stream work ID mismatch')
                pending.append(item)
                if len(pending)==BATCH:
                    batch,pending=pending,[]
                    self._insert_batch(id,batch,upserts=stream_file is not None)
        except BaseException:
            if pending:self._insert_batch(id,pending,upserts=stream_file is not None)
            raise
        if pending:self._insert_batch(id,pending,upserts=stream_file is not None)
        if self.db.execute('SELECT count(*) FROM observations WHERE scan_id=?',(id,)).fetchone()[0]!=meta['completed_ports']:
            raise ValueError('history coverage differs from recorded report')
        with self.transaction():self.db.execute('UPDATE scans SET finalized=1 WHERE scan_id=?',(id,))
        return id

    def compare(self, previous, current):
        """Two indexed iterators; absence is an observation gap, never removal."""
        old_meta,new_meta=self.show(previous),self.show(current)
        def versions(meta):
            return {'implementation':{k:meta['implementation'].get(k) for k in ('engine','engine_version','wire_protocol')},
                    'probe_database':meta.get('probe_database_version'),
                    'plugin_api':meta.get('plugin_api_version'),'plugin_registry':meta.get('plugin_registry_version'),
                    'os_database':meta.get('scope',{}).get('os_detection',{}).get('database_version'),
                    'writer':meta.get('history_writer')}
        yield {'type':'comparison','previous':previous,'current':current,
               'previous_versions':versions(old_meta),'current_versions':versions(new_meta),
               'previous_incomplete':old_meta['incomplete'],'current_incomplete':new_meta['incomplete'],
               'configuration_equal':old_meta['configuration']==new_meta['configuration'],
               'scope_policy_equal':old_meta['scope']==new_meta['scope'],
               'selected_scope_identity_assumed':False,
               'absence_semantics':'not_observed; never inferred removal or closure'}
        old,new=iter(self.records(previous)),iter(self.records(current))
        a,b=next(old,None),next(new,None)
        while a is not None or b is not None:
            if b is None or a is not None and a[0]<b[0]:
                yield {'type':'not_observed','endpoint':json.loads(a[0]),'previous_state':a[1]['state']}
                a=next(old,None)
            elif a is None or b[0]<a[0]:
                yield {'type':'new_observation','endpoint':json.loads(b[0]),'state':b[1]['state']}
                b=next(new,None)
            else:
                changes={}
                if a[1]['state']!=b[1]['state']:changes['state']={'previous':a[1]['state'],'current':b[1]['state']}
                before,after=service_identity(a[1]),service_identity(b[1])
                if before!=after:changes['service_evidence']={'previous':before,'current':after,'meaning':'observed evidence changed; absence is not service removal'}
                if stable_evidence(a[1])!=stable_evidence(b[1]):changes['evidence_changed']=True
                if changes:yield {'type':'changed','endpoint':json.loads(a[0]),'changes':changes}
                a,b=next(old,None),next(new,None)

    def delete(self, id):
        self.show(identifier(id))
        with self.transaction():self.db.execute('DELETE FROM scans WHERE scan_id=?',(id,))

    def prune(self, keep):
        if type(keep) is not int or not 0 <= keep <= 10000:raise ValueError('history retention must be0–10000')
        with self.transaction():
            cursor=self.db.execute('DELETE FROM scans WHERE sequence NOT IN (SELECT sequence FROM scans ORDER BY sequence DESC LIMIT ?)',(keep,))
        return cursor.rowcount
