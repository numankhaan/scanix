"""Protocol-1 subprocess adapter. Trusted executable, untrusted bounded wire input."""
from concurrent.futures import CancelledError
import ipaddress
import json
import math
import os
import queue
import re
import shutil
import subprocess
import threading
import time

from ..core.models import ScanReport, utc_now
from ..core.scanner import new_result
from ..core.timing import Runtime

PROTOCOL = 1
MAX_FRAME = 65536
QUEUE = 32
MAX_PORTS = 4096


def preview(config):
    return {'engine': config.engine, 'wire_protocol': 1 if config.engine == 'native' else None,
            'capabilities': ['connect'] if config.engine == 'native' else ['connect','syn','udp'],
            'session_timeout_seconds': config.engine_timeout if config.engine == 'native' else None,
            'max_ports': MAX_PORTS if config.engine == 'native' else 65535,
            'fallback': False}


def _decode(data):
    def unique(pairs):
        obj = {}
        for key,value in pairs:
            if key in obj:
                raise ValueError('duplicate engine JSON key')
            obj[key] = value
        return obj
    value = json.loads(data, object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
    if not isinstance(value,dict):
        raise ValueError('engine frame must be an object')
    return value


def _number(value, minimum=0, maximum=1_000_000):
    return type(value) in (int,float) and math.isfinite(value) and minimum <= value <= maximum


def _integer(value, minimum=0, maximum=1_000_000):
    return type(value) is int and minimum <= value <= maximum


def _run(config, targets, stop, report, binary, progress):
    command = binary or os.environ.get('SCANIX_NATIVE_ENGINE') or shutil.which('scanix-engine')
    if not command:
        raise FileNotFoundError('native engine executable not configured')
    process = subprocess.Popen([command],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,bufsize=0)
    events=queue.Queue(QUEUE);finished=threading.Event();write_lock=threading.Lock()
    errors=bytearray();threads=[]

    def put(value):
        while not finished.is_set():
            try:
                events.put(value,timeout=.05);return
            except queue.Full:
                pass

    def read():
        try:
            while not finished.is_set():
                line=process.stdout.readline(MAX_FRAME+1)
                if not line:
                    put(('eof',None));return
                if len(line)>MAX_FRAME or not line.endswith(b'\n'):
                    raise ValueError('invalid engine frame size or termination')
                put(('frame',_decode(line)))
        except (OSError,ValueError,UnicodeError) as exc:
            put(('fault',type(exc).__name__))

    def drain():
        try:
            while chunk:=process.stderr.read(4096):
                if len(errors)<8192:
                    errors.extend(chunk[:8192-len(errors)])
        except OSError:
            pass

    def send(frame):
        payload=(json.dumps(frame,allow_nan=False,separators=(',',':'))+'\n').encode()
        if len(payload)>MAX_FRAME:
            raise ValueError('request exceeds engine frame limit')
        with write_lock:
            view=memoryview(payload)
            while view:
                count=process.stdin.write(view)
                if not count:
                    raise BrokenPipeError('engine input closed')
                view=view[count:]

    def write():
        try:
            send({'type':'start','protocol':PROTOCOL,'method':config.method,'ports':list(config.ports),
                  'timeout_ms':max(1,math.ceil(config.timeout*1000)),
                  'min_timeout_ms':math.ceil(config.min_timeout*1000),
                  'max_timeout_ms':math.ceil(config.max_timeout*1000),'adaptive':config.adaptive,
                  'concurrency':config.concurrency,'per_host':config.per_host,
                  'rate':config.rate or 100,'max_targets':65536,'max_results':1_000_000,
                  'session_timeout_ms':math.ceil(config.engine_timeout*1000)})
            for target in targets:
                if stop.is_set():
                    send({'type':'cancel'});return
                send({'type':'target','ip':target.ip})
            send({'type':'run'})
        except (OSError,ValueError) as exc:
            put(('write_fault',type(exc).__name__))

    def cancel():
        try:
            send({'type':'cancel'})
        except (OSError,ValueError):
            pass

    for function in (read,drain,write):
        thread=threading.Thread(target=function,daemon=True)
        threads.append(thread);thread.start()
    started=time.monotonic();ready=False;hello=False;done=None;seen=set();fatal=False
    requested=len(targets)*len(config.ports);cancelled_at=None;done_at=None
    try:
        while True:
            now=time.monotonic()
            if stop.is_set() and cancelled_at is None:
                cancelled_at=now
                thread=threading.Thread(target=cancel,daemon=True);threads.append(thread);thread.start()
            if cancelled_at is not None and now-cancelled_at>2:
                report.issues.append({'reason':'native_cancel_grace_exhausted'});break
            if now-started > (config.engine_timeout+5 if ready else 30):
                raise TimeoutError('native engine watchdog expired')
            if done_at is not None and now-done_at>2:
                raise TimeoutError('native engine did not exit after done')
            try:
                kind,frame=events.get(timeout=.05)
            except queue.Empty:
                continue
            if kind=='eof':
                break
            if kind=='write_fault' and fatal:
                continue  # A rejected preflight can close stdin during registration.
            if kind!='frame':
                raise ValueError('native pipe or protocol failure: '+str(frame))
            if done is not None:
                raise ValueError('native frame after done')
            kind=frame.get('type')
            if not hello:
                if (kind!='hello' or frame.get('protocol')!=PROTOCOL or frame.get('engine')!='scanix-rust'
                    or not isinstance(frame.get('engine_version'),str)
                    or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',frame['engine_version'])
                    or not isinstance(frame.get('capabilities'),list)
                    or config.method not in frame['capabilities']):
                    raise ValueError('incompatible native handshake')
                report.implementation.update(engine_version=frame['engine_version'],wire_protocol=PROTOCOL)
                hello=True;continue
            if kind=='diagnostic':
                code=frame.get('code')
                if not isinstance(code,str) or not re.fullmatch(r'[a-z_]{1,64}',code) or frame.get('fatal') is not True:
                    raise ValueError('invalid native diagnostic')
                report.issues.append({'reason':'native_'+code});fatal=True
            elif kind=='ready':
                if ready or frame.get('requested')!=requested:
                    raise ValueError('invalid native ready')
                ready=True;started=time.monotonic()
            elif kind=='result':
                index=frame.get('id');target_index=frame.get('target_index');port=frame.get('port')
                if (not ready or not _integer(index,0,requested-1) or index in seen
                    or not _integer(target_index,0,len(targets)-1) or not _integer(port,1,65535)
                    or index//len(config.ports)!=target_index or config.ports[index%len(config.ports)]!=port
                    or ipaddress.ip_address(frame.get('ip'))!=ipaddress.ip_address(targets[target_index].ip)):
                    raise ValueError('duplicate or out-of-scope native result')
                allowed={'open':'connection_succeeded','closed':'connection_refused','unknown':'timeout'}
                state,reason=frame.get('state'),frame.get('reason')
                if (state not in (*allowed,'error') or (state in allowed and reason!=allowed[state])
                    or state=='error' and reason not in ('routing_failure','permission_denied','resource_exhausted','socket_error')
                    or not _number(frame.get('elapsed_seconds'),0,301)
                    or frame.get('error_code') is not None and not _integer(frame['error_code'],-2**31,2**31-1)
                    or state=='open' and frame.get('error_code') is not None):
                    raise ValueError('invalid native result evidence')
                from ..core.models import ResolvedTarget
                endpoint=targets[target_index]
                result=new_result(config,ResolvedTarget(endpoint.ip,endpoint.family),port)
                result.target=endpoint.originals[0];result.original_targets=endpoint.originals
                result.state,result.reason,result.error_code=state,reason,frame.get('error_code')
                result.connection_elapsed_seconds=frame['elapsed_seconds']
                result.evidence={'engine':'native','wire_protocol':PROTOCOL,'work_id':index}
                report.results.append(result);seen.add(index)
                if progress:
                    progress(len(seen),requested)
            elif kind=='done':
                status=frame.get('status');completed=frame.get('completed');attempted=frame.get('attempted')
                count=frame.get('requested');peak=frame.get('peak_outstanding')
                setup_cancel=status=='interrupted' and not ready and completed==0
                if (status not in ('complete','interrupted','failed') or not _integer(completed) or completed!=len(seen)
                    or not _integer(attempted,completed,requested) or not _integer(count,0,requested)
                    or not setup_cancel and count!=requested
                    or status=='complete' and (not ready or completed!=requested or attempted!=requested)
                    or not _integer(peak,0,min(config.concurrency,config.per_host))
                    or not _number(frame.get('elapsed_seconds'),0,86410)):
                    raise ValueError('invalid native completion coverage')
                done=frame;done_at=time.monotonic()
            else:
                raise ValueError('unknown native frame type')
        if process.poll() is None:
            if cancelled_at is not None:
                process.kill()
            process.wait(timeout=2)
        if done is None:
            if stop.is_set():
                report.completion_status='interrupted'
            else:
                raise ValueError('native engine exited without done')
        else:
            report.completion_status=done['status']
            report.implementation['metrics']={k:v for k,v in done.items() if k!='type'}
            expected={'complete':0,'interrupted':130,'failed':3}[done['status']]
            if process.returncode!=expected or fatal and done['status']!='failed':
                raise ValueError('native exit status contradicts protocol')
        if any(r.reason in ('permission_denied','resource_exhausted') for r in report.results):
            report.completion_status='failed'
    finally:
        finished.set()
        if process.poll() is None:
            process.kill()
        process.wait(timeout=2)
        for pipe in (process.stdin,process.stdout,process.stderr):
            try:pipe.close()
            except OSError:pass
        for thread in threads:
            thread.join(timeout=.2)
        report.implementation['exit_code']=process.returncode
        if errors:
            # Drain all stderr, retaining only a finite sanitized diagnostic excerpt.
            from ..service.parsers import clean
            report.issues.append({'reason':'native_stderr','detail':clean(errors.decode('utf-8','replace'),500)})


def scan_native(config, plan, stop=None, *, binary=None, progress=None):
    if config.engine!='native':
        raise ValueError('native adapter requires an explicit native configuration')
    stop=stop or threading.Event()
    report=ScanReport(config,implementation={'engine':'native','wire_protocol':PROTOCOL,'engine_version':None})
    targets=list(plan)
    report.requested_probes=len(targets)*len(config.ports)
    report.scope=plan.preview(config.ports,config.method,limit=0)
    report.scope['implementation']=preview(config)
    try:
        if len(config.ports)>MAX_PORTS or len(targets)>65536 or report.requested_probes>1_000_000:
            raise ValueError('native scope limit exceeded')
        if not stop.is_set():
            _run(config,targets,stop,report,binary,progress)
        if config.service_detect:
            from ..service.engine import enrich_results,policy
            from ..service.registry import load_registry
            report.probe_database_version=load_registry().version
            report.scope['service_detection']=policy(config)
            runtime=Runtime(config)
            # Conservative one-interval guard between child starts and Python enrichment.
            runtime.limiter.acquire(stop)
            enrich_results(report.results,config,stop,runtime)
    except CancelledError:
        stop.set()
    except Exception as exc:
        report.completion_status='failed'
        report.issues.append({'reason':'native_execution_failed','exception_type':type(exc).__name__,'message':str(exc)[:256]})
    finally:
        if stop.is_set():
            report.completion_status='interrupted'
        report.results.sort(key=lambda row:(row.target,row.resolved_ip or '',row.port))
        report.finished_at=utc_now()
    return report
