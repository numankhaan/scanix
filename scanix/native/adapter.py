"""Protocol-3 subprocess adapter. Trusted executable, untrusted bounded wire input."""
from concurrent.futures import CancelledError
import ipaddress
from itertools import islice
import json
import math
import os
import queue
import re
import shutil
import sys
import subprocess  # nosec B404: fixed argv, explicitly selected trusted engine, never a shell
import threading
import time

from ..core.models import ScanReport, utc_now
from ..core.scanner import new_result
from ..core.timing import Runtime

PROTOCOL = 3
MAX_FRAME = 65536
QUEUE = 32
MAX_PORTS = 4096


def preview(config):
    return {'engine': config.engine, 'wire_protocol': PROTOCOL if config.engine == 'native' else None,
            'capabilities': (['connect','syn_ipv4'] if sys.platform=='linux' else ['connect']) if config.engine == 'native' else ['connect','syn','udp'],
            'platform_supported': config.engine!='native' or config.method=='connect' or sys.platform=='linux',
            'syn_ipv4_only': config.engine=='native' and config.method=='syn',
            'receive_cooldown_seconds': config.syn_cooldown if config.engine=='native' and config.method=='syn' else None,
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
    try:
        value = json.loads(data, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
    except RecursionError:
        raise ValueError('engine JSON nesting exceeds parser limits') from None
    if not isinstance(value,dict):
        raise ValueError('engine frame must be an object')
    pending=[(value,0)]
    while pending:
        node,depth=pending.pop()
        if isinstance(node,(dict,list)):
            if depth>=16:
                raise ValueError('engine JSON nesting exceeds 16 levels')
            pending.extend((item,depth+1) for item in (node.values() if isinstance(node,dict) else node))
    return value


def _number(value, minimum=0, maximum=1_000_000):
    if type(value) not in (int, float) or not minimum <= value <= maximum:
        return False
    return math.isfinite(value)


def _integer(value, minimum=0, maximum=1_000_000):
    return type(value) is int and minimum <= value <= maximum


def _run(config, targets, stop, report, binary, progress, selection=None, on_result=None, retain=True, on_tick=None):
    command = binary or os.environ.get('SCANIX_NATIVE_ENGINE') or shutil.which('scanix-engine')
    if not command:
        raise FileNotFoundError('native engine executable not configured')
    process = subprocess.Popen([command],stdin=subprocess.PIPE,stdout=subprocess.PIPE,  # nosec B603: trusted executable, fixed argv, no shell
                               stderr=subprocess.PIPE,bufsize=0)
    events=queue.Queue(QUEUE);finished=threading.Event();write_lock=threading.Lock()
    stderr_bytes=0;threads=[];handshake=threading.Event()

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
        nonlocal stderr_bytes
        try:
            while chunk:=process.stderr.read(4096):
                stderr_bytes += len(chunk)
        except (OSError,ValueError):
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
            # A peer must pass compatibility checks before receiving scope or run.
            while not handshake.wait(.05):
                if finished.is_set() or stop.is_set():
                    return
            if finished.is_set() or stop.is_set():
                return
            send({'type':'start','protocol':PROTOCOL,'method':config.method,'ports':list(config.ports),
                  'timeout_ms':max(1,math.ceil(config.timeout*1000)),
                  'min_timeout_ms':math.ceil(config.min_timeout*1000),
                  'max_timeout_ms':math.ceil(config.max_timeout*1000),'adaptive':config.adaptive,
                  'concurrency':config.concurrency,'per_host':config.per_host,
                  'rate':config.rate or {'connect':100,'syn':10}[config.method],
                  'retries':config.retries,'cooldown_ms':math.ceil(config.syn_cooldown*1000),'max_targets':65536,'max_results':1_000_000,
                  'session_timeout_ms':math.ceil(config.engine_timeout*1000),
                  **({'shard_index':selection.index,'shard_count':selection.count} if selection else {})})
            for target in targets:
                if stop.is_set():
                    send({'type':'cancel'});return
                send({'type':'target','ip':target.ip})
            if selection:
                batch=[]
                for index, completed in enumerate(selection.completed):
                    if completed:
                        batch.append(index)
                        if len(batch)==4096:
                            send({'type':'completed','ids':batch});batch=[]
                if batch:send({'type':'completed','ids':batch})
            send({'type':'run'})
        except (OSError,ValueError) as exc:
            put(('write_fault',type(exc).__name__))

    def cancel():
        try:
            send({'type':'cancel'})
        except (OSError,ValueError):
            pass

    started=time.monotonic();ready=False;hello=False;done=None;fatal=False;completed_count=0;send_error=False;fatal_result_error=False
    full_count=len(targets)*len(config.ports)
    requested=selection.remaining if selection else full_count
    seen=bytearray(full_count)
    cancelled_at=None;done_at=None
    try:
        for function in (read,drain,write):
            thread=threading.Thread(target=function,daemon=True)
            threads.append(thread);thread.start()
        while True:
            if on_tick:on_tick()
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
                if (kind!='hello' or not _integer(frame.get('protocol'),PROTOCOL,PROTOCOL) or frame.get('engine')!='scanix-rust'
                    or not isinstance(frame.get('engine_version'),str)
                    or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',frame['engine_version'])
                    or not isinstance(frame.get('capabilities'),list)
                    or ('syn_ipv4' if config.method=='syn' else config.method) not in frame['capabilities']):
                    raise ValueError('incompatible native handshake')
                report.implementation.update(engine_version=frame['engine_version'],wire_protocol=PROTOCOL)
                hello=True;handshake.set();continue
            if kind=='diagnostic':
                code=frame.get('code')
                if not isinstance(code,str) or not re.fullmatch(r'[a-z_]{1,64}',code) or frame.get('fatal') is not True:
                    raise ValueError('invalid native diagnostic')
                report.issues.append({'reason':'native_'+code});fatal=True
            elif kind=='ready':
                if fatal or ready or not _integer(frame.get('requested'),requested,requested):
                    raise ValueError('invalid native ready')
                ready=True;started=time.monotonic()
            elif kind=='result':
                index=frame.get('id');target_index=frame.get('target_index');port=frame.get('port')
                if (fatal or not ready or not _integer(index,0,full_count-1) or seen[index]
                    or selection is not None and not selection.selected(index)
                    or not _integer(target_index,0,len(targets)-1) or not _integer(port,1,65535)
                    or index//len(config.ports)!=target_index or config.ports[index%len(config.ports)]!=port
                    or not isinstance(frame.get('ip'),str)
                    or ipaddress.ip_address(frame['ip'])!=ipaddress.ip_address(targets[target_index].ip)):
                    raise ValueError('duplicate or out-of-scope native result')
                allowed=({'open':('connection_succeeded',),'closed':('connection_refused',),'unknown':('timeout',)}
                         if config.method=='connect' else {'open':('syn_ack',),'closed':('syn_rst_ack',),
                         'filtered':('icmp_administratively_prohibited',),'unknown':('no_response','icmp_unreachable_or_path_error')})
                state,reason=frame.get('state'),frame.get('reason')
                if (state not in (*allowed,'error') or (state in allowed and reason not in allowed[state])
                    or state=='error' and reason not in ('routing_failure','permission_denied','resource_exhausted','socket_error')
                    or not _number(frame.get('elapsed_seconds'),0,86410 if config.method=='syn' else 301)
                    or frame.get('error_code') is not None and not _integer(frame['error_code'],-2**31,2**31-1)
                    or state=='open' and frame.get('error_code') is not None):
                    raise ValueError('invalid native result evidence')
                evidence={}
                attempts=1
                if config.method=='syn':
                    attempts=frame.get('attempts');data=frame.get('evidence')
                    if (not _integer(attempts,1,config.retries+1) or reason=='no_response' and attempts!=config.retries+1
                        or not isinstance(data,dict)
                        or type(data.get('matched_response')) is not bool or type(data.get('reset_sent')) is not bool
                        or data['matched_response'] != (state not in ('error',) and reason!='no_response')
                        or data['reset_sent'] and state!='open'
                        or data.get('icmp_code') is not None and not _integer(data['icmp_code'],0,255)
                        or data.get('reset_error_code') is not None and not _integer(data['reset_error_code'],-2**31,2**31-1)
                        or data.get('send_error_code') is not None and not _integer(data['send_error_code'],-2**31,2**31-1)
                        or data['reset_sent'] and data.get('reset_error_code') is not None
                        or reason=='icmp_administratively_prohibited' and data.get('icmp_code') not in (9,10,13)
                        or reason=='icmp_unreachable_or_path_error' and data.get('icmp_code') is None
                        or reason not in ('icmp_administratively_prohibited','icmp_unreachable_or_path_error') and data.get('icmp_code') is not None):
                        raise ValueError('invalid SYN classification evidence')
                    evidence={key:data.get(key) for key in ('matched_response','icmp_code','reset_sent','reset_error_code','send_error_code')}
                from ..core.models import ResolvedTarget
                endpoint=targets[target_index]
                result=new_result(config,ResolvedTarget(endpoint.ip,endpoint.family),port)
                result.target=endpoint.originals[0];result.original_targets=endpoint.originals
                result.state,result.reason,result.error_code=state,reason,frame.get('error_code')
                result.connection_elapsed_seconds=frame['elapsed_seconds']
                result.evidence={'engine':'native','wire_protocol':PROTOCOL,'work_id':index,**evidence}
                result.attempts=attempts
                if config.method=='syn':result.probe_type='syn'
                if on_result:on_result(result)
                if retain:report.results.append(result)
                send_error |= result.evidence.get('send_error_code') is not None
                fatal_result_error |= result.reason in ('permission_denied','resource_exhausted')
                seen[index]=1;completed_count+=1;report.completed_probes=completed_count
                if progress:
                    progress(completed_count,requested)
            elif kind=='done':
                status=frame.get('status');completed=frame.get('completed');attempted=frame.get('attempted')
                count=frame.get('requested');peak=frame.get('peak_outstanding')
                setup_cancel=status=='interrupted' and not ready and completed==0
                if (status not in ('complete','interrupted','failed') or not _integer(completed) or completed!=completed_count
                    or not _integer(attempted,completed,requested) or not _integer(count,0,requested)
                    or not setup_cancel and count!=requested
                    or status=='complete' and (not ready or completed!=requested or attempted!=requested)
                    or not _integer(peak,0,config.concurrency if config.method=='syn' else min(config.concurrency,config.per_host))
                    or not _number(frame.get('elapsed_seconds'),0,86410)
                    or frame.get('reason') is not None and (not isinstance(frame['reason'],str)
                        or not re.fullmatch(r'[a-z_]{1,64}',frame['reason']))):
                    raise ValueError('invalid native completion coverage')
                if config.method=='syn':
                    bounds={'syn_sent':requested*(config.retries+1),'retries_sent':requested*config.retries,
                            'resets_sent':requested,'send_errors':requested*(config.retries+2),
                            'queue_drops':2**64-1,'capture_drops':2**64-1}
                    if any((key not in frame and not setup_cancel) or (key in frame and not _integer(frame[key],0,maximum)
                           and not (key=='capture_drops' and frame[key] is None)) for key,maximum in bounds.items()):
                        raise ValueError('invalid SYN transmission/drop metrics')
                    optional={'peak_per_host':config.per_host,'received_packets':2**64-1,
                              'matched_responses':requested,'duplicate_responses':2**64-1,
                              'unmatched_packets':2**64-1,'late_responses':2**64-1,
                              'timeouts':requested,'cooldown_ms':1000,'receive_cooldown_ms':10000}
                    if any(key in frame and not _integer(frame[key],0,maximum) for key,maximum in optional.items()):
                        raise ValueError('invalid SYN coverage metrics')
                    if (frame.get('native_cpu_seconds') is not None and not _number(frame['native_cpu_seconds'],0,1e9)
                        or frame.get('native_peak_rss_bytes') is not None and not _integer(frame['native_peak_rss_bytes'],0,2**64-1)):
                        raise ValueError('invalid native process resource metrics')
                    if status=='complete' and (any(frame.get(key) for key in ('send_errors','queue_drops','capture_drops'))
                        or send_error):
                        raise ValueError('capture/transmission loss contradicts complete status')
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
            report.implementation['metrics']={k:done[k] for k in (
                'status','requested','completed','attempted','peak_outstanding','elapsed_seconds','reason',
                'peak_per_host','syn_sent','retries_sent','resets_sent','send_errors','received_packets','matched_responses',
                'duplicate_responses','unmatched_packets','late_responses','timeouts','queue_drops','capture_drops','cooldown_ms','receive_cooldown_ms','native_cpu_seconds','native_peak_rss_bytes') if k in done}
            expected={'complete':0,'interrupted':130,'failed':3}[done['status']]
            if process.returncode!=expected or fatal and done['status']!='failed':
                raise ValueError('native exit status contradicts protocol')
        if fatal_result_error:
            report.completion_status='failed'
    finally:
        finished.set()
        if process.poll() is None:
            process.kill()
        process.wait(timeout=2)
        for thread in threads:
            if thread.ident is not None:
                thread.join(timeout=.2)
        for pipe in (process.stdin,process.stdout,process.stderr):
            try:pipe.close()
            except OSError:pass
        report.implementation['exit_code']=process.returncode
        if stderr_bytes:
            # Arbitrary stderr can contain private paths/values. Never export it.
            report.issues.append({'reason':'native_stderr','bytes_drained':stderr_bytes})


def scan_native(config, plan, stop=None, *, binary=None, progress=None, selection=None, on_result=None, retain=True, on_tick=None):
    if config.engine!='native':
        raise ValueError('native adapter requires an explicit native configuration')
    stop=stop or threading.Event()
    report=ScanReport(config,implementation={'engine':'native','wire_protocol':PROTOCOL,'engine_version':None})
    targets=list(islice(plan,65537))
    report.requested_probes=selection.remaining if selection else len(targets)*len(config.ports)
    if not retain:report.completed_probes=0
    report.scope=plan.preview(config.ports,config.method,limit=0)
    report.scope['implementation']=preview(config)
    if selection is not None:
        report.implementation['selection']={'shard_index':selection.index,'shard_count':selection.count,
                                            'full_scope_pairs':selection.total,'restored_results':selection.done}
    try:
        if not retain and config.service_detect:
            raise ValueError('streaming enrichment must run separately from port classification')
        if selection is not None and selection.total!=len(targets)*len(config.ports):
            raise ValueError('selection scope mismatch')
        if len(config.ports)>MAX_PORTS or len(targets)>65536 or len(targets)*len(config.ports)>1_000_000:
            raise ValueError('native scope limit exceeded')
        if config.method=='syn' and (sys.platform!='linux' or any(target.family!='IPv4' for target in targets)):
            report.issues.append({'reason':'native_syn_requires_linux_ipv4'})
            raise NotImplementedError('unsupported SYN platform or address family')
        if not stop.is_set():
            _run(config,targets,stop,report,binary,progress,selection,on_result,retain,on_tick)
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
        report.issues.append({'reason':'native_execution_failed','exception_type':type(exc).__name__})
    finally:
        if stop.is_set():
            report.completion_status='interrupted'
        report.results.sort(key=lambda row:(row.target,row.resolved_ip or '',row.port))
        report.finished_at=utc_now()
    return report
