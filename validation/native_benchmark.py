"""Reproducible bounded loopback connect baseline; outputs measured data, not speed claims."""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
import threading
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def usage():
    try:
        import resource
        own=resource.getrusage(resource.RUSAGE_SELF);children=resource.getrusage(resource.RUSAGE_CHILDREN)
        scale=1 if sys.platform=='darwin' else 1024
        return {'cpu_seconds':own.ru_utime+own.ru_stime+children.ru_utime+children.ru_stime,
                'peak_rss_upper_bound_bytes':(own.ru_maxrss+children.ru_maxrss)*scale,
                'rss_semantics':'sum of self and children high-water marks; upper bound, not simultaneous peak'}
    except ImportError:
        return {'cpu_seconds':None,'peak_rss_upper_bound_bytes':None,'rss_semantics':'unavailable on this platform'}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',required=True)
    parser.add_argument('--ports',type=int,default=32)
    parser.add_argument('--samples',type=int,default=3)
    parser.add_argument('--output')
    parser.add_argument('--worker',choices=['python','native'],help=argparse.SUPPRESS)
    parser.add_argument('--port-list',help=argparse.SUPPRESS)
    args=parser.parse_args(argv)
    if not 2<=args.ports<=128 or not 1<=args.samples<=10:parser.error('ports 2–128; samples 1–10')
    if args.worker:
        from scanix.core.models import ScanConfig
        from scanix.core.scanner import scan_target
        from scanix.core.targets import ScopePlan
        from scanix.native.adapter import scan_native
        config=ScanConfig('127.0.0.1',tuple(map(int,args.port_list.split(','))),engine=args.worker,
                          concurrency=16,per_host=16,rate=500,timeout=5,adaptive=False)
        start=time.perf_counter()
        report=scan_native(config,ScopePlan(['127.0.0.1']),binary=args.binary) if args.worker=='native' else scan_target(config)
        elapsed=time.perf_counter()-start
        assert report.completion_status=='complete',report.issues
        assert all(row.state=='open' for row in report.results)
        assert len(report.results)==args.ports
        print(json.dumps({'engine':args.worker,'elapsed_seconds':elapsed,'completed':len(report.results),
                          'probes_per_second':len(report.results)/elapsed,'usage':usage(),
                          'implementation':report.implementation}));return
    stop=threading.Event();threads=[];ports=[]
    def serve(listener):
        listener.settimeout(.05)
        while not stop.is_set():
            try:
                connection,_=listener.accept();connection.close()
            except socket.timeout:continue
            except OSError:return
    records=[]
    with ExitStack() as stack:
        for _ in range(args.ports):
            listener=stack.enter_context(socket.socket());listener.bind(('127.0.0.1',0));listener.listen(32)
            ports.append(listener.getsockname()[1]);thread=threading.Thread(target=serve,args=(listener,));threads.append(thread);thread.start()
        try:
            for sample in range(args.samples):
                for engine in ('python','native') if sample%2==0 else ('native','python'):
                    command=[sys.executable,'-B',str(Path(__file__).resolve()),'--binary',args.binary,'--ports',str(args.ports),
                             '--worker',engine,'--port-list',','.join(map(str,sorted(ports)))]
                    row=json.loads(subprocess.check_output(command,cwd=ROOT,text=True,timeout=30))
                    row['sample']=sample;records.append(row)
        finally:
            stop.set()
            for thread in threads:thread.join(1)
    result={'platform':platform.platform(),'machine':platform.machine(),'logical_cpus':os.cpu_count(),
            'python':platform.python_version(),'rustc':subprocess.check_output(['rustc','--version'],text=True).strip(),
            'git_head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
            'dirty':bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT)),
            'topology':'127.0.0.1, ephemeral listening TCP ports only; one host; no raw traffic or public targets',
            'config':{'ports':args.ports,'rate':500,'concurrency':16,'per_host':16,'timeout_seconds':5,'adaptive':False},
            'caveats':'Small connect/IPC baseline, includes adapter startup; excludes interpreter launch from wall timing. No SYN or high-speed claim.',
            'records':records}
    payload=json.dumps(result,indent=2)+'\n'
    if args.output:Path(args.output).write_text(payload,encoding='utf-8')
    else:print(payload,end='')


if __name__=='__main__':main()
