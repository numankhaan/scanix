"""Fresh-process loopback comparison: aggregate vs durable stream; no raw/public traffic."""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
import tempfile
import threading
import time
import tracemalloc

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from validation.native_benchmark import usage


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',required=True)
    parser.add_argument('--ports',type=int,default=128)
    parser.add_argument('--samples',type=int,default=3)
    parser.add_argument('--batch',type=int,default=16)
    parser.add_argument('--output',required=True,help='private output file')
    parser.add_argument('--worker',choices=['aggregate','stream'],help=argparse.SUPPRESS)
    parser.add_argument('--port-list',help=argparse.SUPPRESS)
    args=parser.parse_args(argv)
    if not 1<=args.batch<=64:parser.error('batch 1–64')
    if not 2<=args.ports<=128 or not 1<=args.samples<=10:parser.error('ports 2–128; samples 1–10')
    if args.worker:
        from scanix.core.models import ScanConfig
        from scanix.core.targets import ScopePlan
        from scanix.native.adapter import scan_native
        from scanix.native.session import scan_session
        cfg=ScanConfig('127.0.0.1',tuple(map(int,args.port_list.split(','))),engine='native',
                       concurrency=16,per_host=16,rate=500,timeout=5,adaptive=False,checkpoint_batch=args.batch)
        plan=ScopePlan(['127.0.0.1'])
        with tempfile.TemporaryDirectory() as folder:
            output=Path(folder)/'results.ndjson';checkpoint=Path(folder)/'resume.sqlite'
            tracemalloc.start();start=time.monotonic()
            report=(scan_native(cfg,plan,binary=args.binary) if args.worker=='aggregate' else
                    scan_session(cfg,plan,checkpoint,output,binary=args.binary))
            elapsed=time.monotonic()-start;_,peak=tracemalloc.get_traced_memory();tracemalloc.stop()
            data=report.to_dict()
            assert report.completion_status=='complete' and data['completed_ports']==args.ports
            if args.worker=='aggregate':assert all(row.state=='open' for row in report.results)
            else:
                with output.open() as stream:
                    for line in stream:
                        row=json.loads(line)
                        if row['type']=='result':assert row['record']['state']=='open'
            continuation=report.implementation.get('continuation',{})
            result={'mode':args.worker,'elapsed_seconds':elapsed,'completed':data['completed_ports'],
                    'results_per_second':data['completed_ports']/elapsed,'usage':usage(),
                    'python_tracemalloc_peak_bytes':peak,'retained_results':len(report.results),
                    'checkpoint_bytes':checkpoint.stat().st_size if checkpoint.exists() else 0,
                    'storage_commit_seconds':continuation.get('storage_commit_seconds'),
                    'storage_commits':continuation.get('storage_commits')}
            if args.worker=='stream':
                resume_start=time.monotonic()
                resumed=scan_session(cfg,plan,checkpoint,Path(folder)/'restored.ndjson',resume=True,binary=args.binary)
                assert resumed.completion_status=='complete' and resumed.completed_probes==args.ports
                assert resumed.implementation['session_skipped']=='no_remaining_ports'
                result['completed_resume_seconds']=time.monotonic()-resume_start
            print(json.dumps(result));return
    stop=threading.Event();ports=[];threads=[];records=[]
    def serve(listener):
        listener.settimeout(.05)
        while not stop.is_set():
            try:connection,_=listener.accept();connection.close()
            except socket.timeout:continue
            except OSError:return
    with ExitStack() as stack:
        for _ in range(args.ports):
            listener=stack.enter_context(socket.socket());listener.bind(('127.0.0.1',0));listener.listen(32)
            ports.append(listener.getsockname()[1]);thread=threading.Thread(target=serve,args=(listener,));thread.start();threads.append(thread)
        try:
            for sample in range(args.samples):
                for mode in ('aggregate','stream') if sample%2==0 else ('stream','aggregate'):
                    command=[sys.executable,'-B',str(Path(__file__).resolve()),'--binary',args.binary,
                             '--ports',str(args.ports),'--samples','1','--batch',str(args.batch),'--output',args.output,
                             '--worker',mode,'--port-list',','.join(map(str,sorted(ports)))]
                    row=json.loads(subprocess.check_output(command,cwd=ROOT,text=True,timeout=60))
                    row['sample']=sample;records.append(row)
        finally:
            stop.set()
            for thread in threads:thread.join(1)
    result={'source':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
            'dirty':bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT)),
            'platform':platform.platform(),'machine':platform.machine(),'logical_cpus':os.cpu_count(),
            'python':platform.python_version(),'sqlite':__import__('sqlite3').sqlite_version,
            'config':{'checkpoint_batch':args.batch,'ports':args.ports,'rate':500,'per_host':16,'concurrency':16,'timeout':5,'adaptive':False},
            'topology':'IPv4 loopback only, ephemeral accepting listeners, all expected open',
            'scope':'Includes adapter startup, binary hash/SQLite FULL bounded-batch commit and JSONL in stream mode. '
                    'Excludes worker interpreter/import and listener setup from wall. Tracemalloc excludes Rust/SQLite C allocations. '
                    'RSS sums self/child high-water upper bounds, not simultaneous peak. No raw/SYN/scalability/parity claim.',
            'records':records}
    from scanix.native.checkpoint import private_create
    with os.fdopen(private_create(args.output),'w',encoding='utf-8') as stream:
        json.dump(result,stream,indent=2);stream.write('\n')


if __name__=='__main__':main()
