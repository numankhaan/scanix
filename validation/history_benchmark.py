"""Synthetic local SQLite baseline. No network, scan findings or raw evidence output."""
from dataclasses import replace
import argparse
import json
from pathlib import Path
import platform
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def run(rows, samples):
    from scanix.core.models import ScanConfig, ScanReport, ScanResult
    from scanix.history import History
    from scanix.native.checkpoint import implementation_digest
    if type(rows) is not int or not 32 <= rows <= 4096 or type(samples) is not int or not 1 <= samples <= 5:
        raise ValueError('benchmark rows32–4096, samples1–5')
    config = ScanConfig('192.0.2.1', tuple(range(1, rows+1)))
    results = [ScanResult(config.target, config.target, 'IPv4', port, state='open',
                          reason='synthetic_benchmark') for port in config.ports]
    source = ScanReport(config, results)
    changed = replace(source, results=[replace(row, state='closed') for row in results])
    records = []
    for _ in range(samples):
        with tempfile.TemporaryDirectory(prefix='scanix-history-bench-') as directory:
            filename = Path(directory)/'synthetic.sqlite'
            with History(filename, create=True) as history:
                cpu = time.process_time(); start = time.monotonic()
                a = history.save(source); b = history.save(changed)
                save_seconds = time.monotonic()-start
                start = time.monotonic()
                count = sum(x['type']=='changed' for x in history.compare(a,b))
                diff_seconds = time.monotonic()-start
                assert count == rows
                assert not history.show(b)['incomplete']
                records.append({'save_two_scans_seconds':save_seconds,'compare_seconds':diff_seconds,
                                'observations_saved':rows*2,'changes_observed':count,
                                'observations_per_second':rows*2/save_seconds,
                                'cpu_seconds_save_and_compare':time.process_time()-cpu,
                                'main_database_bytes':filename.stat().st_size})
    try:
        import resource
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * (1 if sys.platform=='darwin' else 1024)
    except ImportError:
        peak = None
    return {'benchmark_version':1,'git_head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
            'dirty':bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT)),
            'python_runtime_sha256':implementation_digest(),'python':platform.python_version(),
            'sqlite':sqlite3.sqlite_version,'platform':platform.platform(),'machine':platform.machine(),
            'rows_per_scan':rows,'samples':samples,'records':records,
            'median_observations_per_second':statistics.median(x['observations_per_second'] for x in records),
            'process_peak_rss_bytes':peak,
            'scope':'synthetic reports only; no packets; two aggregate reports retained by fixture; CPU includes save+compare; RSS is whole-process high-water, not streaming-memory evidence'}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rows',type=int,default=256);parser.add_argument('--samples',type=int,default=3)
    args=parser.parse_args()
    try:
        print(json.dumps(run(args.rows,args.samples),sort_keys=True))
    except Exception as exc:
        print('History benchmark failed: '+type(exc).__name__+'; inspect privately',file=sys.stderr)
        raise SystemExit(1)
