import argparse
import importlib
import json
import signal
import sys
import threading

from .core.models import ScanConfig
from .core.ports import parse_ports
from .core.scanner import scan_target


def build_parser():
    parser = argparse.ArgumentParser(prog='scanix', description='Scanix IPv4 network reconnaissance')
    parser.add_argument('--version', action='version', version='Scanix Phase 1')
    sub = parser.add_subparsers(dest='command', required=True)
    scan = sub.add_parser('scan', help='TCP connect scan; experimental SYN available')
    scan.add_argument('-t', '--target', required=True)
    scan.add_argument('-p', '--ports', required=True, help='e.g. 22,80,443,8000-8010')
    methods = scan.add_mutually_exclusive_group()
    methods.add_argument('--connect', dest='method', action='store_const', const='connect',
                         help='TCP connect (default)')
    methods.add_argument('--syn', dest='method', action='store_const', const='syn',
                         help='experimental Scapy SYN; requires privileges, limited accuracy')
    scan.set_defaults(method='connect')
    scan.add_argument('--udp', action='store_true', help='unsupported; exits with code 2')
    scan.add_argument('--banner', action='store_true', help='best-effort plaintext banner evidence')
    scan.add_argument('--timeout', type=float, default=1.0, help='connection timeout seconds (0, 300]')
    scan.add_argument('--concurrency', type=int, default=100, help='outstanding tasks/workers (1–1024)')
    scan.add_argument('--out', choices=['json', 'csv', 'html'])
    scan.add_argument('--out-file', help='filename, or - for JSON on stdout')
    disc = sub.add_parser('discover', help='legacy system-ping sweep (outside Phase 1)')
    disc.add_argument('-n', '--network', required=True)
    trace = sub.add_parser('traceroute', help='legacy system traceroute (outside Phase 1)')
    trace.add_argument('-t', '--target', required=True)
    return parser


def _run_scan(parser, args):
    if args.udp:
        parser.error('UDP scanning is not implemented; use TCP connect scanning')
    if args.out_file and not args.out:
        parser.error('--out-file requires --out')
    if args.out_file == '-' and args.out != 'json':
        parser.error('--out-file - requires --out json')
    try:
        config = ScanConfig(args.target, parse_ports(args.ports), args.timeout,
                            args.concurrency, args.method, args.banner)
    except ValueError as exc:
        parser.error(str(exc))
    # Dependency validation precedes resolution or traffic.
    if config.method == 'syn':
        try:
            importlib.import_module('.modules.syn_scan', __package__)
        except ImportError:
            print('SYN requires the optional scapy dependency: pip install scapy', file=sys.stderr)
            return 1
        print('Warning: experimental SYN does not meet Phase 1 TCP accuracy guarantees; '
              'concurrency is fixed at 1.', file=sys.stderr)
    stop = threading.Event()
    previous_handler = signal.signal(signal.SIGINT, lambda *_: stop.set())
    try:
        report = scan_target(config, stop)
    finally:
        signal.signal(signal.SIGINT, previous_handler)
    code = {'complete': 0, 'failed': 1, 'interrupted': 130}[report.completion_status]
    try:
        if args.out_file == '-':
            json.dump(report.to_dict(), sys.stdout, indent=2, ensure_ascii=False, allow_nan=False)
            print()
        elif args.out:
            module = importlib.import_module(f'.output.save_{args.out}', __package__)
            filename = args.out_file or f'scan_results.{args.out}'
            getattr(module, f'save_{args.out}')(report, filename)
            print(f'Saved {filename}', file=sys.stderr)
        else:
            for result in report.results:
                # JSON quoting prevents untrusted target text from emitting terminal controls.
                print(f'{json.dumps(result.target, ensure_ascii=True)} '
                      f'{result.resolved_ip or "unknown"}:{result.port}/tcp '
                      f'{result.state} ({result.reason})')
    except (OSError, ValueError, TypeError) as exc:
        print(f'Output failed: {exc}', file=sys.stderr)
        return 1
    print(f'Scan {report.completion_status}: {len(report.results)}/{len(config.ports)} '
          'port results.', file=sys.stderr)
    for issue in report.issues:
        print('Scan issue: ' + json.dumps(issue, ensure_ascii=True), file=sys.stderr)
    return code


def run_cli(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == 'scan':
            return _run_scan(parser, args)
        if args.command == 'discover':
            from .modules.discovery import ping_sweep
            for host in ping_sweep(args.network):
                print(host)
        elif args.command == 'traceroute':
            from .modules.traceroute import traceroute
            for index, hop in enumerate(traceroute(args.target), 1):
                print(f'{index}\t{hop}')
        return 0
    except KeyboardInterrupt:
        print('Interrupted.', file=sys.stderr)
        return 130
    except Exception as exc:
        print(f'Scan failed: {exc}', file=sys.stderr)
        return 1
