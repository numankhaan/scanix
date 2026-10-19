import argparse
import importlib
import json
import signal
import sys
import threading

from .core.models import ScanConfig
from .core.ports import parse_ports
from .core.scanner import scan_target


def add_scope_options(parser):
    parser.add_argument('--target-file', action='append', default=[], help='UTF-8, one target per line; # comments')
    parser.add_argument('--exclude', action='append', default=[], help='excluded IP, hostname or CIDR; repeatable')
    parser.add_argument('--exclude-file', action='append', default=[])
    parser.add_argument('--family', choices=['4', '6', 'any'], default='4', help='default IPv4')
    parser.add_argument('--dns-policy', choices=['first', 'all'], default='first', help='system answer order; default first')
    parser.add_argument('--max-targets', type=int, default=4096, help='input address budget, maximum 65536')
    parser.add_argument('--preview', action='store_true', help='offline scope preview; no DNS or probe traffic')
    parser.add_argument('--resolve-preview', action='store_true', help='allow DNS in preview; no probes')


def add_timing_options(parser, discovery=False):
    defaults = 'discovery=10' if discovery else 'connect=100, SYN=10, UDP=1'
    parser.add_argument('--rate', type=float, help='global probes/sec (raw includes retries/resets); defaults ' + defaults)
    parser.add_argument('--per-host', type=int, default=8, help='per-host outstanding tasks; default 8')
    parser.add_argument('--retries', type=int, default=1, help='raw retries after first attempt, 0–5; connect never retries')
    parser.add_argument('--min-timeout', type=float, default=.1)
    parser.add_argument('--max-timeout', type=float, default=5)
    parser.add_argument('--fixed-timeout', action='store_true', help='disable RTT adaptation and timeout backoff')


def scope_from_args(args):
    from .core.targets import ScopePlan, read_target_file
    inputs, exclusions = list(args.target), list(args.exclude)
    for filename in args.target_file:
        inputs.extend(read_target_file(filename))
    for filename in args.exclude_file:
        exclusions.extend(read_target_file(filename))
    return ScopePlan(inputs, exclusions, family=args.family, dns_policy=args.dns_policy,
                     max_targets=args.max_targets, offline=args.preview and not args.resolve_preview)


def selected_discovery(value):
    methods = tuple(dict.fromkeys(value.split(',')))
    if methods == ('none',):
        return ()
    if not methods or any(m not in ('icmp', 'tcp', 'arp', 'nd') for m in methods):
        raise ValueError('discovery methods must be icmp,tcp,arp,nd or none')
    return methods


def build_parser():
    parser = argparse.ArgumentParser(prog='scanix', description='Scanix bounded IPv4/IPv6 network reconnaissance')
    parser.add_argument('--version', action='version', version='Scanix Phase 4B (development)')
    sub = parser.add_subparsers(dest='command', required=True)
    scan = sub.add_parser('scan', help='TCP connect, raw SYN or protocol-aware UDP scan')
    scan.add_argument('-t', '--target', action='append', default=[], help='IP, hostname or CIDR; repeatable')
    scan.add_argument('-p', '--ports', required=True, help='e.g. 22,80,443,8000-8010')
    methods = scan.add_mutually_exclusive_group()
    methods.add_argument('--connect', dest='method', action='store_const', const='connect',
                         help='TCP connect (default)')
    methods.add_argument('--syn', dest='method', action='store_const', const='syn',
                         help='validated raw SYN; requires capture privileges')
    scan.set_defaults(method='connect')
    methods.add_argument('--udp', dest='method', action='store_const', const='udp', help='protocol-aware UDP; requires raw capture privileges')
    scan.add_argument('--service-detect', action='store_true', help='bounded protocol/TLS identification of confirmed open ports')
    scan.add_argument('--service-profile', choices=['quick', 'deep'], default='quick', help='quick: 3 connections/3s; deep: 5 connections/8s per open endpoint')
    scan.add_argument('--service-timeout', type=float, help='total seconds per open endpoint, 0.1–30')
    scan.add_argument('--service-workers', type=int, default=4, help='enrichment workers, bounded by scan concurrency and per-host limit')
    verify = scan.add_mutually_exclusive_group()
    verify.add_argument('--tls-insecure', action='store_true', help='inspect self-signed lab TLS; certificate verification is disabled and reported')
    verify.add_argument('--tls-ca-file', help='PEM CA bundle for verified lab TLS')
    scan.add_argument('--sni', help='TLS SNI/verification name override; connection remains at selected numeric address')
    scan.add_argument('--starttls', action='store_true', help='try advertised SMTP/POP3/IMAP TLS upgrade during service detection')
    scan.add_argument('--allow-excluded-probes', action='store_true', help='allow active service probes on excluded printer/spooler ports')
    scan.add_argument('--engine', choices=['python','native'], default='python', help='explicit engine; Python remains the default')
    scan.add_argument('--native-binary', help='trusted native executable path; otherwise SCANIX_NATIVE_ENGINE or PATH')
    scan.add_argument('--syn-cooldown', type=float, default=.2, help='native SYN final receive cooldown seconds (0–1)')
    scan.add_argument('--engine-timeout', type=float, default=3600, help='native session budget seconds, 0.1–86400')
    scan.add_argument('--banner', action='store_true', help='best-effort plaintext banner evidence')
    scan.add_argument('--timeout', type=float, default=1.0, help='connection timeout seconds (0, 300]')
    scan.add_argument('--concurrency', type=int, default=100, help='outstanding tasks/workers (1–1024)')
    add_scope_options(scan)
    add_timing_options(scan)
    scan.add_argument('--discovery', default='none', help='comma-separated icmp,tcp,arp,nd; default none')
    scan.add_argument('--skip-discovery', action='store_true', help='scan every effective target')
    scan.add_argument('--discovery-ports', default='80,443', help='TCP discovery ports')
    scan.add_argument('--progress', action='store_true', help='completed/selected probes on stderr')
    scan.add_argument('--out', choices=['json', 'csv', 'html'])
    scan.add_argument('--out-file', help='filename, or - for JSON on stdout')
    disc = sub.add_parser('discover', help='bounded ICMP/TCP/ARP/IPv6 neighbor discovery')
    disc.add_argument('-n', '--network', dest='target', action='append', default=[], help='legacy alias for --target')
    disc.add_argument('-t', '--target', dest='target', action='append', help='IP, hostname or CIDR; repeatable')
    add_scope_options(disc)
    add_timing_options(disc, discovery=True)
    disc.add_argument('--methods', default='tcp', help='comma-separated icmp,tcp,arp,nd; default tcp')
    disc.add_argument('-p', '--ports', default='80,443', help='TCP discovery ports (at most 16)')
    disc.add_argument('--timeout', type=float, default=1)
    disc.add_argument('--concurrency', type=int, default=16, help='parallel hosts, capped at 64')
    disc.add_argument('--out-file', help='JSON report path; default stdout')
    disc.add_argument('--progress', action='store_true')
    trace = sub.add_parser('traceroute', help='legacy system traceroute (outside Phase 1)')
    trace.add_argument('-t', '--target', required=True)
    return parser


def _run_scan(parser, args):
    if args.out_file and not args.out:
        parser.error('--out-file requires --out')
    if args.out_file == '-' and args.out != 'json':
        parser.error('--out-file - requires --out json')
    try:
        if not args.target and not args.target_file:
            raise ValueError('provide --target or --target-file')
        if args.resolve_preview and not args.preview:
            raise ValueError('--resolve-preview requires --preview')
        methods = () if args.skip_discovery else selected_discovery(args.discovery)
        if args.engine=='native' and methods:
            raise ValueError('native foundation does not support discovery gates; select --discovery none')
        if args.native_binary and args.engine!='native':
            raise ValueError('--native-binary requires --engine native')
        discovery_ports = parse_ports(args.discovery_ports)
        if len(discovery_ports) > 16:
            raise ValueError('select at most 16 TCP discovery ports')
        config = ScanConfig(args.target[0] if args.target else 'target-file', parse_ports(args.ports), args.timeout,
                            args.concurrency, args.method, args.banner, args.retries, args.rate,
                            args.per_host, args.min_timeout, args.max_timeout, not args.fixed_timeout,
                            service_detect=args.service_detect, service_profile=args.service_profile,
                            service_timeout=args.service_timeout, service_workers=args.service_workers,
                            tls_insecure=args.tls_insecure, tls_ca_file=args.tls_ca_file, sni=args.sni,
                            starttls=args.starttls, allow_excluded_probes=args.allow_excluded_probes,
                            engine=args.engine,engine_timeout=args.engine_timeout,syn_cooldown=args.syn_cooldown)
    except ValueError as exc:
        parser.error(str(exc))
    # Validate CLI/config before DNS, sockets or capture. Offline preview requires no Scapy.
    simple = (len(args.target) == 1 and not args.target_file and not args.exclude and not args.exclude_file
              and args.family == '4' and args.dns_policy == 'first' and '/' not in args.target[0]
              and not methods and not args.preview and args.engine=='python')
    plan = None
    if simple:
        try:
            from .core.targets import ScopePlan
            ScopePlan(args.target, family='4', max_targets=args.max_targets, offline=True)
        except ValueError as exc:
            parser.error(str(exc))
    if not simple:
        try:
            plan = scope_from_args(args)
            if plan.count() * len(config.ports) > 1000000:
                raise ValueError('scope exceeds 1,000,000 port results; split the input')
        except (ValueError, OSError) as exc:
            parser.error(str(exc))
    if args.preview:
        data = plan.preview(config.ports, config.method, methods)
        data['timing'] = {'rate': config.rate or {'connect': 100, 'syn': 10, 'udp': 1}[config.method],
                          'per_host': min(config.concurrency, config.per_host), 'retries': 0 if config.method == 'connect' else config.retries,
                          'adaptive': config.adaptive, 'timeout': config.timeout,
                          'min_timeout': config.min_timeout, 'max_timeout': config.max_timeout}
        from .service.engine import policy
        data['service_detection'] = policy(config)
        from .native.adapter import preview
        data['implementation'] = preview(config)
        json.dump(data, sys.stdout, indent=2)
        print()
        return 0
    if methods and any(method != 'tcp' for method in methods):
        try:
            importlib.import_module('.modules.transport', __package__)
        except ImportError:
            print('Raw discovery requires Scapy: pip install scapy', file=sys.stderr)
            return 1
    if config.method in ('syn', 'udp'):
        try:
            importlib.import_module(f'.modules.{config.method}_scan', __package__)
        except ImportError:
            print('Raw scans require Scapy: pip install scapy', file=sys.stderr)
            return 1
    stop = threading.Event()
    previous_handler = signal.signal(signal.SIGINT, lambda *_: stop.set())
    try:
        if args.engine=='native':
            from .native.adapter import scan_native
            progress=(lambda done,total: print(f'Progress: {done}/{total} completed port results',file=sys.stderr)) if args.progress else None
            report=scan_native(config,plan,stop,binary=args.native_binary,progress=progress)
        elif plan is None:
            if args.progress:
                report = scan_target(config, stop, progress=lambda done, total: print(
                    f'Progress: {done}/{total} completed port results', file=sys.stderr))
            else:
                report = scan_target(config, stop)
        else:
            from .core.scope_scan import scan_scope
            progress = (lambda done, total: print(f'Progress: {done}/{total} completed port results', file=sys.stderr)) if args.progress else None
            report = scan_scope(config, plan, stop, discovery_methods=methods,
                                discovery_ports=discovery_ports, progress=progress)
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
            from .service.parsers import clean
            for result in report.results:
                # JSON quoting prevents untrusted target text from emitting terminal controls.
                print(f'{json.dumps(result.target, ensure_ascii=True)} '
                      f'{result.resolved_ip or "unknown"}:{result.port}/{result.protocol} '
                      f'{result.state} ({result.reason})')
                if result.service_detection:
                    for observation in result.service_detection.observations:
                        print('  ' + clean(f'{observation.service} {observation.product or ""} {observation.version or ""} [{observation.confidence}; {observation.transport}]'))
    except (OSError, ValueError, TypeError) as exc:
        print(f'Output failed: {exc}', file=sys.stderr)
        return 1
    print(f"Scan {report.completion_status}: {len(report.results)}/{report.to_dict()['requested_ports']} "
          'port results.', file=sys.stderr)
    for issue in report.issues:
        print('Scan issue: ' + json.dumps(issue, ensure_ascii=True), file=sys.stderr)
    return code


def _run_discovery(parser, args):
    try:
        methods = selected_discovery(args.methods)
        if not methods:
            raise ValueError('select at least one discovery method')
        ports = parse_ports(args.ports)
        if len(ports) > 16:
            raise ValueError('select at most 16 TCP discovery ports')
        if args.resolve_preview and not args.preview:
            raise ValueError('--resolve-preview requires --preview')
        config = ScanConfig('discovery', ports, args.timeout, args.concurrency,
                            retries=args.retries, rate=args.rate, per_host=args.per_host,
                            min_timeout=args.min_timeout, max_timeout=args.max_timeout,
                            adaptive=not args.fixed_timeout)
        plan = scope_from_args(args)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    if args.preview:
        json.dump(plan.preview(ports, 'discovery', methods), sys.stdout, indent=2)
        print()
        return 0
    if any(method != 'tcp' for method in methods):
        try:
            importlib.import_module('.modules.transport', __package__)
        except ImportError:
            print('Raw discovery requires Scapy: pip install scapy', file=sys.stderr)
            return 1
    from .modules.discovery import discover_targets
    stop = threading.Event()
    previous = signal.signal(signal.SIGINT, lambda *_: stop.set())
    try:
        progress = (lambda done, total: print(f'Progress: {done}/{total} hosts', file=sys.stderr)) if args.progress else None
        payload = discover_targets(plan, methods, ports, config, stop, progress)
    finally:
        signal.signal(signal.SIGINT, previous)
    if args.out_file and args.out_file != '-':
        from .output.common import atomic_text
        with atomic_text(args.out_file) as stream:
            json.dump(payload, stream, indent=2, allow_nan=False)
    else:
        json.dump(payload, sys.stdout, indent=2, allow_nan=False)
        print()
    return {'complete': 0, 'failed': 1, 'interrupted': 130}[payload['completion_status']]


def run_cli(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == 'scan':
            return _run_scan(parser, args)
        if args.command == 'discover':
            return _run_discovery(parser, args)
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
