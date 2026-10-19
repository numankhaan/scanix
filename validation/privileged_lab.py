#!/usr/bin/env python3
"""Opt-in Linux-only lab; all generated traffic stays in fresh network namespaces.

Run with the project virtualenv's absolute Python path and raw/admin privileges.
No dependencies are installed and no host interfaces/routes/firewall are modified.
Exit 0 = all states AND capture evidence verified, 1 = failed, 2 = unavailable.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
V4 = ('10.203.0.1', '10.203.0.2')
V6 = ('fd53:ca:1::1', 'fd53:ca:1::2')
ROUTED = ('10.204.0.2', 'fd53:ca:2::2')


def command(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, timeout=10, **kwargs).stdout


def record(path, payload):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(payload, indent=2) + '\n', encoding='utf-8')
    temporary.replace(path)


def preflight():
    if sys.platform != 'linux':
        return 'requires Linux network namespaces; host platform is ' + sys.platform
    if os.geteuid() != 0:
        return 'requires root with network/mount namespace and raw socket capabilities'
    missing = [tool for tool in ('ip', 'iptables', 'ip6tables', 'unshare', 'tcpdump') if not shutil.which(tool)]
    if missing:
        return 'missing executables: ' + ', '.join(missing)
    try:
        import scapy  # no route/capture initialization before topology setup
    except ImportError:
        return 'Scapy is unavailable in the selected Python interpreter'
    return None


def assert_isolated(parent_netns, allowed):
    if not parent_netns or os.readlink('/proc/self/ns/net') == parent_netns:
        raise RuntimeError('refusing to run outside a fresh network namespace')
    interfaces = {item['ifname'] for item in json.loads(command('ip', '-j', 'link'))}
    if interfaces - set(allowed):
        raise RuntimeError('unexpected interface in lab namespace')
    for family in ('-4', '-6'):
        if command('ip', family, 'route', 'show', 'default').strip():
            raise RuntimeError('refusing lab namespace with an external default route')


def wait_file(path, process, timeout=10):
    deadline = time.monotonic() + timeout
    while not path.exists():
        if process.poll() is not None:
            raise RuntimeError('peer exited before readiness; inspect peer.log')
        if time.monotonic() >= deadline:
            raise TimeoutError('peer readiness deadline exceeded')
        time.sleep(.02)


def peer(args):
    assert_isolated(args.parent_netns, ('lo', 'sxpeer'))
    args.output.joinpath('peer.namespace-ready').touch()
    deadline = time.monotonic() + 10
    while 'sxpeer' not in {item['ifname'] for item in json.loads(command('ip', '-j', 'link'))}:
        if time.monotonic() >= deadline:
            raise TimeoutError('veth peer was not installed')
        time.sleep(.02)
    command('ip', 'link', 'set', 'lo', 'up')
    command('ip', 'link', 'set', 'sxpeer', 'up')
    command('ip', 'addr', 'add', V4[1] + '/29', 'dev', 'sxpeer')
    command('ip', '-6', 'addr', 'add', V6[1] + '/64', 'dev', 'sxpeer', 'nodad')
    for tool, reject in (('iptables', 'icmp-admin-prohibited'), ('ip6tables', 'icmp6-adm-prohibited')):
        for protocol in ('tcp', 'udp'):
            command(tool, '-A', 'INPUT', '-p', protocol, '--dport', '19002', '-j', 'REJECT', '--reject-with', reject)
            command(tool, '-A', 'INPUT', '-p', protocol, '--dport', '19003', '-j', 'DROP')
    sockets = []
    try:
        for family, address in ((socket.AF_INET, V4[1]), (socket.AF_INET6, V6[1])):
            for kind, port in ((socket.SOCK_STREAM, 19000), (socket.SOCK_DGRAM, 53),
                               (socket.SOCK_DGRAM, 123), (socket.SOCK_DGRAM, 19000)):
                sock = socket.socket(family, kind)
                sockets.append(sock)
                if family == socket.AF_INET6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.bind((address, port))
                if kind == socket.SOCK_STREAM:
                    sock.listen(8)
        record(args.output / 'peer-topology.json', {'addresses': json.loads(command('ip', '-j', 'addr')),
               'routes_v4': json.loads(command('ip', '-j', '-4', 'route')),
               'routes_v6': json.loads(command('ip', '-j', '-6', 'route')),
               'firewall_v4': command('iptables', '-S'), 'firewall_v6': command('ip6tables', '-S')})
        args.output.joinpath('peer.ready').touch()
        while True:
            ready, _, _ = select.select(sockets, [], [], .1)
            for sock in ready:
                if sock.type == socket.SOCK_STREAM:
                    connection, _ = sock.accept()
                    connection.close()
                    continue
                data, address = sock.recvfrom(2048)
                port = sock.getsockname()[1]
                if port == 53:
                    if len(data) < 12:
                        continue
                    # Empty, nonrecursive NOERROR answer, retaining the question.
                    reply = data[:2] + struct.pack('!5H', 0x8000, 1, 0, 0, 0) + data[12:]
                elif port == 123:
                    if len(data) != 48 or data[0] & 7 != 3:
                        continue
                    stamp = struct.pack('!II', (int(time.time()) + 2208988800) % 2**32, 0)
                    reply = b'\x24\x02' + b'\0' * 22 + data[40:48] + stamp + stamp
                else:
                    reply = data
                sock.sendto(reply, address)
    finally:
        for sock in sockets:
            sock.close()


def capture_evidence(packets, cases):
    """Require real wire correlation in addition to the scan result's state."""
    from scapy.all import TCP, UDP, ARP, ICMPv6ND_NS
    from scanix.modules.packets import network, classify_syn, classify_udp
    from scanix.modules.discovery import classify_link
    checks = []
    for case in cases:
        method, target = case['method'], case['target']
        if method in ('syn', 'udp'):
            layer = TCP if method == 'syn' else UDP
            probes = [network(p) for p in packets if network(p) is not None
                      and network(p).src in (V4[0], V6[0]) and network(p).dst == target
                      and isinstance(network(p).payload, layer)
                      and network(p).payload.dport == case['port']
                      and (method == 'udp' or int(network(p).payload.flags) == 2)]
            matched = []
            for probe in probes[:1]:
                for packet in packets:
                    evidence = classify_syn(probe, packet) if method == 'syn' else classify_udp(probe, packet, case['probe_type'])
                    if evidence:
                        matched.append(evidence.state)
            wanted = case['expected']
            ok = len(probes) == case['attempts'] and (wanted in matched if wanted not in ('unknown', 'open|filtered') else not matched)
            reset_count = 0
            if method == 'syn' and wanted == 'open' and probes:
                probe = probes[0]
                responses = [network(p) for p in packets if classify_syn(probe, p) is not None
                             and classify_syn(probe, p).state == 'open']
                for packet in packets:
                    ip = network(packet)
                    if ip is None or not isinstance(ip.payload, TCP) or ip.src != probe.src or ip.dst != probe.dst:
                        continue
                    tcp = ip.payload
                    if (tcp.sport == probe.payload.sport and tcp.dport == probe.payload.dport
                            and int(tcp.flags) == 0x14 and any(tcp.seq == r.payload.ack
                            and tcp.ack == (r.payload.seq + 1) % 2**32 for r in responses)):
                        reset_count += 1
                ok = ok and reset_count > 0
            checks.append({'case': case['name'], 'passed': bool(ok), 'probe_packets': len(probes),
                           'matched_states': matched, 'validated_reset_packets': reset_count})
        elif method in ('arp', 'nd'):
            if method == 'arp':
                probes = [p for p in packets if p.haslayer(ARP) and p[ARP].op == 1 and p[ARP].pdst == target]
            else:
                probes = [p for p in packets if p.haslayer(ICMPv6ND_NS) and p[ICMPv6ND_NS].tgt == target]
            matches = any(classify_link(probe, packet, method, target) is not None for probe in probes for packet in packets)
            ok = (bool(probes) and matches) if case['expected'] == 'up' else not probes if case['expected'] == 'error' else bool(probes) and not matches
            checks.append({'case': case['name'], 'passed': bool(ok), 'probe_packets': len(probes), 'matching_link_reply': matches})
    return checks


def inside(args):
    assert_isolated(args.parent_netns, ('lo',))
    child = capture = loopback_capture = None
    report = {'status': 'failed', 'cases': [], 'capture_evidence': [], 'topology': {
        'scanner': {'IPv4': V4[0] + '/29', 'IPv6': V6[0] + '/64', 'interface': 'sxscan'},
        'peer': {'IPv4': V4[1] + '/29', 'IPv6': V6[1] + '/64', 'interface': 'sxpeer'},
        'external_default_routes': [], 'transport': 'veth pair between fresh network namespaces'}}
    try:
        command('ip', 'link', 'set', 'lo', 'up')
        with (args.output / 'peer.log').open('w') as peer_log:
            child = subprocess.Popen(['unshare', '--net', sys.executable, '-B', str(Path(__file__).resolve()),
                '--output', str(args.output), '--peer', '--parent-netns', os.readlink('/proc/self/ns/net')],
                stdout=peer_log, stderr=peer_log)
            wait_file(args.output / 'peer.namespace-ready', child)
            command('ip', 'link', 'add', 'sxscan', 'type', 'veth', 'peer', 'name', 'sxpeer')
            command('ip', 'link', 'set', 'sxpeer', 'netns', str(child.pid))
            command('ip', 'link', 'set', 'sxscan', 'up')
            command('ip', 'addr', 'add', V4[0] + '/29', 'dev', 'sxscan')
            command('ip', '-6', 'addr', 'add', V6[0] + '/64', 'dev', 'sxscan', 'nodad')
            command('ip', 'route', 'add', ROUTED[0] + '/32', 'via', V4[1], 'dev', 'sxscan')
            command('ip', '-6', 'route', 'add', ROUTED[1] + '/128', 'via', V6[1], 'dev', 'sxscan')
            wait_file(args.output / 'peer.ready', child)
            record(args.output / 'scanner-topology.json', {'addresses': json.loads(command('ip', '-j', 'addr')),
                   'routes_v4': json.loads(command('ip', '-j', '-4', 'route')),
                   'routes_v6': json.loads(command('ip', '-j', '-6', 'route'))})
            with (args.output / 'capture.log').open('w') as capture_log:
                capture = subprocess.Popen(['tcpdump', '-n', '-U', '-s', '256', '-c', '10000', '-i', 'sxscan', '-w', str(args.output / 'capture.pcap')],
                                           stdout=subprocess.DEVNULL, stderr=capture_log)
                deadline = time.monotonic() + 5
                while 'listening on' not in (args.output / 'capture.log').read_text():
                    if capture.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError('capture did not start; inspect capture.log')
                    time.sleep(.02)
                # Import Scapy after interfaces/routes exist, avoiding stale route caches.
                import scapy
                from scanix.core.models import ScanConfig, ResolvedTarget
                from scanix.core.scanner import scan_target
                from scanix.core.targets import Target
                from scanix.modules.discovery import discover_host
                import threading
                report['environment'] = {'platform': sys.platform, 'python': sys.version, 'scapy': scapy.__version__}
                for family, target in (('IPv4', V4[1]), ('IPv6', V6[1])):
                    for method, ports in (('syn', (19000, 19001, 19002, 19003)), ('udp', (53, 123, 19000, 19001, 19002, 19003))):
                        cfg = ScanConfig(target, ports, timeout=.75, method=method, concurrency=1,
                                         per_host=1, adaptive=False, retries=1, rate=4)
                        result = scan_target(cfg, endpoint=ResolvedTarget(target, family))
                        record(args.output / f'{family}-{method}.json', result.to_dict())
                        for port in ports:
                            expected = ('open' if port in (53, 123, 19000) else 'closed' if port == 19001
                                        else 'filtered' if port == 19002 else 'unknown' if method == 'syn' else 'open|filtered')
                            rows = [row for row in result.results if row.port == port]
                            row = rows[0] if len(rows) == 1 else None
                            report['cases'].append({'name': f'{family}-{method}-{port}', 'method': method, 'target': target,
                                'port': port, 'expected': expected, 'observed': row.state if row else None,
                                'passed': result.completion_status == 'complete' and row is not None and row.state == expected,
                                'probe_type': row.probe_type if row else None, 'attempts': row.attempts if row else 0})
                    for method, address, expected in (('arp' if family == 'IPv4' else 'nd', target, 'up'),
                            ('arp' if family == 'IPv4' else 'nd', '10.203.0.3' if family == 'IPv4' else 'fd53:ca:1::3', 'no_response'),
                            ('arp' if family == 'IPv4' else 'nd', ROUTED[0] if family == 'IPv4' else ROUTED[1], 'error')):
                        discovery = discover_host(Target(address, (address,)), (method,), (19000,), cfg, threading.Event())
                        name = f'{family}-{method}-{expected}'
                        record(args.output / (name + '.json'), discovery)
                        report['cases'].append({'name': name, 'method': method, 'target': address,
                            'expected': expected, 'observed': discovery['state'], 'passed': discovery['state'] == expected
                            and (expected != 'error' or any(e.get('reason') == 'routed_target_not_on_link' for e in discovery['evidence']))})
                # Exercise the existing opt-in raw loopback tests in this same
                # isolated namespace. Capture lo separately from Ethernet.
                with (args.output / 'loopback-capture.log').open('w') as loopback_log:
                    loopback_capture = subprocess.Popen(['tcpdump', '-n', '-U', '-s', '256', '-c', '10000',
                        '-i', 'lo', '-w', str(args.output / 'loopback.pcap')],
                        stdout=subprocess.DEVNULL, stderr=loopback_log)
                    deadline = time.monotonic() + 5
                    while 'listening on' not in (args.output / 'loopback-capture.log').read_text():
                        if loopback_capture.poll() is not None or time.monotonic() > deadline:
                            raise RuntimeError('loopback capture did not start')
                        time.sleep(.02)
                    with (args.output / 'loopback-tests.log').open('w') as test_log:
                        result = subprocess.run([sys.executable, '-B', '-m', 'unittest',
                            'scanix.tests.test_integration_optional', '-v'], cwd=ROOT,
                            env=dict(os.environ, SCANIX_PRIVILEGED_TESTS='1'),
                            stdout=test_log, stderr=test_log, timeout=30)
                    loopback_capture.send_signal(signal.SIGINT)
                    loopback_capture.wait(timeout=10)
                    report['loopback_tests'] = {'exit_code': result.returncode,
                        'passed': result.returncode == 0,
                        'capture_sha256': hashlib.sha256((args.output / 'loopback.pcap').read_bytes()).hexdigest()}
                capture.send_signal(signal.SIGINT)
                capture.wait(timeout=10)
                from scapy.all import rdpcap
                packets = rdpcap(str(args.output / 'capture.pcap'))
                report['capture_evidence'] = capture_evidence(packets, report['cases'])
                report['capture_sha256'] = hashlib.sha256((args.output / 'capture.pcap').read_bytes()).hexdigest()
                report['packet_count'] = len(packets)
                if all(case['passed'] for case in report['cases']) and all(check['passed'] for check in report['capture_evidence']) and report['loopback_tests']['passed']:
                    report['status'] = 'passed'
    except Exception as exc:
        report['error'] = {'type': type(exc).__name__, 'message': str(exc)}
    finally:
        for process in (loopback_capture, capture, child):
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        record(args.output / 'results.json', report)
    return 0 if report['status'] == 'passed' else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='new output directory; never overwrite previous evidence')
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--peer', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--parent-netns', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    args.output = args.output.resolve()
    if args.peer:
        peer(args)
        return 0
    if args.inside:
        return inside(args)
    args.output.mkdir(parents=True, exist_ok=False)
    reason = preflight()
    if reason:
        record(args.output / 'results.json', {'status': 'unavailable', 'reason': reason,
               'cases': [], 'capture_evidence': [], 'packets_sent': 0})
        print(reason, file=sys.stderr)
        return 2
    result = subprocess.run(['unshare', '--net', '--mount', '--propagation', 'private', '--pid', '--fork', '--kill-child', '--mount-proc',
        sys.executable, '-B', str(Path(__file__).resolve()), '--output', str(args.output),
        '--inside', '--parent-netns', os.readlink('/proc/self/ns/net')])
    if not (args.output / 'results.json').exists():
        record(args.output / 'results.json', {'status': 'unavailable', 'reason': 'namespace setup failed',
                                             'exit_code': result.returncode, 'cases': [], 'capture_evidence': []})
    return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())
