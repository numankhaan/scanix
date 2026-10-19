"""Bounded discovery; positive evidence, explicit path errors, or no response."""
from concurrent.futures import CancelledError, FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import ExitStack
from dataclasses import replace
import ipaddress
import secrets
import threading

from ..core.models import ResolvedTarget
from ..core.scanner import scan_single_port
from ..core.timing import RateLimiter, Runtime


def local_link_method(method, family, gateway, hardware_address):
    if method == 'arp' and family != 'IPv4':
        return 'arp_requires_ipv4'
    if method == 'nd' and family != 'IPv6':
        return 'nd_requires_ipv6'
    if not ipaddress.ip_address(gateway).is_unspecified:
        return 'routed_target_not_on_link'
    if not hardware_address or hardware_address == '00:00:00:00:00:00':
        return 'ethernet_capture_required'
    return None


def echo_probe(source, destination):
    from scapy.all import ICMP, ICMPv6EchoRequest, Raw
    from .packets import ip_header
    echo = ICMPv6EchoRequest if ':' in destination else ICMP
    fields = dict(id=secrets.randbits(16), seq=secrets.randbits(16))
    if ':' not in destination:
        fields['type'] = 8
    return ip_header(source, destination)/echo(**fields)/Raw(secrets.token_bytes(16))


def classify_echo(probe, reply):
    from scapy.all import IP, ICMP, ICMPv6EchoReply, ICMPv6DestUnreach, ICMPv6TimeExceeded
    from .packets import network, same_ip, Evidence
    outer = network(reply)
    if outer is None or not same_ip(outer.dst, probe.src):
        return None
    echo, sent = outer.payload, probe.payload
    v4_reply = isinstance(echo, ICMP) and int(echo.type) == 0
    if (v4_reply or isinstance(echo, ICMPv6EchoReply)) and same_ip(outer.src, probe.dst):
        if (echo.id, echo.seq) == (sent.id, sent.seq) and bytes(echo)[8:] == bytes(sent)[8:]:
            return Evidence('up', 'echo_reply', {'responder': str(outer.src), 'matched_token': True})
    path_error = (isinstance(echo, ICMP) and int(echo.type) in (3, 11)) or isinstance(echo, (ICMPv6DestUnreach, ICMPv6TimeExceeded))
    if path_error:
        quote = echo.payload
        if (isinstance(quote, type(probe)) and same_ip(quote.src, probe.src) and same_ip(quote.dst, probe.dst)
                and (not isinstance(probe, IP) or quote.id == probe.id)):
            quoted_echo = quote.payload
            if isinstance(quoted_echo, type(sent)) and (quoted_echo.id, quoted_echo.seq) == (sent.id, sent.seq):
                return Evidence('unreachable', 'icmp_path_error', {'responder': str(outer.src),
                    'icmp_type': int(echo.type), 'icmp_code': int(echo.code), 'matched_quote': True})
    return None


def link_probe(method, source, destination, hardware_address):
    from scapy.all import Ether, ARP, IPv6, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr
    if method == 'arp':
        return Ether(src=hardware_address, dst='ff:ff:ff:ff:ff:ff')/ARP(op=1, psrc=source, pdst=destination, hwsrc=hardware_address)
    suffix = int(ipaddress.IPv6Address(destination)) & 0xffffff
    multicast = str(ipaddress.IPv6Address(int(ipaddress.IPv6Address('ff02::1:ff00:0')) | suffix))
    mac = '33:33:ff:' + ':'.join(f'{(suffix >> shift) & 255:02x}' for shift in (16, 8, 0))
    return Ether(src=hardware_address, dst=mac)/IPv6(src=source, dst=multicast, hlim=255)/ICMPv6ND_NS(tgt=destination)/ICMPv6NDOptSrcLLAddr(lladdr=hardware_address)


def classify_link(probe, reply, method, destination):
    from scapy.all import Ether, ARP, IPv6, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr
    from .packets import same_ip, Evidence
    if not isinstance(reply, Ether) or reply.dst.lower() != probe.src.lower():
        return None
    if method == 'arp':
        arp, sent = reply.payload, probe.payload
        if (isinstance(arp, ARP) and arp.op == 2 and arp.hwtype == 1 and arp.ptype == 0x800
                and arp.hwlen == 6 and arp.plen == 4
                and same_ip(arp.psrc, destination) and same_ip(arp.pdst, sent.psrc)
                and arp.hwdst.lower() == sent.hwsrc.lower() and arp.hwsrc.lower() == reply.src.lower()):
            return Evidence('up', 'arp_reply', {'responder': str(arp.psrc), 'mac': str(arp.hwsrc)})
    else:
        ip = reply.payload
        if not isinstance(ip, IPv6) or ip.hlim != 255 or not same_ip(ip.dst, probe.payload.src):
            return None
        na = ip.payload
        if (isinstance(na, ICMPv6ND_NA) and na.code == 0 and na.S == 1
                and same_ip(na.tgt, destination) and same_ip(ip.src, destination)):
            option = na.getlayer(ICMPv6NDOptDstLLAddr)
            if option is not None and option.lladdr.lower() == reply.src.lower():
                return Evidence('up', 'neighbor_advertisement', {'responder': str(ip.src), 'mac': str(option.lladdr)})
    return None


def discover_host(target, methods, ports, config, stop, runtime=None):
    runtime = runtime or Runtime(config)
    observations = []
    output = {'ip': target.ip, 'original_targets': list(target.originals), 'state': 'no_response', 'evidence': observations}
    try:
        with ExitStack() as stack:
            transports, hardware = {}, {}
            for method in methods:
                if method == 'tcp':
                    continue
                from .transport import PacketTransport
                from scapy.all import get_if_hwaddr
                transport = stack.enter_context(PacketTransport(target.ip, layer2=method in ('arp', 'nd')))
                if method in ('arp', 'nd'):
                    mac = get_if_hwaddr(transport.iface)
                    reason = local_link_method(method, target.family, transport.gateway, mac)
                    if reason:
                        observations.append({'method': method, 'state': 'error', 'reason': reason})
                        continue
                    hardware[method] = mac
                transports[method] = transport
            for method in methods:
                if stop.is_set():
                    break
                if method == 'tcp':
                    for port in ports:
                        runtime.limiter.acquire(stop)
                        effective = replace(config, target=target.originals[0], method='connect', banner=False,
                                            timeout=runtime.timeout.value() if config.adaptive else config.timeout)
                        result = scan_single_port(effective, ResolvedTarget(target.ip, target.family), port, stop)
                        state = ('up' if result.state in ('open', 'closed') else
                                 'unreachable' if result.reason == 'routing_failure' else
                                 'error' if result.state == 'error' else 'no_response')
                        observations.append({'method': method, 'port': port, 'state': state,
                                             'reason': result.reason, 'error_code': result.error_code})
                        if state == 'up':
                            if result.connection_elapsed_seconds is not None:
                                runtime.timeout.observe(result.connection_elapsed_seconds)
                            break
                elif method in transports:
                    transport = transports[method]
                    if method == 'icmp':
                        probe = echo_probe(transport.source, target.ip)
                        classify = lambda reply: classify_echo(probe, reply)
                    else:
                        probe = link_probe(method, transport.source, target.ip, hardware[method])
                        classify = lambda reply: classify_link(probe, reply, method, target.ip)
                    evidence = None
                    for attempt in range(config.retries + 1):
                        if stop.is_set():
                            break
                        timeout = runtime.timeout.value(attempt) if config.adaptive else config.timeout
                        evidence, _, rtt = transport.exchange(probe, classify, timeout, runtime.limiter, stop)
                        if evidence:
                            if attempt == 0:
                                runtime.timeout.observe(rtt)
                            break
                    observations.append({'method': method, 'state': evidence.state if evidence else 'no_response',
                        'reason': evidence.reason if evidence else ('cancelled' if stop.is_set() else 'retry_budget_exhausted'),
                        'details': evidence.details if evidence else {}})
                if any(e['state'] == 'up' for e in observations):
                    break
    except CancelledError:
        pass
    except Exception as exc:
        observations.append({'state': 'error', 'reason': 'discovery_failure',
                             'exception_type': type(exc).__name__, 'message': str(exc)[:500]})
    output['state'] = next((state for state in ('up', 'error', 'unreachable')
                            if any(e['state'] == state for e in observations)), 'no_response')
    output['interrupted'] = stop.is_set()
    return output


def discover_targets(plan, methods, ports, config, stop=None, progress=None):
    stop = stop or threading.Event()
    limiter = RateLimiter(config.rate or 10)
    results, pending = [], {}
    targets = iter(plan)
    exhausted = False
    workers = min(config.concurrency, 64)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        try:
            while pending or not exhausted:
                if stop.is_set():
                    break
                while len(pending) < workers and not exhausted and not stop.is_set():
                    target = next(targets, None)
                    if target is None:
                        exhausted = True
                    else:
                        future = executor.submit(discover_host, target, methods, ports, config, stop, Runtime(config, limiter))
                        pending[future] = target
                done, _ = wait(pending, timeout=.05, return_when=FIRST_COMPLETED) if pending else ((), ())
                for future in done:
                    target = pending.pop(future)
                    results.append(_collect(future, target))
                    if progress:
                        progress(len(results), plan.count())
        except KeyboardInterrupt:
            stop.set()
        finally:
            for future in pending:
                future.cancel()
            # Collect running results on cancellation, and observe every exception.
            executor.shutdown(wait=True, cancel_futures=True)
            for future, target in pending.items():
                if not future.cancelled():
                    results.append(_collect(future, target))
    return {'requested_hosts': plan.count(), 'completed_hosts': len(results),
            'completion_status': 'interrupted' if stop.is_set() else 'failed' if any(r['state'] == 'error' for r in results) else 'complete',
            'incomplete': stop.is_set() or len(results) < plan.count() or any(r['state'] == 'error' for r in results),
            'scope': plan.preview(ports, 'discovery', methods, limit=0), 'hosts': sorted(results, key=lambda r: r['ip'])}


def _collect(future, target):
    try:
        return future.result()
    except Exception as exc:
        return {'ip': target.ip, 'original_targets': list(target.originals), 'state': 'error',
                'evidence': [{'reason': 'worker_exception', 'exception_type': type(exc).__name__}]}


def ping_sweep(network_cidr):
    """Compatibility helper: bounded TCP discovery; use CLI for explicit methods."""
    from ..core.targets import ScopePlan
    from ..core.models import ScanConfig
    plan = ScopePlan([network_cidr])
    result = discover_targets(plan, ('tcp',), (80, 443), ScanConfig(network_cidr, (80, 443)))
    return [host['ip'] for host in result['hosts'] if host['state'] == 'up']
