"""Pure packet builders/classifiers. Importing this module opens no sockets."""
from ..core.udp_protocols import udp_payload, match_udp_payload
from dataclasses import dataclass
import ipaddress
import secrets
import struct
import time

from scapy.all import IP, IPv6, TCP, UDP, Raw, ICMP, ICMPv6DestUnreach, ICMPv6TimeExceeded, ICMPv6ParamProblem


@dataclass(frozen=True)
class Evidence:
    state: str
    reason: str
    details: dict


def network(packet):
    # Only the outer IP header, never an IP header quoted inside an ICMP error.
    if isinstance(packet, (IP, IPv6)):
        return packet
    payload = getattr(packet, 'payload', None)
    return payload if isinstance(payload, (IP, IPv6)) else None


def same_ip(a, b):
    try:
        return ipaddress.ip_address(str(a).split('%')[0]) == ipaddress.ip_address(str(b).split('%')[0])
    except ValueError:
        return False


def ip_header(source, destination):
    if ipaddress.ip_address(destination).version == 6:
        return IPv6(src=source, dst=destination)
    return IP(src=source, dst=destination, id=secrets.randbits(16))


def probe_source_port(destination_port):
    # Reversed endpoints must differ even on loopback. Otherwise an outgoing
    # generic UDP request can match itself when its source port equals dport.
    excluded = 49152 <= destination_port <= 65535
    candidate = 49152 + secrets.randbelow(16384 - int(excluded))
    return candidate + int(excluded and candidate >= destination_port)


def syn_probe(source, destination, port):
    return ip_header(source, destination) / TCP(sport=probe_source_port(port),
                                              dport=port, flags='S', seq=secrets.randbits(32))


def reset_probe(probe, reply):
    tcp = network(reply).payload
    return ip_header(probe.src, probe.dst) / TCP(sport=probe.payload.sport,
        dport=probe.payload.dport, flags='RA', seq=int(tcp.ack), ack=(int(tcp.seq) + 1) % 2**32)




def udp_probe(source, destination, port):
    kind, payload = udp_payload(port)
    packet = ip_header(source, destination) / UDP(sport=probe_source_port(port), dport=port) / Raw(payload)
    # Materialize checksum/length so even minimum-length ICMP quotations can match.
    return kind, packet.__class__(bytes(packet))




def quoted_error(probe, reply):
    outer = network(reply)
    if outer is None or not same_ip(outer.dst, probe.src):
        return None
    error = outer.payload
    ipv6 = isinstance(probe, IPv6)
    if ipv6:
        if not isinstance(error, (ICMPv6DestUnreach, ICMPv6TimeExceeded, ICMPv6ParamProblem)):
            return None
    elif not isinstance(error, ICMP) or int(error.type) not in (3, 11, 12):
        return None
    quote = error.payload
    if not isinstance(quote, type(probe)) or not same_ip(quote.src, probe.src) or not same_ip(quote.dst, probe.dst):
        return None
    if not ipv6 and int(quote.id) != int(probe.id):
        return None
    sent, quoted = probe.payload, quote.payload
    if not isinstance(quoted, type(sent)) or int(quoted.sport) != int(sent.sport) or int(quoted.dport) != int(sent.dport):
        return None
    if isinstance(sent, TCP) and int(quoted.seq) != int(sent.seq):
        return None
    if isinstance(sent, UDP) and bytes(quoted)[:8] != bytes(sent)[:8]:
        return None
    details = {'icmp_family': 6 if ipv6 else 4, 'icmp_type': int(error.type),
               'icmp_code': int(error.code), 'responder': str(outer.src), 'matched_quote': True}
    if ipv6:
        if isinstance(error, ICMPv6DestUnreach):
            if int(error.code) == 4 and isinstance(sent, UDP):
                return Evidence('closed', 'icmp_port_unreachable', details)
            if int(error.code) in (1, 5, 6):
                return Evidence('filtered', 'icmp_administratively_prohibited', details)
    elif int(error.type) == 3:
        if int(error.code) == 3 and isinstance(sent, UDP):
            return Evidence('closed', 'icmp_port_unreachable', details)
        if int(error.code) in (9, 10, 13):
            return Evidence('filtered', 'icmp_administratively_prohibited', details)
    return Evidence('unknown', 'icmp_unreachable_or_path_error', details)


def classify_syn(probe, reply):
    error = quoted_error(probe, reply)
    if error:
        return error
    outer = network(reply)
    if outer is None or not same_ip(outer.src, probe.dst) or not same_ip(outer.dst, probe.src):
        return None
    tcp = outer.payload
    sent = probe.payload
    if not isinstance(tcp, TCP) or int(tcp.sport) != int(sent.dport) or int(tcp.dport) != int(sent.sport):
        return None
    flags = int(tcp.flags)
    # RST without ACK cannot be safely correlated to this SYN's sequence number.
    if not flags & 0x10 or int(tcp.ack) != (int(sent.seq) + 1) % 2**32:
        return None
    details = {'responder': str(outer.src), 'tcp_flags': flags, 'matched_ack': True}
    if flags & 0x17 == 0x14:
        return Evidence('closed', 'syn_rst_ack', details)
    if flags & 0x3f == 0x12:
        return Evidence('open', 'syn_ack', details)
    return None


def classify_udp(probe, reply, kind='generic'):
    error = quoted_error(probe, reply)
    if error:
        return error
    outer = network(reply)
    if outer is None or not same_ip(outer.src, probe.dst) or not same_ip(outer.dst, probe.src):
        return None
    udp, sent = outer.payload, probe.payload
    if not isinstance(udp, UDP) or int(udp.sport) != int(sent.dport) or int(udp.dport) != int(sent.sport):
        return None
    if not match_udp_payload(kind, bytes(sent.payload), bytes(udp.payload)):
        return None
    details = {'responder': str(outer.src), 'matched_endpoints': True,
               'protocol_token_validated': kind != 'generic'}
    body = bytes(udp.payload)
    if kind == 'ntp' and body[1] == 0:
        details['ntp_kiss_code'] = body[12:16].decode('ascii', errors='replace')
        details['rate_limited'] = body[12:16] == b'RATE'
    return Evidence('open', 'udp_response', details)
