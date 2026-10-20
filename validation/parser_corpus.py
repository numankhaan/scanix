"""Deterministic mutation smoke corpus; no sockets, output snippets or coverage claims."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def mutations(seed, cases):
    """Stable byte mutations, truncation and oversize inputs, bounded to 16385 bytes."""
    if type(cases) is not int or not 1 <= cases <= 4096:
        raise ValueError('corpus cases must be1–4096')
    seed = seed[:16385]
    for index in range(cases):
        block = hashlib.sha256(str(index).encode()).digest()
        data = bytearray(seed)
        if index % 4 == 0:
            data = data[:int.from_bytes(block[:2], 'big') % (len(data) + 1)]
        elif index % 4 == 1 and data:
            data[int.from_bytes(block[:2], 'big') % len(data)] ^= block[2] or 1
        elif index % 4 == 2:
            data.extend(block * (1 + block[0] % 8))
        else:
            data = bytearray(block * (block[0] % 8))
        yield bytes(data[:16385])
    yield seed
    yield b'x' * 16385


def run(cases=128):
    from scanix.core.os_fingerprint import tcp_features, validate_database
    from scanix.core.ports import parse_ports
    from scanix.core.targets import ScopePlan
    from scanix.core.udp_protocols import match_udp_payload
    from scanix.native.adapter import _decode
    from scanix.service.parsers import protocol_response
    from scanix.service.registry import validate
    from scanix.modules.packets import classify_syn, classify_udp
    from scapy.all import IP, IPv6, TCP, UDP, Raw

    counts = {}; digest = hashlib.sha256()

    def record(group, data, accepted):
        row = counts.setdefault(group, {'inputs': 0, 'accepted': 0, 'rejected': 0})
        row['inputs'] += 1
        row['accepted' if accepted else 'rejected'] += 1
        digest.update(group.encode() + b'\0' + hashlib.sha256(data).digest() + bytes([bool(accepted)]))

    seeds = {'http': b'HTTP/1.1 200 OK\r\nServer: Synthetic/1\r\n\r\n',
             'ssh': b'SSH-2.0-Synthetic_1\r\n', 'ftp': b'220 Synthetic FTP ready\r\n',
             'smtp': b'220 lab.invalid ESMTP ready\r\n', 'pop3': b'+OK lab ready\r\n',
             'imap': b'* OK lab ready\r\n', 'tls': b'not a TLS handshake'}
    for protocol, seed in seeds.items():
        for data in mutations(seed, cases):
            found = protocol_response(protocol, data)
            assert found is None or isinstance(found, dict)
            if len(data) > 16384:
                assert found is None
            # Bytes alone cannot establish a completed TLS handshake.
            if protocol == 'tls':
                assert found is None
            record(protocol, data, found is not None)

    dns = b'\x12\x34' + struct.pack('!5H', 0, 1, 0, 0, 0) + b'\x06scanix\x07invalid\0\0\x01\0\x01'
    ntp = b'\x23' + b'\0' * 39 + b'\x01\x02\x03\x04\x05\x06\x07\x08'
    response = bytearray(48); response[0] = 0x24; response[24:32] = ntp[40:48]
    for kind, request, seed in (('dns', dns, dns[:2] + b'\x80' + dns[3:]), ('ntp', ntp, bytes(response))):
        for data in mutations(seed, cases):
            accepted = bool(match_udp_payload(kind, request, data))
            assert not match_udp_payload(kind, b'bad', data)
            record(kind, data, accepted)

    json_seeds = [b'{"type":"cancel"}', b'{"duplicate":1,"duplicate":2}',
                  b'{"x":NaN}', b'{"x":' + b'[' * 20 + b'0' + b']' * 20 + b'}']
    for seed in json_seeds:
        for data in mutations(seed, cases):
            try:
                _decode(data); accepted = True
            except ValueError:
                accepted = False
            record('native_json', data, accepted)

    for filename, validator in (('probes-v1.json', validate), ('os-fingerprints-v1.json', validate_database)):
        seed = (ROOT / 'scanix/data' / filename).read_bytes()
        for data in mutations(seed, cases):
            try:
                validator(json.loads(data)); accepted = True
            except (ValueError, UnicodeError):
                accepted = False
            record(filename, data, accepted)

    for family, source, target, layer in ((4, '192.0.2.1', '192.0.2.2', IP),
                                          (6, '2001:db8::1', '2001:db8::2', IPv6)):
        syn = layer(src=source, dst=target) / TCP(sport=45000, dport=8080, seq=123, flags='S')
        udp = layer(bytes(layer(src=source, dst=target) / UDP(sport=45001, dport=8081) / Raw(b'synthetic')))
        seed = bytes(layer(src=target, dst=source) / TCP(sport=8080, dport=45000, ack=124, flags='SA'))
        for data in mutations(seed, cases):
            try:
                reply = layer(data)
            except (ValueError, struct.error):
                record('packet_ipv' + str(family), data, False)
                continue
            syn_result = classify_syn(syn, reply)
            udp_result = classify_udp(udp, reply)
            if syn_result and syn_result.state == 'open':
                assert reply.src == target and reply.dst == source
                assert int(reply.payload.sport) == 8080 and int(reply.payload.dport) == 45000
                assert int(reply.payload.ack) == 124
            assert udp_result is None  # No corpus seed is a matching UDP response.
            record('packet_ipv' + str(family), data, syn_result is not None)
        header = bytes(TCP(flags='SA', options=[('MSS', 1460)]))
        for data in mutations(header, cases):
            found = tcp_features(family, 64, True if family == 4 else None, data)
            assert found is None or 20 <= found['tcp_header_bytes'] <= 60
            record('tcp_options_ipv' + str(family), data, found is not None)

    for seed in (b'127.0.0.0/30', b'2001:db8::/126', b'synthetic.invalid', b'::/0'):
        for data in mutations(seed, cases):
            try:
                plan = ScopePlan([data.decode('utf-8')], offline=True, family='any', max_targets=16)
                assert len(list(plan)) <= 16
                accepted = True
            except (ValueError, UnicodeError):
                accepted = False
            record('scope', data, accepted)
    for data in mutations(b'1-3,80,443', cases):
        try:
            ports = parse_ports(data.decode('utf-8'))
            assert ports == tuple(sorted(set(ports))) and all(1 <= p <= 65535 for p in ports)
            accepted = True
        except (ValueError, UnicodeError):
            accepted = False
        record('ports', data, accepted)
    return {'corpus_version': 1, 'cases_per_seed': cases, 'groups': counts,
            'inputs': sum(x['inputs'] for x in counts.values()), 'outcome_sha256': digest.hexdigest(),
            'limits': 'deterministic smoke mutations, not coverage-guided fuzzing or proof of parser safety'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cases', type=int, default=128)
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.cases), sort_keys=True))
    except Exception as exc:
        print('Parser corpus failed: ' + type(exc).__name__ + '; inspect privately', file=sys.stderr)
        raise SystemExit(1)
