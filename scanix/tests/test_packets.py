import unittest
from scapy.all import IP, IPv6, TCP, UDP, Raw, ICMP, ICMPv6DestUnreach
from scanix.modules.packets import (syn_probe, reset_probe, udp_probe, classify_syn, classify_udp)


class PacketTests(unittest.TestCase):
    def syn_reply(self, probe, flags='SA', **overrides):
        fields = dict(sport=probe.payload.dport, dport=probe.payload.sport,
                      seq=123, ack=(probe.payload.seq + 1) % 2**32, flags=flags)
        fields.update(overrides)
        return probe.__class__(src=probe.dst, dst=probe.src) / TCP(**fields)

    def test_syn_ack_rst_reset_duplicates_and_silence(self):
        for src, dst in [('127.0.0.1', '127.0.0.2'), ('::1', '::2')]:
            p = syn_probe(src, dst, 80)
            r = self.syn_reply(p)
            self.assertEqual(classify_syn(p, r).state, 'open')
            self.assertEqual(classify_syn(p, r), classify_syn(p, r.copy()))
            reset = reset_probe(p, r)
            self.assertEqual((reset.src, reset.dst, reset.payload.sport, reset.payload.dport),
                             (p.src, p.dst, p.payload.sport, 80))
            self.assertEqual((int(reset.payload.flags), reset.payload.seq, reset.payload.ack),
                             (0x14, r.payload.ack, 124))
            self.assertEqual(classify_syn(p, self.syn_reply(p, 'RA')).state, 'closed')
            for reply in [None, IP()/UDP(), self.syn_reply(p, ack=0),
                          self.syn_reply(p, dport=1), self.syn_reply(p, 'R')]:
                self.assertIsNone(classify_syn(p, reply))
            r.src = src
            self.assertIsNone(classify_syn(p, r))

    def test_quoted_errors_and_mismatches(self):
        for src, dst in [('127.0.0.1', '127.0.0.2'), ('::1', '::2')]:
            for proto in ('tcp', 'udp'):
                p = syn_probe(src, dst, 80) if proto == 'tcp' else udp_probe(src, dst, 53)[1]
                v6 = isinstance(p, IPv6)
                error = ICMPv6DestUnreach(code=1) if v6 else ICMP(type=3, code=13)
                reply = p.__class__(src=dst, dst=src) / error / p.copy()
                fn = classify_syn if proto == 'tcp' else classify_udp
                # Decode as from wire to exercise IPerror/TCPerror/UDPerror subclasses.
                reply = reply.__class__(bytes(reply))
                self.assertEqual(fn(p, reply).state, 'filtered')
                quote = reply.payload.payload
                quote.payload.dport = 99
                self.assertIsNone(fn(p, reply))
                quote.payload.dport = p.payload.dport
                if proto == 'tcp':
                    quote.payload.seq += 1
                else:
                    quote.payload.chksum ^= 1
                self.assertIsNone(fn(p, reply))

    def test_udp_protocol_tokens_and_closed(self):
        for port in (53, 123, 65000):
            for src, dst in [('127.0.0.1', '127.0.0.2'), ('::1', '::2')]:
                kind, p = udp_probe(src, dst, port)
                body = bytearray(bytes(p.payload.payload))
                if kind == 'dns':
                    body[2] |= 0x80
                elif kind == 'ntp':
                    body[0] = 0x24
                    body[24:32] = body[40:48]
                r = p.__class__(src=dst, dst=src)/UDP(sport=port, dport=p.payload.sport)/Raw(bytes(body))
                self.assertEqual(classify_udp(p, r, kind).state, 'open')
                if kind != 'generic':
                    body[0 if kind == 'dns' else 24] ^= 1
                    r.payload.payload = Raw(bytes(body))
                    self.assertIsNone(classify_udp(p, r, kind))
                r.payload.dport = 1
                self.assertIsNone(classify_udp(p, r, kind))
                error = ICMPv6DestUnreach(code=4) if isinstance(p, IPv6) else ICMP(type=3, code=3)
                r = p.__class__(src=dst, dst=src)/error/p.copy()
                self.assertEqual(classify_udp(p, r, kind).state, 'closed')
                self.assertIsNone(classify_udp(p, None, kind))

    def test_minimum_quote_and_path_error(self):
        kind, p = udp_probe('127.0.0.1', '127.0.0.2', 53)
        reply = IP(src=p.dst, dst=p.src)/ICMP(type=3, code=0)/Raw(bytes(p)[:28])
        reply = IP(bytes(reply))
        self.assertEqual(classify_udp(p, reply).state, 'unknown')
        reply.payload.payload.id ^= 1
        self.assertIsNone(classify_udp(p, reply))
