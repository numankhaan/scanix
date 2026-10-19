"""Minimal UDP payloads and matching shared by raw scans and service enrichment."""
import secrets
import struct
import time


def udp_payload(port):
    """DNS: RD=0 A query under .invalid, no EDNS. NTP: mode 3, 48 bytes.

    No ANY, recursion, monlist, control, broadcast or extension requests.
    Generic fallback is eight random bytes; only endpoint correlation is possible.
    """
    if port == 53:
        question = b'\x06scanix\x07invalid\x00\x00\x01\x00\x01'
        return 'dns', secrets.token_bytes(2) + struct.pack('!5H', 0, 1, 0, 0, 0) + question
    if port == 123:
        seconds = int(time.time()) + 2208988800
        stamp = struct.pack('!II', seconds % 2**32, secrets.randbits(32))
        return 'ntp', b'\x23' + b'\0' * 39 + stamp
    return 'generic', secrets.token_bytes(8)


def match_udp_payload(kind, request, response):
    if kind == 'dns':
        return (len(request) >= 17 and len(response) >= len(request) and response[:2] == request[:2]
                and response[2] & 0x80 and response[2] & 0x78 == 0
                and response[4:6] == b'\0\1' and response[12:len(request)] == request[12:])
    if kind == 'ntp':
        return (len(request) == 48 and len(response) >= 48 and response[0] & 7 == 4
                and (response[0] >> 3) & 7 in (3, 4) and response[24:32] == request[40:48])
    return True
