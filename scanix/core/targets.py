"""Bounded scope parsing. CIDRs remain ranges; DNS answers are resolved once."""
from dataclasses import dataclass
import ipaddress
import re
import socket
from pathlib import Path

MAX_FILE_BYTES = 1024 * 1024
MAX_INPUTS = 10000


@dataclass(frozen=True)
class Target:
    ip: str
    originals: tuple[str, ...]

    @property
    def family(self):
        return 'IPv6' if ipaddress.ip_address(self.ip).version == 6 else 'IPv4'


def read_target_file(filename):
    # Bounded read works even for files without a trustworthy stat size.
    with Path(filename).open('rb') as stream:
        content = stream.read(MAX_FILE_BYTES + 1)
    if len(content) > MAX_FILE_BYTES:
        raise ValueError('target file exceeds 1 MiB')
    try:
        text = content.decode('utf-8')
    except UnicodeError as exc:
        raise ValueError('target files must be UTF-8') from exc
    tokens = []
    for line in text.splitlines():
        token = line.partition('#')[0].strip()
        if token:
            tokens.append(token)
        if len(tokens) > MAX_INPUTS:
            raise ValueError('too many target file entries')
    return tokens


class ScopePlan:
    def __init__(self, inputs, exclusions=(), *, family='4', dns_policy='first',
                 max_targets=4096, offline=False, resolver=None):
        if family not in ('4', '6', 'any') or dns_policy not in ('first', 'all'):
            raise ValueError('invalid address family or DNS policy')
        if type(max_targets) is not int or not 1 <= max_targets <= 65536:
            raise ValueError('max-targets must be within 1–65536')
        if not inputs or len(inputs) + len(exclusions) > MAX_INPUTS:
            raise ValueError('provide between 1 and 10000 explicit scope entries')
        self.family, self.dns_policy = family, dns_policy
        self.max_targets, self.offline = max_targets, offline
        self.inputs, self.exclusions = tuple(inputs), tuple(exclusions)
        self.unresolved = []
        self._dns = {}
        self._resolver = resolver or socket.getaddrinfo
        self.sources = self._parse(self.inputs, expand=True)
        self.excluded = self._parse(self.exclusions, expand=False)
        # Reject oversized input before network traffic, even if exclusions would
        # later shrink it. IPv6 /64 is never iterated or silently truncated.
        if sum(self._size(net) for _, net in self.sources) > max_targets:
            raise ValueError('target input exceeds max-targets; narrow CIDRs/input explicitly')

    @staticmethod
    def _size(net):
        count = net.num_addresses
        return count - 2 if net.version == 4 and net.prefixlen < 31 else (
            count - 1 if net.version == 6 and net.prefixlen < 127 else count)

    def _parse(self, tokens, expand):
        result = []
        budget = 0
        dns_addresses = 0
        for token in dict.fromkeys(tokens):
            if not isinstance(token, str) or not token or len(token) > 253 or any(ord(c) < 33 or ord(c) == 127 for c in token):
                raise ValueError('invalid target: empty, oversized or contains whitespace/control characters')
            if '%' in token:
                raise ValueError('scoped IPv6 addresses are not supported; use a global/ULA address')
            try:
                net = ipaddress.ip_network(token, strict=False)
            except ValueError:
                if '/' in token or ':' in token or re.fullmatch(r'[0-9.]+', token):
                    raise ValueError('invalid IP address or CIDR') from None
                try:
                    name = token.encode('idna').decode('ascii').lower().rstrip('.')
                except UnicodeError as exc:
                    raise ValueError('invalid hostname') from exc
                if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9.])?', name):
                    raise ValueError('invalid hostname')
                if self.offline:
                    self.unresolved.append(token)
                    continue
                if name not in self._dns:
                    af = {'4': socket.AF_INET, '6': socket.AF_INET6, 'any': socket.AF_UNSPEC}[self.family]
                    answers = self._resolver(name, None, af, socket.SOCK_STREAM)
                    addresses = []
                    for answer in answers:
                        if answer[0] not in (socket.AF_INET, socket.AF_INET6):
                            continue
                        ip = ipaddress.ip_address(answer[4][0])
                        if self.family != 'any' and str(ip.version) != self.family:
                            continue
                        if str(ip) not in addresses:
                            addresses.append(str(ip))
                            if len(addresses) > self.max_targets:
                                raise ValueError('DNS answers exceed max-targets')
                    if not addresses:
                        raise ValueError('hostname has no addresses for selected family')
                    self._dns[name] = addresses
                addresses = self._dns[name]
                # Excluded hostnames exclude every DNS answer, independently of
                # the selected scan-answer policy.
                chosen = addresses[:1] if expand and self.dns_policy == 'first' else addresses
                dns_addresses += len(chosen)
                if dns_addresses > self.max_targets:
                    raise ValueError('DNS scope expansion exceeds max-targets')
                result.extend((token, ipaddress.ip_network(address)) for address in chosen)
                if expand:
                    budget += len(chosen)
            else:
                if self.family != 'any' and str(net.version) != self.family:
                    raise ValueError('target address family conflicts with --family')
                result.append((token, net))
                if expand:
                    budget += self._size(net)
            if expand and budget > self.max_targets:
                raise ValueError('target input exceeds max-targets; narrow CIDRs/input explicitly')
        return tuple(result)

    def __iter__(self):
        seen = set()
        for _, net in self.sources:
            for address in net.hosts():
                if address in seen or any(address.version == ex.version and address in ex for _, ex in self.excluded):
                    continue
                seen.add(address)
                originals = tuple(dict.fromkeys(original for original, source in self.sources
                    if address.version == source.version and address in source))
                yield Target(str(address), originals)

    def count(self):
        return sum(1 for _ in self)

    def preview(self, ports, method, discovery=(), limit=256):
        sample, count = [], 0
        for target in self:
            count += 1
            if len(sample) < limit:
                sample.append({'ip': target.ip, 'family': target.family, 'originals': list(target.originals)})
        return {'inputs': list(self.inputs), 'exclusions': list(self.exclusions),
                'family': self.family, 'dns_policy': self.dns_policy,
                'offline': self.offline, 'unresolved_hostnames': list(dict.fromkeys(self.unresolved)),
                'scope_complete': not self.unresolved, 'effective_target_count': count if not self.unresolved else None,
                'numeric_target_count': count, 'targets': sample, 'sample_truncated': count > len(sample),
                'ports': list(ports), 'method': method, 'discovery_methods': list(discovery),
                'max_targets': self.max_targets}
