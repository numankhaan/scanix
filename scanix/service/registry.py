"""Validated original data. No imports/eval/commands are derived from registry data."""
from dataclasses import dataclass
from functools import lru_cache
import json
from pathlib import Path
import re

PARSERS = frozenset(('http_v1', 'ssh_v1', 'ftp_v1', 'smtp_v1', 'pop3_v1', 'imap_v1', 'tls_v1', 'dns_v1', 'ntp_v1'))
STRATEGIES = frozenset(('greeting', 'http_head', 'tls', 'ftp_feat', 'smtp_ehlo', 'pop3_capa', 'imap_capability', 'dns_minimal', 'ntp_client'))


def safe_regex(pattern):
    """Finite, anchored subset: <=2 bounded repeats and <=2 non-nested named groups.

    No wildcard, alternation, lookaround, backreference, unbounded repetition or
    executable replacement. Fields matched against these patterns are <=256 chars.
    """
    if not isinstance(pattern, str) or len(pattern) > 256 or not pattern.startswith('^') or not pattern.endswith('$'):
        raise ValueError('signature regex must be anchored and at most 256 characters')
    simplified = re.sub(r'\[[A-Za-z0-9._+ /:\-]+\]', 'A', pattern)
    simplified = re.sub(r'\\[.*+?()/_-]', 'A', simplified)
    simplified = re.sub(r'\(\?P<[a-z_]{1,20}>', '(', simplified)
    repeats = re.findall(r'\{([0-9]+),([0-9]+)\}', simplified)
    if len(repeats) > 2 or any(not 0 <= int(a) <= int(b) <= 128 for a, b in repeats):
        raise ValueError('signature regex repeats exceed finite safety bounds')
    if re.search(r'\)\{', simplified):
        raise ValueError('repeating groups are unsupported')
    simplified = re.sub(r'\{[0-9]+,[0-9]+\}', '', simplified)
    if re.search(r'[^A-Za-z0-9 /:_()^$-]', simplified) or simplified.count('(') > 2:
        raise ValueError('unsupported signature regex construct')
    depth = 0
    for char in simplified:
        if char == '(':
            depth += 1
            if depth > 1:
                raise ValueError('nested signature groups are unsupported')
        elif char == ')':
            depth -= 1
        if depth < 0:
            raise ValueError('unbalanced signature regex')
    if depth:
        raise ValueError('unbalanced signature regex')
    try:
        return re.compile(pattern, re.ASCII)
    except re.error as exc:
        raise ValueError('invalid signature regex') from exc


@dataclass(frozen=True)
class Registry:
    version: str
    probes: dict
    signatures: dict
    exclusions: tuple
    compiled: dict

    def hints(self, protocol, field, value):
        if len(value) > 256:
            return None
        for key, signature in self.signatures.items():
            if signature['protocol'] == protocol and signature['field'] == field and 'pattern' in signature:
                match = self.compiled[key].fullmatch(value)
                if match:
                    return key, signature.get('product') or match.groupdict().get('product'), match.groupdict().get('version')
        return None


def validate(data):
    if set(data) != {'schema_version', 'database_version', 'license', 'probes', 'signatures', 'sensitivity_exclusions'} or data['schema_version'] != 1:
        raise ValueError('unknown probe database schema')
    if not re.fullmatch(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', data['database_version']) or data['license'] != 'CC0-1.0':
        raise ValueError('invalid probe database version/license')
    probes, signatures, compiled = {}, {}, {}
    for collection, target in ((data['probes'], probes), (data['signatures'], signatures)):
        if not isinstance(collection, list) or not 1 <= len(collection) <= 64:
            raise ValueError('probe/signature count exceeds bounds')
        for entry in collection:
            key = entry.get('id')
            if not isinstance(key, str) or not re.fullmatch(r'[a-z0-9_.-]{1,64}', key) or key in target:
                raise ValueError('invalid or duplicate stable ID')
            target[key] = entry
    for probe in probes.values():
        if set(probe) != {'id', 'protocol', 'transport', 'payload_strategy', 'parser_id', 'response_limit', 'ports', 'matchers', 'fallbacks'}:
            raise ValueError('unknown probe fields')
        if probe['parser_id'] not in PARSERS or probe['payload_strategy'] not in STRATEGIES:
            raise ValueError('unknown parser/payload strategy')
        if probe['transport'] not in ('tcp', 'tls', 'udp') or probe['protocol'] not in {p.removesuffix('_v1') for p in PARSERS}:
            raise ValueError('invalid probe protocol/transport')
        if type(probe['response_limit']) is not int or not 64 <= probe['response_limit'] <= 16384:
            raise ValueError('invalid response limit')
        if not isinstance(probe['ports'], list) or any(type(p) is not int or not 1 <= p <= 65535 for p in probe['ports']):
            raise ValueError('invalid port hints')
        if not isinstance(probe['matchers'], list) or not isinstance(probe['fallbacks'], list):
            raise ValueError('invalid registry references')
        if any(key not in signatures for key in probe['matchers']) or any(key not in probes for key in probe['fallbacks']):
            raise ValueError('dangling registry reference')
    for key, signature in signatures.items():
        if not set(signature) <= {'id', 'protocol', 'field', 'pattern', 'product', 'parser_id'} or not {'id', 'protocol', 'field', 'parser_id'} <= set(signature):
            raise ValueError('invalid signature fields')
        if signature['parser_id'] not in PARSERS or signature['protocol'] not in {p.removesuffix('_v1') for p in PARSERS}:
            raise ValueError('invalid signature parser/protocol')
        if signature['field'] not in ('server', 'software', 'greeting', 'wire'):
            raise ValueError('unknown signature field')
        if 'pattern' in signature:
            compiled[key] = safe_regex(signature['pattern'])
        elif signature['field'] != 'wire':
            raise ValueError('text signature requires a safe pattern')
    exclusions = data['sensitivity_exclusions']
    if not isinstance(exclusions, list) or len(exclusions) > 32:
        raise ValueError('invalid sensitivity exclusions')
    for item in exclusions:
        if set(item) != {'ports', 'reason'} or not isinstance(item['ports'], list) or not isinstance(item['reason'], str) or len(item['reason']) > 128:
            raise ValueError('invalid exclusion entry')
        if any(type(port) is not int or not 1 <= port <= 65535 for port in item['ports']):
            raise ValueError('invalid excluded port')
    return Registry(data['database_version'], probes, signatures, tuple(exclusions), compiled)


@lru_cache(maxsize=1)
def load_registry():
    data = Path(__file__).resolve().parents[1].joinpath('data', 'probes-v1.json').read_bytes()
    if len(data) > 65536:
        raise ValueError('probe database exceeds 64 KiB')
    return validate(json.loads(data))
