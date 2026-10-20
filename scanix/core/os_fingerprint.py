"""Experimental remote SYN/ACK evidence, never a local-host or TTL-only guess."""
from functools import lru_cache
import json
from pathlib import Path

DATABASE_VERSION = '1.0.0'
FEATURE_VERSION = 1
MAX_DATABASE_BYTES = 32768


def guess_os_from_ttl(ttl):
    """Compatibility helper: TTL alone is never sufficient."""
    return None


def tcp_features(family, hop_limit, dont_fragment, header):
    """Parse at most a captured TCP header. Caller must correlate the remote SYN/ACK."""
    if (family not in (4, 6) or type(hop_limit) is not int or not 1 <= hop_limit <= 255 or
            not isinstance(header, bytes) or not 20 <= len(header) <= 60 or
            family == 4 and type(dont_fragment) is not bool):
        return None
    length = (header[12] >> 4) * 4
    if length < 20 or length > len(header) or header[13] & 0x3f != 0x12:
        return None
    kinds, mss, scale, sack, timestamps = [], None, None, False, False
    cursor = 20
    while cursor < length:
        kind = header[cursor]
        kinds.append(kind)
        if kind == 0:
            if any(header[cursor + 1:length]):
                return None
            break
        if kind == 1:
            cursor += 1
            continue
        if cursor + 2 > length:
            return None
        size = header[cursor + 1]
        if size < 2 or cursor + size > length:
            return None
        data = header[cursor + 2:cursor + size]
        if kind == 2:
            if size != 4 or mss is not None:
                return None
            mss = int.from_bytes(data, 'big')
        elif kind == 3:
            if size != 3 or scale is not None or data[0] > 14:
                return None
            scale = data[0]
        elif kind == 4:
            if size != 2 or sack:
                return None
            sack = True
        elif kind == 8:
            if size != 10 or timestamps:
                return None
            timestamps = True  # Do not retain remote uptime/timestamp values.
        cursor += size
    return {'feature_version': FEATURE_VERSION, 'source': 'matched_remote_syn_ack',
            'probe': 'syn_without_options_v1', 'ip_version': family,
            'observed_hop_limit': hop_limit, 'dont_fragment': dont_fragment if family == 4 else None,
            'tcp_window': int.from_bytes(header[14:16], 'big'), 'tcp_header_bytes': length,
            'option_kinds': kinds, 'mss': mss, 'window_scale': scale,
            'sack_permitted': sack, 'timestamps': timestamps}


def validate_database(data):
    if (not isinstance(data, dict) or set(data) != {'schema_version','database_version','license','profiles'} or
            type(data['schema_version']) is not int or data['schema_version'] != 1 or
            data['database_version'] != DATABASE_VERSION or data['license'] != 'CC0-1.0' or
            not isinstance(data['profiles'], list) or not 1 <= len(data['profiles']) <= 16):
        raise ValueError('invalid OS fingerprint database')
    ids = set()
    for profile in data['profiles']:
        if (not isinstance(profile, dict) or set(profile) != {'id','candidate','support','provenance','signals'} or
                not isinstance(profile['id'], str) or not profile['id'].startswith('linux.ipv4.') or
                len(profile['id']) > 80 or profile['id'] in ids or profile['candidate'] != 'Linux-compatible' or
                profile['support'] != 'experimental' or not isinstance(profile['provenance'], str) or
                not 1 <= len(profile['provenance']) <= 512):
            raise ValueError('invalid OS fingerprint profile')
        ids.add(profile['id'])
        signals = profile['signals']
        if (not isinstance(signals, dict) or set(signals) != {'observed_hop_limit','dont_fragment','tcp_window','option_kinds','mss'} or
                type(signals['observed_hop_limit']) is not int or not 1 <= signals['observed_hop_limit'] <= 255 or
                type(signals['dont_fragment']) is not bool or type(signals['tcp_window']) is not int or
                not 0 <= signals['tcp_window'] <= 65535 or type(signals['mss']) is not int or
                not 1 <= signals['mss'] <= 65535 or not isinstance(signals['option_kinds'], list) or
                not 1 <= len(signals['option_kinds']) <= 40 or any(type(x) is not int or not 0 <= x <= 255 for x in signals['option_kinds'])):
            raise ValueError('invalid OS fingerprint signals')
    return data


@lru_cache(maxsize=1)
def database():
    path = Path(__file__).resolve().parents[1] / 'data' / 'os-fingerprints-v1.json'
    with path.open('rb') as stream:
        content = stream.read(MAX_DATABASE_BYTES + 1)
    if len(content) > MAX_DATABASE_BYTES:
        raise ValueError('OS fingerprint database exceeds limit')
    return validate_database(json.loads(content))


def identify(features, *, registry=None):
    registry = validate_database(registry) if registry is not None else database()
    result = {'database_version': registry['database_version'], 'status': 'inconclusive',
              'confidence': 'insufficient', 'candidates': [], 'reason': 'no_correlated_syn_ack',
              'authenticated': False}
    if not isinstance(features, dict):
        return result
    if features.get('source') != 'matched_remote_syn_ack' or features.get('probe') != 'syn_without_options_v1' or features.get('feature_version') != 1:
        result['reason'] = 'unsupported_evidence'
        return result
    if features.get('ip_version') != 4:
        result['reason'] = 'unsupported_fingerprint_family'
        return result
    matches = [p for p in registry['profiles'] if all(type(features.get(k)) is type(v) and features.get(k) == v for k,v in p['signals'].items())]
    if len(matches) != 1:
        result['reason'] = 'conflicting_profiles' if matches else 'no_supported_profile'
        return result
    match = matches[0]
    result.update(status='experimental_match', confidence='experimental', reason='multiple_exact_lab_signals',
                  candidates=[{'profile_id': match['id'], 'os_family': match['candidate'],
                               'version': None, 'support': match['support'], 'matched_signals': list(match['signals'])}])
    return result


def annotate(result):
    # Keep legacy os unknown: an experimental compatible stack is not a proven OS.
    try:
        result.evidence['os_detection'] = identify(result.evidence.get('remote_tcp'))
    except (OSError, ValueError, TypeError, KeyError):
        result.evidence['os_detection'] = {'database_version': DATABASE_VERSION, 'status': 'error',
            'confidence': 'insufficient', 'candidates': [], 'reason': 'fingerprint_database_invalid', 'authenticated': False}


def policy(config):
    return {'enabled': config.os_detect, 'database_version': DATABASE_VERSION,
            'methods': ['python_syn'], 'supported_fingerprint_families': ['IPv4'],
            'confidence': 'experimental exact lab signals; no reliable OS/version claim',
            'additional_probes': 0, 'ttl_only': False}
