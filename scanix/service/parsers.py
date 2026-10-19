"""Small protocol parsers. Untrusted bytes never choose code or response destinations."""
import re
import unicodedata
from .models import ServiceEvidence
from .registry import load_registry
from ..core.udp_protocols import match_udp_payload


def clean(value, limit=512):
    return ''.join(c if not unicodedata.category(c).startswith('C') else '?' for c in str(value))[:limit]


def protocol_response(protocol, data, *, request=None, command=None, tls_handshake=False):
    """Return parsed evidence only; generic greeting codes cannot confirm FTP/SMTP."""
    if len(data) > 16384 or b'\x00' in data and protocol not in ('dns','ntp','tls'):
        return None
    if protocol in ('dns','ntp'):
        if request is None or not match_udp_payload(protocol, request, data):
            return None
        return {'response_bytes': len(data), 'transaction_validated': True}
    if protocol == 'tls':
        return {'handshake_completed': True} if tls_handshake else None
    try:
        text = data.decode('ascii')
    except UnicodeError:
        return None
    # Require terminated protocol lines; never identify a partial status/banner.
    if '\r\n' not in text:
        return None
    lines = text.split('\r\n')
    if any(len(line) > 1024 for line in lines) or any(ord(c)<32 and c not in '\r\n\t' for c in text):
        return None
    first = lines[0]
    if protocol == 'http':
        if '\r\n\r\n' not in text or not re.fullmatch(r'HTTP/1\.[01] [1-5][0-9]{2}(?: [\x20-\x7e]{0,128})?', first):
            return None
        headers = {}
        for line in lines[1:lines.index('')]:
            if ':' not in line or line[0].isspace():
                return None
            name,value = line.split(':',1)
            if not re.fullmatch(r'[A-Za-z0-9-]{1,64}',name):
                return None
            name = name.lower()
            if name in ('server','content-type','allow'):
                if name in headers:
                    return None
                headers[name] = clean(value.strip(),256)
        return {'status': int(first.split()[1]), 'headers': headers}
    if protocol == 'ssh':
        for line in lines[:4]:
            match=re.fullmatch(r'SSH-(2\.0|1\.99|1\.5)-([!-~]{1,180})(?: [ -~]{0,60})?',line)
            if match and len(line)+2<=255:
                return {'protocol_version':match[1],'software':match[2]}
        return None
    if protocol == 'smtp':
        if command == 'ehlo':
            if len(lines)<2 or not lines[-2].startswith('250 ') or any(not line.startswith(('250-','250 ')) for line in lines[:-1]):
                return None
            return {'capabilities': [clean(line[4:],128) for line in lines[:-1]][:16]}
        return {'greeting':clean(first,256)} if re.fullmatch(r'220[ -][ -~]{0,240} ESMTP(?: [ -~]{1,80})?',first) else None
    if protocol == 'ftp':
        if command == 'feat':
            if first.startswith('211-') and lines[-2].startswith('211 '):
                return {'features':[clean(line.strip(),128) for line in lines[1:-2]][:16]}
            return None
        return {'greeting':clean(first,256)} if first.startswith('220 ') and ('FTP' in first.upper()) else None
    if protocol == 'pop3':
        if command == 'capa':
            if first.startswith('+OK') and len(lines)>=3 and lines[-2]=='.':
                caps=lines[1:-2]
                if caps and all(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 ._-]{0,127}',line) for line in caps):
                    return {'capabilities':[clean(line,128) for line in caps][:16]}
            return None
        return {'greeting':clean(first,256)} if first.startswith('+OK ') else None
    if protocol == 'imap':
        if command == 'capability':
            cap = next((line[13:] for line in lines if line.startswith('* CAPABILITY ')), None)
            if cap and lines[-2].startswith('a001 OK ') and re.fullmatch(r'[A-Za-z0-9=._ -]{1,512}',cap):
                return {'capabilities':cap.split()[:32]}
            return None
        return {'greeting':clean(first,256)} if re.fullmatch(r'\* (?:OK|PREAUTH) [ -~]{1,240}',first) else None
    return None


def identify(protocol,data,probe_id,transport='tcp',*,request=None,command=None,tls_handshake=False,registry=None):
    registry=registry or load_registry()
    parsed=protocol_response(protocol,data,request=request,command=command,tls_handshake=tls_handshake)
    if parsed is None:
        return None
    confidence='protocol' if protocol in ('http','ssh','dns','ntp','tls') or command else 'banner'
    signature=protocol+'.response.v1'
    product=version=None
    field = 'server' if protocol=='http' else 'software' if protocol=='ssh' else 'greeting'
    value=parsed.get('headers',{}).get('server','').split(' ')[0] if protocol=='http' else parsed.get(field,'')
    hints=registry.hints(protocol,field,value,registry.probes[probe_id]['matchers'] if probe_id in registry.probes else None)
    if hints:
        signature,product,version=hints
    return ServiceEvidence(protocol,product,version,transport,
        'tls_handshake' if protocol=='tls' else 'request_response' if command or request is not None or protocol=='http' else 'greeting',
        probe_id,signature,confidence,parsed)


def greeting_protocol(data):
    for protocol in ('ssh','smtp','ftp','imap','pop3','http'):
        if protocol_response(protocol,data) is not None:
            return protocol
    return None
