"""Bounded opt-in enrichment. Port states and destinations are never changed here."""
from concurrent.futures import CancelledError, FIRST_COMPLETED, ThreadPoolExecutor, wait
import hashlib
import ipaddress
import ssl
import time

from .models import DetectionReport, TLSEvidence
from .parsers import clean, greeting_protocol, identify, protocol_response
from .registry import load_registry
from .transport import BudgetExceeded, Session
from ..core.udp_protocols import udp_payload

PROFILES = {
    'quick': dict(connections=3, transmissions=6, receive_bytes=8192, send_bytes=2048,
                  total_seconds=3., operation_timeout=.7, passive_timeout=.2),
    'deep': dict(connections=5, transmissions=12, receive_bytes=16384, send_bytes=4096,
                 total_seconds=8., operation_timeout=1.5, passive_timeout=.4),
}


class TLSUpgradeFailed(OSError):
    """An advertised upgrade failed; never attempt a plaintext fallback."""


def policy(config):
    registry = load_registry()
    return dict(enabled=config.service_detect, database_version=registry.version,
                profile=config.service_profile, budget=budget_for(config),
                workers=min(config.service_workers, config.concurrency, config.per_host),
                tls_verification='disabled' if config.tls_insecure else 'required',
                sni_override=config.sni, starttls=config.starttls,
                allow_excluded_probes=config.allow_excluded_probes,
                sensitivity_exclusions=list(registry.exclusions),
                rate_units='shared tokens for connection starts, application writes and TLS handshake starts; kernel packets are not counted')


def budget_for(config):
    budget = dict(PROFILES[config.service_profile])
    if config.service_timeout is not None:
        budget['total_seconds'] = config.service_timeout
    return budget


def verification_name(result, override=None):
    if override:
        return override
    for original in result.original_targets or (result.target,):
        try:
            ipaddress.ip_address(original)
        except ValueError:
            if '/' not in original:
                # Scope resolution has already validated hostnames; no new DNS lookup.
                return original.rstrip('.').encode('idna').decode('ascii')
    return result.resolved_ip


def excluded(port, registry):
    return next((entry['reason'] for entry in registry.exclusions if port in entry['ports']), None)


class Detector:
    def __init__(self, result, config, stop, runtime):
        self.result, self.config, self.stop, self.runtime = result, config, stop, runtime
        self.registry = load_registry()
        self.report = DetectionReport(self.registry.version, config.service_profile)
        result.service_detection = self.report
        self.budget = budget_for(config)
        self.started = time.monotonic()
        self.deadline = self.started + self.budget['total_seconds']
        self.name = verification_name(result, config.sni)

    def session(self):
        return Session(self.result.resolved_ip, self.result.port, self.stop, self.runtime.limiter,
                       self.report, self.budget, self.deadline)

    def add(self, protocol, data=b'', *, command=None, request=None, tls=False, probe_id=None):
        probe = self.registry.probes[probe_id or protocol+('.udp.v1' if protocol in ('dns','ntp') else '.tcp.v1')]
        if len(data) > probe['response_limit']:
            return None
        observation = identify(probe['parser_id'].removesuffix('_v1'), data, probe['id'], 'tls' if tls else 'udp' if protocol in ('dns','ntp') else 'tcp',
                               command=command, request=request, tls_handshake=protocol=='tls', registry=self.registry)
        if observation:
            # Keep both initial banner and confirmation, with their actual evidence rules.
            self.report.observations.append(observation)
        return observation

    def handshake(self, session, probe_id):
        name = self.name
        try:
            ipaddress.ip_address(name)
            sni = None
        except ValueError:
            sni = name
        evidence = TLSEvidence(probe_id, sni=sni, verification_name=name)
        self.report.tls.append(evidence)
        try:
            context = ssl.create_default_context(cafile=self.config.tls_ca_file)
            context.set_alpn_protocols(['http/1.1'])
        except (OSError, ssl.SSLError) as exc:
            evidence.error = clean(type(exc).__name__+': '+str(exc))
            raise RuntimeError('TLS trust configuration could not be loaded') from exc
        if self.config.tls_insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            evidence.verification = 'disabled'
        try:
            sock = session.tls(context, name)
            evidence.handshake = 'succeeded'
            evidence.verification = 'disabled' if self.config.tls_insecure else 'verified'
            evidence.version = sock.version()
            evidence.cipher = sock.cipher()[0] if sock.cipher() else None
            evidence.alpn = sock.selected_alpn_protocol()
            der = sock.getpeercert(binary_form=True)
            cert = sock.getpeercert()
            evidence.certificate = {'sha256': hashlib.sha256(der).hexdigest(), 'der_bytes': len(der)} if der else {}
            for key in ('subject','issuer','serialNumber','notBefore','notAfter','subjectAltName'):
                if key in cert:
                    # Bounded metadata; never save the full certificate or private data.
                    evidence.certificate[key] = clean(str(cert[key]), 1024)
            self.add('tls', tls=True, probe_id=probe_id)
            return True
        except ssl.SSLCertVerificationError as exc:
            evidence.verification = 'failed'
            evidence.verify_code = exc.verify_code
            evidence.error = clean(exc.verify_message)
            # Definite TLS: no silent insecure retry or plaintext fallback.
            raise
        except (OSError, TimeoutError) as exc:
            evidence.error = clean(type(exc).__name__+': '+str(exc))
            raise

    def http(self, session, tls=False):
        host = self.name
        if ':' in host:
            host = '['+host+']'
        session.send(('HEAD / HTTP/1.1\r\nHost: '+host+'\r\nConnection: close\r\nUser-Agent: Scanix/3\r\n\r\n').encode('ascii'))
        return self.add('http', session.receive(4096, complete=lambda data: protocol_response('http', data) is not None), tls=tls)

    def capabilities(self, session, protocol, tls=False):
        commands = {'smtp': (b'EHLO scanix.invalid\r\n','ehlo'), 'ftp': (b'FEAT\r\n','feat'),
                    'pop3': (b'CAPA\r\n','capa'), 'imap': (b'a001 CAPABILITY\r\n','capability')}
        probe = self.registry.probes[protocol+'.tcp.v1']
        strategy_protocol = {'smtp_ehlo':'smtp','ftp_feat':'ftp','pop3_capa':'pop3','imap_capability':'imap'}[probe['payload_strategy']]
        payload, command = commands[strategy_protocol]
        session.send(payload)
        data = session.receive(probe['response_limit'], complete=lambda data: protocol_response(protocol, data, command=command) is not None)
        observation = self.add(protocol, data, command=command, tls=tls)
        if not observation or not self.config.starttls or tls or protocol == 'ftp':
            return observation
        caps = observation.evidence['capabilities']
        token = {'smtp':'STARTTLS','pop3':'STLS','imap':'STARTTLS'}[protocol]
        if not any(token == cap.split()[0].upper() for cap in caps):
            self.report.issues.append(protocol+': TLS upgrade not advertised')
            return observation
        upgrade = {'smtp':b'STARTTLS\r\n','pop3':b'STLS\r\n','imap':b'a002 STARTTLS\r\n'}[protocol]
        session.send(upgrade)
        reply = session.receive(1024, passive=True)
        accepted = reply.startswith({'smtp':b'220 ', 'pop3':b'+OK', 'imap':b'a002 OK '}[protocol]) and reply.endswith(b'\r\n')
        if not accepted:
            self.report.issues.append(protocol+': TLS upgrade refused or malformed')
            return observation
        try:
            self.handshake(session, protocol+'.starttls.v1')
        except (OSError, TimeoutError) as exc:
            raise TLSUpgradeFailed('TLS upgrade failed: '+str(exc)) from exc
        # RFC 3207/2595: discard pre-TLS capabilities and request fresh ones.
        return self.capabilities(session, protocol, tls=True)

    def greet(self, session, *, tls=False):
        data = session.receive(4096, passive=True, complete=lambda data: bool(greeting_protocol(data)) or (data.startswith(b'220 ') and data.endswith(b'\r\n')))
        protocol = greeting_protocol(data)
        if protocol:
            self.add(protocol, data, tls=tls)
            if protocol in ('smtp','ftp','pop3','imap') and (self.config.service_profile == 'deep' or self.config.starttls):
                self.capabilities(session, protocol, tls=tls)
            return True
        if data.startswith(b'220 ') and data.endswith(b'\r\n'):
            # A bare 220 is shared by FTP/SMTP. EHLO is bounded and no identity is inferred from its port.
            observation = self.capabilities(session, 'smtp', tls=tls)
            if not observation and self.config.service_profile == 'deep':
                self.capabilities(session, 'ftp', tls=tls)
            return bool(self.report.observations)
        return False

    def tcp(self):
        tls_first = self.result.port in self.registry.probes['tls.tcp.v1']['ports']
        chain = self.registry.fallback_chain('tls.tcp.v1', self.budget['connections'])
        stages = [{'tls':'tls','http_head':'http'}[probe['payload_strategy']] for probe in chain]
        stages.insert(1 if tls_first else 0, 'greeting')
        for stage in stages:
            try:
                with self.session() as session:
                    session.connect()
                    if stage == 'greeting':
                        if self.greet(session):
                            return
                    elif stage == 'tls':
                        self.handshake(session, 'tls.tcp.v1')
                        if not self.greet(session, tls=True):
                            self.http(session, tls=True)
                        return
                    elif self.http(session):
                        return
            except (ssl.SSLCertVerificationError, TLSUpgradeFailed) as exc:
                self.report.issues.append(clean(type(exc).__name__+': '+str(exc)))
                return
            except (OSError, TimeoutError) as exc:
                self.report.issues.append(stage+': '+clean(type(exc).__name__+': '+str(exc),256))
                if isinstance(exc, BudgetExceeded) or self.report.observations:
                    # Once a protocol/TLS is observed, a failed follow-up is not
                    # a reason to open a new plaintext fallback connection.
                    return

    def udp(self):
        # Phase 2 already correlated the wire transaction; retain its concrete evidence.
        if self.result.probe_type in ('dns','ntp') and self.result.reason == 'udp_response':
            from .models import ServiceEvidence
            protocol = self.result.probe_type
            self.report.observations.append(ServiceEvidence(protocol, transport='udp', detection_method='scan_response',
                probe_id=protocol+'.udp.v1', signature_id=protocol+'.response.v1', confidence='protocol',
                evidence=dict(self.result.evidence)))
            return
        for probe in self.registry.fallback_chain('dns.udp.v1', 2 if self.config.service_profile == 'deep' else 1):
            protocol = probe['protocol']
            _, payload = udp_payload({'dns_minimal':53,'ntp_client':123}[probe['payload_strategy']])
            try:
                with self.session() as session:
                    session.connect(udp=True)
                    session.send(payload)
                    if self.add(protocol, session.receive(512, datagram=True), request=payload):
                        return
            except (OSError, TimeoutError) as exc:
                self.report.issues.append(protocol+': '+clean(type(exc).__name__+': '+str(exc),256))

    def run(self):
        reason = excluded(self.result.port, self.registry)
        try:
            if reason and not self.config.allow_excluded_probes:
                self.report.status = 'excluded'
                self.report.issues.append(reason)
                return
            if self.stop.is_set():
                raise CancelledError()
            self.udp() if self.result.protocol == 'udp' else self.tcp()
            self.report.status = 'identified' if self.report.observations else 'unknown'
        except CancelledError:
            self.report.status = 'interrupted'
        except Exception as exc:
            self.report.status = 'error'
            self.report.issues.append(clean(type(exc).__name__+': '+str(exc)))
        finally:
            self.report.elapsed_seconds = time.monotonic()-self.started
        return self.report


def enrich_results(results, config, stop, runtime):
    """At most N pending futures. Completed evidence remains attached on cancellation."""
    registry = load_registry()
    for result in results:
        if result.state == 'open':
            result.service_detection = DetectionReport(registry.version, config.service_profile, status='not_attempted')
    selected = iter(result for result in results if result.state == 'open')
    workers = min(config.service_workers, config.concurrency, config.per_host)
    pending = set()
    with ThreadPoolExecutor(max_workers=workers) as executor:
        exhausted = False
        try:
            while pending or not exhausted:
                if stop.is_set():
                    break
                while len(pending)<workers and not exhausted:
                    result = next(selected,None)
                    if result is None:
                        exhausted = True
                    else:
                        pending.add(executor.submit(lambda item: Detector(item, config, stop, runtime).run(), result))
                if pending:
                    done, pending = wait(pending, timeout=.05, return_when=FIRST_COMPLETED)
                    for future in done:
                        future.result()
        except KeyboardInterrupt:
            stop.set()
        finally:
            for future in pending:
                future.cancel()
