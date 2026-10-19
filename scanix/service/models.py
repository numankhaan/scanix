from dataclasses import dataclass, field


@dataclass
class ServiceEvidence:
    service: str | None
    product: str | None = None
    version: str | None = None
    transport: str = 'tcp'
    detection_method: str = 'greeting'
    probe_id: str | None = None
    signature_id: str | None = None
    confidence: str = 'banner'
    evidence: dict = field(default_factory=dict)
    authenticated: bool = False


@dataclass
class TLSEvidence:
    probe_id: str
    handshake: str = 'failed'
    verification: str = 'not_completed'
    sni: str | None = None
    verification_name: str | None = None
    version: str | None = None
    cipher: str | None = None
    alpn: str | None = None
    certificate: dict = field(default_factory=dict)
    error: str | None = None
    verify_code: int | None = None


@dataclass
class DetectionReport:
    database_version: str
    profile: str
    status: str = 'unknown'
    observations: list[ServiceEvidence] = field(default_factory=list)
    tls: list[TLSEvidence] = field(default_factory=list)
    attempts: int = 0
    transmissions: int = 0
    bytes_received: int = 0
    bytes_sent: int = 0
    elapsed_seconds: float = 0.0
    issues: list[str] = field(default_factory=list)
