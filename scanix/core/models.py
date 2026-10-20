"""Typed schema-5 reports; unknown evidence remains None (JSON null)."""
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import math
from typing import Literal
from ..service.models import DetectionReport

State = Literal["open", "closed", "unknown", "error", "filtered", "open|filtered"]
Method = Literal["connect", "syn", "udp"]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class ScanConfig:
    target: str
    ports: tuple[int, ...]
    timeout: float = 1.0
    concurrency: int = 100
    method: Method = "connect"
    banner: bool = False
    retries: int = 1
    rate: float | None = None
    per_host: int = 8
    min_timeout: float = 0.1
    max_timeout: float = 5.0
    adaptive: bool = True
    service_detect: bool = False
    service_profile: str = 'quick'
    service_timeout: float | None = None
    service_workers: int = 4
    tls_insecure: bool = False
    tls_ca_file: str | None = None
    sni: str | None = None
    starttls: bool = False
    allow_excluded_probes: bool = False
    engine: str = 'python'
    engine_timeout: float = 3600.0
    syn_cooldown: float = 0.2
    checkpoint_batch: int = 16
    plugins: tuple[str, ...] = ()
    plugin_timeout: float = 2.0
    allow_intrusive_plugins: bool = False

    def __post_init__(self):
        if not isinstance(self.target, str) or not self.target.strip() or '\x00' in self.target:
            raise ValueError("target must be a nonempty hostname or IP address")
        if not self.ports or any(type(p) is not int or not 1 <= p <= 65535 for p in self.ports):
            raise ValueError("ports must be integers within 1–65535")
        object.__setattr__(self, 'ports', tuple(sorted(set(self.ports))))
        if not math.isfinite(self.timeout) or not 0 < self.timeout <= 300:
            raise ValueError("timeout must be finite and within (0, 300] seconds")
        if type(self.concurrency) is not int or not 1 <= self.concurrency <= 1024:
            raise ValueError("concurrency must be within 1–1024")
        if type(self.retries) is not int or not 0 <= self.retries <= 5:
            raise ValueError("retries must be within 0–5")
        if self.rate is not None and (not math.isfinite(self.rate) or not 0 < self.rate <= 10000):
            raise ValueError("rate must be finite within (0, 10000]")
        if type(self.per_host) is not int or not 1 <= self.per_host <= 1024:
            raise ValueError("per-host concurrency must be within 1–1024")
        if not (math.isfinite(self.min_timeout) and math.isfinite(self.max_timeout)
                and 0.01 <= self.min_timeout <= self.max_timeout <= 300):
            raise ValueError("timeout bounds must satisfy 0.01 <= min <= max <= 300")
        if self.service_profile not in ('quick', 'deep'):
            raise ValueError('service profile must be quick or deep')
        if self.service_timeout is not None and (not math.isfinite(self.service_timeout) or not .1 <= self.service_timeout <= 30):
            raise ValueError('service timeout must be within 0.1–30 seconds')
        if type(self.service_workers) is not int or not 1 <= self.service_workers <= 64:
            raise ValueError('service workers must be within 1–64')
        if self.sni is not None:
            import re
            if not isinstance(self.sni, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', self.sni):
                raise ValueError('SNI override must be an ASCII hostname or IPv4 address')
        if self.tls_insecure and self.tls_ca_file:
            raise ValueError('--tls-insecure and --tls-ca-file are mutually exclusive')
        if self.service_detect and self.banner:
            raise ValueError('use --service-detect or legacy --banner, not both')
        from ..plugins.registry import select
        object.__setattr__(self, 'plugins', select(self.plugins))
        if not math.isfinite(self.plugin_timeout) or not .1 <= self.plugin_timeout <= 10:
            raise ValueError('plugin timeout must be within 0.1–10 seconds')
        if type(self.allow_intrusive_plugins) is not bool:
            raise ValueError('intrusive plugin opt-in must be boolean')
        if type(self.checkpoint_batch) is not int or not 1 <= self.checkpoint_batch <= 64:
            raise ValueError('checkpoint batch must be within 1–64')
        if self.engine not in ('python','native'):
            raise ValueError('unknown scan engine')
        if not math.isfinite(self.engine_timeout) or not .1 <= self.engine_timeout <= 86400:
            raise ValueError('engine timeout must be within 0.1–86400 seconds')
        if self.engine=='native' and (self.method not in ('connect','syn') or self.banner):
            raise ValueError('native supports connect/SYN; use --service-detect instead of --banner')
        if not math.isfinite(self.syn_cooldown) or not 0 <= self.syn_cooldown <= 1:
            raise ValueError('SYN cooldown must be within 0–1 seconds')
        if self.engine=='native' and len(self.ports)>4096:
            raise ValueError('native foundation supports at most 4096 selected ports')
        if self.engine=='native' and self.rate is not None and self.rate<.000001:
            raise ValueError('native rate must be at least 0.000001 attempts/second')
        if self.method not in ("connect", "syn", "udp"):
            raise ValueError("unknown scan method")
        if self.method != "connect" and self.banner:
            raise ValueError("--banner is supported only with TCP connect scanning")


@dataclass(frozen=True)
class ResolvedTarget:
    ip: str
    family: Literal["IPv4", "IPv6"] = "IPv4"


@dataclass
class ScanResult:
    target: str
    resolved_ip: str | None
    address_family: str | None
    port: int
    protocol: str = "tcp"
    scan_method: Method = "connect"
    state: State = "unknown"
    reason: str = "not_probed"
    error_code: int | None = None
    timestamp: str = field(default_factory=utc_now)
    connection_elapsed_seconds: float | None = None
    service_name: str | None = None
    detection_source: str | None = None
    banner: str | None = None
    version_evidence: dict[str, str] | None = None
    os: str | None = None
    probe_type: str | None = None
    evidence: dict = field(default_factory=dict)
    attempts: int = 1
    original_targets: tuple[str, ...] = ()
    service_detection: DetectionReport | None = None
    plugin_results: list[dict] = field(default_factory=list)


@dataclass
class ScanReport:
    configuration: ScanConfig
    results: list[ScanResult] = field(default_factory=list)
    schema_version: int = 5
    plugin_api_version: int | None = None
    plugin_registry_version: str | None = None
    implementation: dict = field(default_factory=lambda: {'engine':'python','engine_version':'phase4b','wire_protocol':None})
    probe_database_version: str | None = None
    started_at: str = field(default_factory=utc_now)
    finished_at: str | None = None
    completion_status: Literal["complete", "failed", "interrupted"] = "complete"
    issues: list[dict] = field(default_factory=list)

    completed_probes: int | None = None
    requested_probes: int | None = None
    scope: dict = field(default_factory=dict)
    discovery: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = asdict(self)
        data['configuration']['ports'] = list(self.configuration.ports)
        data['configuration']['plugins'] = list(self.configuration.plugins)
        for result in data['results']:
            result['original_targets'] = list(result['original_targets'])
        data['completed_ports'] = self.completed_probes if self.completed_probes is not None else len(self.results)
        data['requested_ports'] = (self.requested_probes if self.requested_probes is not None else len(self.configuration.ports))
        data['incomplete'] = self.completion_status != 'complete' or data['completed_ports'] < data['requested_ports']
        return data
