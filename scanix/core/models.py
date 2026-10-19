"""Phase 1 wire schema. Unknown evidence is represented by None (JSON null)."""
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import math
from typing import Literal

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

    def __post_init__(self):
        if not isinstance(self.target, str) or not self.target.strip() or '\x00' in self.target:
            raise ValueError("target must be a nonempty hostname or IPv4 address")
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


@dataclass
class ScanReport:
    configuration: ScanConfig
    results: list[ScanResult] = field(default_factory=list)
    schema_version: int = 1
    started_at: str = field(default_factory=utc_now)
    finished_at: str | None = None
    completion_status: Literal["complete", "failed", "interrupted"] = "complete"
    issues: list[dict] = field(default_factory=list)

    requested_probes: int | None = None
    scope: dict = field(default_factory=dict)
    discovery: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = asdict(self)
        data['configuration']['ports'] = list(self.configuration.ports)
        for result in data['results']:
            result['original_targets'] = list(result['original_targets'])
        data['completed_ports'] = len(self.results)
        data['requested_ports'] = (self.requested_probes if self.requested_probes is not None else len(self.configuration.ports))
        data['incomplete'] = self.completion_status != 'complete'
        return data
