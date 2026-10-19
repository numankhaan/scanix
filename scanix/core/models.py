"""Phase 1 wire schema. Unknown evidence is represented by None (JSON null)."""
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import math
from typing import Literal

State = Literal["open", "closed", "unknown", "error"]
Method = Literal["connect", "syn"]


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
        if self.method not in ("connect", "syn"):
            raise ValueError("unknown scan method")
        if self.method == "syn" and self.banner:
            raise ValueError("--banner is supported only with TCP connect scanning")


@dataclass(frozen=True)
class ResolvedTarget:
    ip: str
    family: Literal["IPv4"] = "IPv4"


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


@dataclass
class ScanReport:
    configuration: ScanConfig
    results: list[ScanResult] = field(default_factory=list)
    schema_version: int = 1
    started_at: str = field(default_factory=utc_now)
    finished_at: str | None = None
    completion_status: Literal["complete", "failed", "interrupted"] = "complete"
    issues: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = asdict(self)
        data['configuration']['ports'] = list(self.configuration.ports)
        data['completed_ports'] = len(self.results)
        data['requested_ports'] = len(self.configuration.ports)
        data['incomplete'] = self.completion_status != 'complete'
        return data
