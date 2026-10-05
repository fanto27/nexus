from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

@dataclass(frozen=True, slots=True)
class Service:
    address: str
    port: int
    protocol: str = "tcp"
    state: str = "open"
    name: str = "unknown"
    version: str | None = None
    tls: bool | None = None
    certificate: dict[str, object] | None = None

@dataclass(frozen=True, slots=True)
class Finding:
    title: str
    severity: Severity
    what: str
    why: str
    evidence: str
    impact: str
    recommendation: str
    confidence: float
    target_address: str | None = None
    cve_id: str | None = None
    source: str | None = None

@dataclass(slots=True)
class ScanResult:
    targets: list[str]
    ports: list[int]
    services: list[Service]
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    duration_seconds: float = 0.0
    scan_id: str | None = None
    status: str = "completed"
    findings: list[Finding] = field(default_factory=list)
