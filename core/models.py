"""Pydantic models for vapt-recon."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field


class Profile(StrEnum):
    """Scan profile enumeration."""

    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"
    COMPLIANCE = "compliance"


class ReportFormat(StrEnum):
    """Report output format."""

    HTML = "html"
    PDF = "pdf"
    JSON = "json"


class Severity(StrEnum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Subdomain(BaseModel):
    """Discovered subdomain."""

    name: str
    source: str
    resolved: bool = False
    ip_addresses: list[str] = Field(default_factory=list)
    cname: str | None = None
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


class PortService(BaseModel):
    """Open port with service information."""

    host: str
    port: int
    protocol: Literal["tcp", "udp"] = "tcp"
    service: str | None = None
    version: str | None = None
    state: Literal["open", "filtered", "closed"] = "open"
    source: str = "naabu"
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


class Technology(BaseModel):
    """Identified technology."""

    url: str
    category: str  # cms, framework, language, server, cdn, waf, analytics, etc.
    name: str
    version: str | None = None
    confidence: int = 100  # 0-100
    source: str = "httpx"
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


class Finding(BaseModel):
    """Vulnerability finding."""

    id: str = Field(default_factory=lambda: str(uuid4())[:8])
    template_id: str
    name: str
    severity: Severity
    cvss: float | None = None
    description: str
    matched_at: str  # URL or host:port
    evidence: str | None = None
    extraction: str | None = None
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    cwe: str | None = None
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


class ScanMetadata(BaseModel):
    """Scan execution metadata."""

    scan_id: str = Field(default_factory=lambda: str(uuid4())[:8])
    target: str
    profile: Profile
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None
    duration_seconds: float | None = None
    tools_versions: dict[str, str] = Field(default_factory=dict)
    config_snapshot: dict[str, Any] = Field(default_factory=dict)


class ReconConfig(BaseModel):
    """Reconciliation scan configuration."""

    target: str
    profile: Profile = Profile.STANDARD
    report_formats: list[ReportFormat] = [ReportFormat.HTML]
    output_dir: Path = Path("./reports")
    rate_limit: int = 100
    resume: bool = False
    config_path: Path | None = None
    checkpoint_file: Path | None = None

    def model_post_init(self, __context: Any) -> None:
        self.output_dir = Path(self.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        if self.checkpoint_file is None:
            self.checkpoint_file = self.output_dir / f".checkpoint_{self.target}.json"


class ScanResult(BaseModel):
    """Complete scan result."""

    config: ReconConfig
    metadata: ScanMetadata
    subdomains: list[Subdomain] = Field(default_factory=list)
    services: list[PortService] = Field(default_factory=list)
    technologies: list[Technology] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    def summary(self) -> dict[str, int]:
        """Return finding counts by severity."""
        return dict(Counter(f.severity.value for f in self.findings))
