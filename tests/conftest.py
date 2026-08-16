"""Pytest fixtures and configuration."""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from core.models import (
    Finding,
    PortService,
    Profile,
    ReconConfig,
    ReportFormat,
    ScanMetadata,
    ScanResult,
    Severity,
    Subdomain,
    Technology,
)


@pytest.fixture
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def sample_config(tmp_path: Path) -> ReconConfig:
    """Sample scan configuration."""
    return ReconConfig(
        target="example.com",
        profile=Profile.STANDARD,
        report_formats=[ReportFormat.HTML, ReportFormat.JSON],
        output_dir=tmp_path / "reports",
        rate_limit=100,
    )


@pytest.fixture
def sample_subdomains() -> list[Subdomain]:
    """Sample subdomains for testing."""
    return [
        Subdomain(
            name="example.com", source="subfinder", resolved=True, ip_addresses=["93.184.216.34"]
        ),
        Subdomain(
            name="www.example.com",
            source="subfinder",
            resolved=True,
            ip_addresses=["93.184.216.34"],
        ),
        Subdomain(
            name="api.example.com", source="amass", resolved=True, ip_addresses=["93.184.216.35"]
        ),
        Subdomain(name="test.example.com", source="crtsh", resolved=False),
    ]


@pytest.fixture
def sample_services() -> list[PortService]:
    """Sample port services for testing."""
    return [
        PortService(
            host="example.com",
            port=80,
            protocol="tcp",
            service="http",
            version="nginx 1.18.0",
            source="nmap",
        ),
        PortService(
            host="example.com",
            port=443,
            protocol="tcp",
            service="https",
            version="nginx 1.18.0",
            source="nmap",
        ),
        PortService(
            host="api.example.com",
            port=443,
            protocol="tcp",
            service="https",
            version="nginx 1.20.0",
            source="nmap",
        ),
    ]


@pytest.fixture
def sample_technologies() -> list[Technology]:
    """Sample technologies for testing."""
    return [
        Technology(
            url="https://example.com",
            category="server",
            name="nginx",
            version="1.18.0",
            confidence=95,
            source="httpx",
        ),
        Technology(
            url="https://example.com",
            category="cdn",
            name="cloudflare",
            confidence=90,
            source="httpx",
        ),
        Technology(
            url="https://api.example.com",
            category="framework",
            name="express",
            confidence=85,
            source="wappalyzer",
        ),
    ]


@pytest.fixture
def sample_findings() -> list[Finding]:
    """Sample findings for testing."""
    return [
        Finding(
            template_id="cve-2024-1234",
            name="Test Critical Vulnerability",
            severity=Severity.CRITICAL,
            cvss=9.8,
            description="A critical vulnerability for testing",
            matched_at="https://example.com/vuln",
            evidence="Proof of concept",
            references=["https://cve.org/CVE-2024-1234"],
            tags=["cve", "rce"],
            mitre_techniques=["T1190"],
        ),
        Finding(
            template_id="exposed-git",
            name="Exposed .git Directory",
            severity=Severity.HIGH,
            cvss=7.5,
            description="Git directory accessible",
            matched_at="https://example.com/.git/",
            evidence="Directory listing",
            tags=["exposure", "misconfig"],
        ),
    ]


@pytest.fixture
def sample_scan_result(
    sample_config: ReconConfig,
    sample_subdomains: list[Subdomain],
    sample_services: list[PortService],
    sample_technologies: list[Technology],
    sample_findings: list[Finding],
) -> ScanResult:
    """Complete sample scan result."""
    return ScanResult(
        config=sample_config,
        metadata=ScanMetadata(
            scan_id="test123",
            target="example.com",
            profile=Profile.STANDARD,
        ),
        subdomains=sample_subdomains,
        services=sample_services,
        technologies=sample_technologies,
        findings=sample_findings,
    )


@pytest.fixture
def mock_subprocess():
    """Mock subprocess for tool execution."""
    with patch("asyncio.create_subprocess_exec") as mock:
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))
        mock.return_value = mock_proc
        yield mock


@pytest.fixture
def tmp_output_dir(tmp_path: Path) -> Path:
    """Temporary output directory."""
    output_dir = tmp_path / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


# Async fixtures
@pytest.fixture
async def async_sample_config(tmp_path: Path) -> ReconConfig:
    """Async sample config."""
    return ReconConfig(
        target="example.com",
        profile=Profile.STANDARD,
        report_formats=[ReportFormat.HTML],
        output_dir=tmp_path / "reports",
    )
