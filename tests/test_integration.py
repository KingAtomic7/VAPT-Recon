"""Integration tests for vapt-recon pipeline."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.models import (
    Finding, PortService, Profile, ReconConfig, ReportFormat,
    ScanMetadata, ScanResult, Severity, Subdomain, Technology
)
from core.recon import run_recon
from reporting import generate_reports
from utils.dedupe import (
    merge_subdomains, merge_services, merge_technologies,
    merge_findings, normalize_subdomain, normalize_url
)


class TestDeduplication:
    """Test deduplication utilities."""

    def test_normalize_subdomain(self):
        assert normalize_subdomain("WWW.EXAMPLE.COM") == "example.com"
        assert normalize_subdomain("  api.example.com  ") == "api.example.com"
        assert normalize_subdomain("mail.example.com.") == "mail.example.com"

    def test_merge_subdomains(self):
        subdomains = [
            Subdomain(name="example.com", source="subfinder", resolved=True),
            Subdomain(name="EXAMPLE.COM", source="amass", resolved=True, ip_addresses=["1.2.3.4"]),
            Subdomain(name="www.example.com", source="crtsh", resolved=False),
        ]
        merged = merge_subdomains(subdomains)
        assert len(merged) == 2  # example.com and www.example.com
        main = next(m for m in merged if m.name == "example.com")
        assert "subfinder" in main.source and "amass" in main.source
        assert main.ip_addresses == ["1.2.3.4"]

    def test_normalize_url(self):
        assert normalize_url("https://example.com:443/path?b=2&a=1#frag") == "https://example.com/path?a=1&b=2"
        assert normalize_url("http://example.com:80/path") == "http://example.com/path"

    def test_merge_services(self):
        services = [
            PortService(host="example.com", port=80, service="http", source="naabu"),
            PortService(host="example.com", port=80, service="http", version="nginx 1.18", source="nmap"),
        ]
        merged = merge_services(services)
        assert len(merged) == 1
        assert merged[0].version == "nginx 1.18"
        assert merged[0].source == "nmap"

    def test_merge_technologies(self):
        techs = [
            Technology(url="https://example.com", category="server", name="nginx", confidence=80),
            Technology(url="https://example.com", category="server", name="nginx", version="1.18", confidence=95),
        ]
        merged = merge_technologies(techs)
        assert len(merged) == 1
        assert merged[0].confidence == 95
        assert merged[0].version == "1.18"

    def test_merge_findings(self):
        findings = [
            Finding(template_id="cve-1", name="Test", severity=Severity.HIGH, matched_at="https://example.com"),
            Finding(template_id="cve-1", name="Test", severity=Severity.HIGH, matched_at="https://example.com", evidence="extra"),
        ]
        merged = merge_findings(findings)
        assert len(merged) == 1
        assert "extra" in merged[0].evidence


class TestReconPipeline:
    """Test the main recon pipeline with mocked tools."""

    @pytest.mark.asyncio
    async def test_run_recon_quick_profile(self, sample_config: ReconConfig, sample_subdomains, sample_services, sample_technologies, sample_findings):
        """Test quick scan profile execution."""
        sample_config.profile = Profile.QUICK

        with patch('core.recon.run_subdomain_enum', new_callable=AsyncMock) as mock_sub, \
             patch('core.recon.run_port_scan', new_callable=AsyncMock) as mock_ports, \
             patch('core.recon.run_tech_fingerprint', new_callable=AsyncMock) as mock_tech, \
             patch('core.recon.run_vuln_scan', new_callable=AsyncMock) as mock_vulns, \
             patch('core.recon.run_param_discovery', new_callable=AsyncMock) as mock_params, \
             patch('core.recon.run_enrichment', new_callable=AsyncMock) as mock_enrich, \
             patch('core.recon._save_checkpoint', new_callable=AsyncMock) as mock_save:

            mock_sub.return_value = sample_subdomains
            mock_ports.return_value = sample_services
            mock_tech.return_value = sample_technologies
            mock_vulns.return_value = sample_findings
            mock_params.return_value = []
            mock_enrich.return_value = {}

            result = await run_recon(sample_config)

            assert isinstance(result, ScanResult)
            assert result.config.target == "example.com"
            assert len(result.subdomains) == len(sample_subdomains)
            assert len(result.services) == len(sample_services)
            assert len(result.technologies) == len(sample_technologies)
            assert len(result.findings) == len(sample_findings)

    @pytest.mark.asyncio
    async def test_resume_from_checkpoint(self, sample_config: ReconConfig, tmp_path: Path):
        """Test resuming from checkpoint."""
        # Create a checkpoint file
        checkpoint_file = tmp_path / ".checkpoint_example.com.json"
        checkpoint_data = {
            "config": {"target": "example.com", "profile": "standard", "rate_limit": 100},
            "result": {
                "subdomains": [{"name": "example.com", "source": "subfinder", "resolved": True, "ip_addresses": []}],
                "services": [],
                "technologies": [],
                "findings": [],
                "errors": [],
            },
            "saved_at": "2024-01-01T00:00:00",
        }
        checkpoint_file.write_text(json.dumps(checkpoint_data))
        sample_config.checkpoint_file = checkpoint_file
        sample_config.resume = True

        with patch('core.recon.run_subdomain_enum', new_callable=AsyncMock) as mock_sub, \
             patch('core.recon.run_port_scan', new_callable=AsyncMock) as mock_ports, \
             patch('core.recon.run_tech_fingerprint', new_callable=AsyncMock) as mock_tech, \
             patch('core.recon.run_vuln_scan', new_callable=AsyncMock) as mock_vulns, \
             patch('core.recon.run_param_discovery', new_callable=AsyncMock) as mock_params, \
             patch('core.recon.run_enrichment', new_callable=AsyncMock) as mock_enrich, \
             patch('core.recon._save_checkpoint', new_callable=AsyncMock):

            mock_sub.return_value = []
            mock_ports.return_value = []
            mock_tech.return_value = []
            mock_vulns.return_value = []
            mock_params.return_value = []
            mock_enrich.return_value = {}

            result = await run_recon(sample_config)

            # Should not call subdomain enum since we're resuming
            mock_sub.assert_not_called()


class TestReportGeneration:
    """Test report generation."""

    @pytest.mark.asyncio
    async def test_generate_html_report(self, sample_scan_result: ScanResult, tmp_path: Path):
        """Test HTML report generation."""
        from reporting.html import generate_html_report

        output_path = tmp_path / "report.html"
        result = await generate_html_report(sample_scan_result, output_path)

        assert result.exists()
        content = result.read_text()
        assert "example.com" in content
        assert "Test Critical Vulnerability" in content
        assert "chart.js" in content.lower() or "Chart" in content

    @pytest.mark.asyncio
    async def test_generate_json_report(self, sample_scan_result: ScanResult, tmp_path: Path):
        """Test JSON report generation."""
        from reporting.json import generate_json_report

        output_path = tmp_path / "report.json"
        result = await generate_json_report(sample_scan_result, output_path)

        assert result.exists()
        data = json.loads(result.read_text())
        assert data["metadata"]["target"] == "example.com"
        assert data["summary"]["findings"] == 2
        assert len(data["findings"]) == 2

    @pytest.mark.asyncio
    async def test_generate_all_reports(self, sample_scan_result: ScanRecord, tmp_path: Path):
        """Test generating all report formats."""
        sample_scan_result.config.report_formats = [ReportFormat.HTML, ReportFormat.JSON]
        sample_scan_result.config.output_dir = tmp_path / "reports"

        outputs = await generate_reports(sample_scan_result.config, sample_scan_result)

        assert ReportFormat.HTML in outputs
        assert ReportFormat.JSON in outputs
        assert outputs[ReportFormat.HTML].exists()
        assert outputs[ReportFormat.JSON].exists()


class TestProfileLoading:
    """Test profile configuration loading."""

    def test_load_default_profiles(self):
        from config.profiles import load_profiles
        profiles = load_profiles()
        assert "quick" in profiles
        assert "standard" in profiles
        assert "deep" in profiles
        assert "compliance" in profiles

    def test_profile_structure(self):
        from config.profiles import load_profiles
        profiles = load_profiles()
        standard = profiles["standard"]
        assert "subdomains" in standard
        assert "ports" in standard
        assert "vulns" in standard
        assert standard["estimated_time_minutes"] == 20