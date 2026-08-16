#!/usr/bin/env python3
"""Generate sample HTML report and capture screenshots for README."""

import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

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
from reporting.html import generate_html_report


async def generate_sample_html():
    """Generate HTML report with sample data."""

    # Create sample data
    config = ReconConfig(
        target="example.com",
        profile=Profile.STANDARD,
        report_formats=[ReportFormat.HTML],
        output_dir=Path("./reports"),
        rate_limit=100,
    )

    subdomains = [
        Subdomain(name="example.com", source="subfinder", resolved=True, ip_addresses=["93.184.216.34"]),
        Subdomain(name="www.example.com", source="subfinder", resolved=True, ip_addresses=["93.184.216.34"]),
        Subdomain(name="api.example.com", source="amass", resolved=True, ip_addresses=["93.184.216.35"]),
        Subdomain(name="test.example.com", source="crtsh", resolved=False),
        Subdomain(name="dev.example.com", source="subfinder", resolved=True, ip_addresses=["93.184.216.36"]),
        Subdomain(name="staging.example.com", source="amass", resolved=True, ip_addresses=["93.184.216.37"]),
    ]

    services = [
        PortService(host="example.com", port=80, protocol="tcp", service="http", version="nginx 1.18.0", source="nmap"),
        PortService(host="example.com", port=443, protocol="tcp", service="https", version="nginx 1.18.0", source="nmap"),
        PortService(host="example.com", port=22, protocol="tcp", service="ssh", version="OpenSSH 8.9", source="nmap"),
        PortService(host="api.example.com", port=443, protocol="tcp", service="https", version="nginx 1.20.0", source="nmap"),
        PortService(host="api.example.com", port=80, protocol="tcp", service="http", version="nginx 1.20.0", source="nmap"),
        PortService(host="dev.example.com", port=3000, protocol="tcp", service="http", version="Node.js Express", source="nmap"),
        PortService(host="staging.example.com", port=443, protocol="tcp", service="https", version="nginx 1.22.0", source="nmap"),
    ]

    technologies = [
        Technology(url="https://example.com", category="server", name="nginx", version="1.18.0", confidence=95, source="httpx"),
        Technology(url="https://example.com", category="cdn", name="Cloudflare", confidence=90, source="httpx"),
        Technology(url="https://example.com", category="waf", name="Cloudflare WAF", version="2024", confidence=85, source="wappalyzer"),
        Technology(url="https://api.example.com", category="framework", name="Express", version="4.18.2", confidence=85, source="wappalyzer"),
        Technology(url="https://api.example.com", category="language", name="Node.js", version="18.17.0", confidence=90, source="wappalyzer"),
        Technology(url="https://dev.example.com", category="framework", name="Next.js", version="14.0.0", confidence=88, source="wappalyzer"),
        Technology(url="https://dev.example.com", category="language", name="TypeScript", version="5.2.0", confidence=80, source="wappalyzer"),
    ]

    findings = [
        Finding(
            template_id="CVE-2024-21367",
            name="nginx Worker Process Use-After-Free",
            severity=Severity.CRITICAL,
            cvss=9.8,
            description="A use-after-free vulnerability in nginx worker process allows remote code execution.",
            matched_at="https://example.com",
            evidence="Version 1.18.0 is vulnerable per CVE-2024-21367",
            references=["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-21367"],
            tags=["cve", "rce", "nginx"],
            mitre_techniques=["T1190"],
        ),
        Finding(
            template_id="exposed-git",
            name="Exposed .git Directory",
            severity=Severity.HIGH,
            cvss=7.5,
            description="Git directory accessible on web server exposing source code.",
            matched_at="https://example.com/.git/",
            evidence="Directory listing enabled: HEAD, config, objects/ found",
            tags=["exposure", "misconfig", "git"],
        ),
        Finding(
            template_id="ssl-old-version",
            name="TLS 1.0/1.1 Deprecated Protocol",
            severity=Severity.MEDIUM,
            cvss=5.9,
            description="Server supports deprecated TLS 1.0 and 1.1 protocols.",
            matched_at="https://example.com:443",
            evidence="TLS 1.0 and TLS 1.1 enabled",
            tags=["ssl", "tls", "crypto", "compliance"],
        ),
        Finding(
            template_id="security-headers-missing",
            name="Missing Security Headers",
            severity=Severity.LOW,
            cvss=3.7,
            description="Important security headers are missing: CSP, X-Frame-Options, X-Content-Type-Options.",
            matched_at="https://example.com",
            evidence="Content-Security-Policy header not set",
            tags=["headers", "misconfig", "web"],
        ),
        Finding(
            template_id="server-version-disclosure",
            name="Server Version Disclosure",
            severity=Severity.INFO,
            cvss=0.0,
            description="Server header reveals nginx version: 1.18.0 (Ubuntu).",
            matched_at="https://example.com",
            evidence="Server: nginx/1.18.0 (Ubuntu)",
            tags=["disclosure", "nginx", "information"],
        ),
    ]

    scan_result = ScanResult(
        config=config,
        metadata=ScanMetadata(
            scan_id="demo123",
            target="example.com",
            profile=Profile.STANDARD,
            tools_versions={
                "subfinder": "2.14.0",
                "naabu": "2.3.7",
                "nmap": "7.94",
                "httpx": "1.6.10",
                "nuclei": "3.11.1",
                "katana": "1.1.3",
            },
        ),
        subdomains=subdomains,
        services=services,
        technologies=technologies,
        findings=findings,
    )

    # Generate HTML report
    output_path = Path("./docs/report-html.png")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    html_output = await generate_html_report(scan_result, output_path.with_suffix(".html"))

    print(f"Generated HTML report: {html_output}")

    return html_output


async def capture_screenshots(html_path: Path, docs_dir: Path):
    """Capture screenshots of HTML report using Playwright."""
    from playwright.async_api import async_playwright

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            viewport={"width": 1400, "height": 900},
            device_scale_factor=1.5,
        )

        # Screenshot HTML report
        page = await context.new_page()
        await page.goto(f"file://{html_path.absolute()}", wait_until="networkidle")
        await page.wait_for_timeout(1500)  # Wait for Chart.js to render

        # Full page screenshot
        await page.screenshot(path=str(docs_dir / "report-html.png"), full_page=True)
        print(f"Saved HTML screenshot: {docs_dir / 'report-html.png'}")

        # Also capture a cropped view of the top portion for README
        await page.set_viewport_size({"width": 1400, "height": 800})
        await page.screenshot(path=str(docs_dir / "report-html-preview.png"), full_page=False)
        print(f"Saved HTML preview: {docs_dir / 'report-html-preview.png'}")

        await page.close()
        await browser.close()


async def main():
    print("Generating sample HTML report...")
    html_path = await generate_sample_html()

    docs_dir = Path("./docs")
    docs_dir.mkdir(exist_ok=True)

    print("\nCapturing screenshots...")
    await capture_screenshots(html_path, docs_dir)

    print("\nDone! Screenshots saved to docs/")


if __name__ == "__main__":
    asyncio.run(main())