"""Vulnerability scanning with Nuclei."""

import asyncio
import json
import tempfile
from pathlib import Path

from core.models import Finding, ReconConfig, Severity, Technology
from utils.dedupe import merge_findings
from utils.rate_limit import get_limiter

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}


def _extract_mitre_techniques(tags: list[str]) -> list[str]:
    """Extract MITRE ATT&CK techniques from nuclei tags."""
    techniques = []
    for tag in tags:
        if tag.startswith("attack-") or tag.startswith("mitre-"):
            techniques.append(tag)
        elif "-" in tag and tag[:4].isdigit():
            # Pattern like T1190, T1068
            if tag[0] == "T" and tag[1:].isdigit():
                techniques.append(tag)
    return techniques


async def _run_nuclei(
    targets: list[str], config: ReconConfig, limiter, profile_config: dict
) -> list[Finding]:
    """Run nuclei vulnerability scanner."""
    findings: list[Finding] = []
    vuln_config = profile_config.get("vulns", {}).get("nuclei", {})

    severity = vuln_config.get("severity", ["critical", "high"])
    tags = vuln_config.get("tags", [])
    exclude_tags = vuln_config.get("exclude_tags", ["dos", "fuzz"])
    rate_limit = vuln_config.get("rate_limit", 100)
    templates_dir = vuln_config.get("templates_dir")
    custom_templates = vuln_config.get("custom_templates", False)

    if not targets:
        return findings

    # Write targets to temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(targets))
        targets_file = f.name

    try:
        args = [
            "nuclei",
            "-l",
            targets_file,
            "-json",
            "-silent",
            "-rate-limit",
            str(rate_limit),
            "-severity",
            ",".join(severity),
        ]

        if tags:
            args.extend(["-tags", ",".join(tags)])
        if exclude_tags:
            args.extend(["-exclude-tags", ",".join(exclude_tags)])
        if templates_dir:
            args.extend(["-t", templates_dir])
        if custom_templates:
            # Include custom templates from config/nuclei-templates
            custom_path = Path(__file__).parent.parent.parent / "config" / "nuclei-templates"
            if custom_path.exists():
                args.extend(["-t", str(custom_path)])

        await limiter.acquire("nuclei", rate=rate_limit)
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)

        for line in stdout.decode().strip().split("\n"):
            if line:
                try:
                    data = json.loads(line)
                    info = data.get("info", {})
                    severity_str = info.get("severity", "info").lower()

                    finding = Finding(
                        template_id=data.get("template-id", ""),
                        name=info.get("name", "Unknown"),
                        severity=_SEVERITY_MAP.get(severity_str, Severity.INFO),
                        cvss=info.get("cvss"),
                        description=info.get("description", ""),
                        matched_at=data.get("matched-at", ""),
                        evidence=data.get("extracted-results", [None])[0]
                        or data.get("curl-command"),
                        extraction=data.get("extracted-results", [None])[0],
                        references=info.get("reference", []),
                        tags=info.get("tags", []),
                        mitre_techniques=_extract_mitre_techniques(info.get("tags", [])),
                        cwe=info.get("cwe") if isinstance(info.get("cwe"), str) else None,
                    )
                    findings.append(finding)
                except json.JSONDecodeError:
                    continue
    except (TimeoutError, FileNotFoundError, Exception):
        pass
    finally:
        import os

        try:
            os.unlink(targets_file)
        except Exception:
            pass

    return findings


async def run_vuln_scan(technologies: list[Technology], config: ReconConfig) -> list[Finding]:
    """Run vulnerability scanning on discovered technologies."""
    limiter = get_limiter(config.rate_limit)
    profile_config = getattr(config, "_profile_config", {})

    # Build target URLs from technologies
    targets = list(set(tech.url for tech in technologies))

    findings = await _run_nuclei(targets, config, limiter, profile_config)

    return merge_findings(findings)
