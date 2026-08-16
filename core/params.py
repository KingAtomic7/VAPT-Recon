"""Parameter discovery and fuzzing module."""

import asyncio
import contextlib
import json
import tempfile
from pathlib import Path

from core.models import Finding, ReconConfig, Severity, Technology
from utils.dedupe import merge_findings
from utils.rate_limit import get_limiter


async def _run_katana(
    targets: list[str], config: ReconConfig, limiter, profile_config: dict
) -> list[str]:
    """Run katana for crawling and URL discovery."""
    urls: list[str] = []
    params_config = profile_config.get("params", {})
    max_urls = params_config.get("max_urls", 500)

    if not targets:
        return urls

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(targets))
        targets_file = f.name

    try:
        await limiter.acquire("katana", rate=20)
        proc = await asyncio.create_subprocess_exec(
            "katana",
            "-list",
            targets_file,
            "-silent",
            "-jc",  # JavaScript crawling
            "-kf",  # known-files
            "-rl",
            "10",  # rate limit
            "-d",
            "3",  # depth
            "-o",
            "/dev/stdout",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _stderr = await asyncio.wait_for(proc.communicate(), timeout=300)

        for line in stdout.decode().strip().split("\n"):
            if line and len(urls) < max_urls:
                urls.append(line.strip())
    except (TimeoutError, FileNotFoundError, Exception):
        pass
    finally:
        with contextlib.suppress(Exception):
            Path(targets_file).unlink()

    return urls


async def _run_paramspider(targets: list[str], config: ReconConfig, limiter) -> list[str]:
    """Run paramspider for parameter discovery."""
    urls: list[str] = []
    if not targets:
        return urls

    for target in targets[:10]:  # Limit to avoid too many runs
        try:
            await limiter.acquire("paramspider", rate=10)
            proc = await asyncio.create_subprocess_exec(
                "paramspider",
                "-d",
                target,
                "-o",
                "/dev/stdout",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _stderr = await asyncio.wait_for(proc.communicate(), timeout=120)

            for line in stdout.decode().strip().split("\n"):
                if line and "=" in line:
                    urls.append(line.strip())
        except (TimeoutError, FileNotFoundError, Exception):
            pass
    return urls


async def _run_arjun(urls: list[str], config: ReconConfig, limiter) -> list[str]:
    """Run arjun for parameter discovery."""
    discovered: list[str] = []
    if not urls:
        return discovered

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(urls[:50]))
        urls_file = f.name

    try:
        await limiter.acquire("arjun", rate=10)
        proc = await asyncio.create_subprocess_exec(
            "arjun",
            "-i",
            urls_file,
            "-o",
            "/dev/stdout",
            "-t",
            "20",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _stderr = await asyncio.wait_for(proc.communicate(), timeout=180)

        for line in stdout.decode().strip().split("\n"):
            if line and line.startswith("http"):
                discovered.append(line.strip())
    except (TimeoutError, FileNotFoundError, Exception):
        pass
    finally:
        with contextlib.suppress(Exception):
            Path(urls_file).unlink()

    return discovered


async def _fuzz_parameters(
    urls: list[str], config: ReconConfig, limiter, profile_config: dict
) -> list[Finding]:
    """Fuzz discovered parameters with nuclei fuzzing templates."""
    findings: list[Finding] = []
    params_config = profile_config.get("params", {})
    fuzz_templates = params_config.get("fuzz_templates", "fuzzing")

    if not urls:
        return findings

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(urls[:100]))
        urls_file = f.name

    try:
        args = [
            "nuclei",
            "-l",
            urls_file,
            "-t",
            fuzz_templates,
            "-json",
            "-silent",
            "-rate-limit",
            "50",
        ]

        await limiter.acquire("nuclei-fuzz", rate=50)
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _stderr = await asyncio.wait_for(proc.communicate(), timeout=300)

        for line in stdout.decode().strip().split("\n"):
            if line:
                try:
                    data = json.loads(line)
                    info = data.get("info", {})
                    severity_str = info.get("severity", "info").lower()

                    finding = Finding(
                        template_id=data.get("template-id", ""),
                        name=info.get("name", "Parameter Fuzzing"),
                        severity=Severity(severity_str)
                        if severity_str in Severity._value2member_map_
                        else Severity.INFO,
                        cvss=info.get("cvss"),
                        description=info.get("description", ""),
                        matched_at=data.get("matched-at", ""),
                        evidence=data.get("extracted-results", [None])[0],
                        tags=info.get("tags", []) + ["fuzzing"],
                        mitre_techniques=[],
                    )
                    findings.append(finding)
                except (json.JSONDecodeError, ValueError):
                    continue
    except (TimeoutError, FileNotFoundError, Exception):
        pass
    finally:
        with contextlib.suppress(Exception):
            Path(urls_file).unlink()

    return findings


async def run_param_discovery(technologies: list[Technology], config: ReconConfig) -> list[Finding]:
    """Run parameter discovery and fuzzing."""
    limiter = get_limiter(config.rate_limit)
    profile_config = getattr(config, "_profile_config", {})

    params_config = profile_config.get("params", {})
    if not params_config.get("enabled", False):
        return []

    # Collect base URLs from technologies
    base_urls = list(set(tech.url for tech in technologies))

    all_findings = []
    discovered_urls = []

    # Crawl with katana
    if "katana" in params_config.get("tools", []):
        katana_urls = await _run_katana(base_urls, config, limiter, profile_config)
        discovered_urls.extend(katana_urls)

    # Paramspider
    if "paramspider" in params_config.get("tools", []):
        param_urls = await _run_paramspider(base_urls, config, limiter)
        discovered_urls.extend(param_urls)

    # Arjun
    if "arjun" in params_config.get("tools", []):
        arjun_urls = await _run_arjun(discovered_urls or base_urls, config, limiter)
        discovered_urls.extend(arjun_urls)

    # Deduplicate
    discovered_urls = list(set(discovered_urls))

    # Fuzz parameters
    if params_config.get("fuzz_params", False) and discovered_urls:
        fuzz_findings = await _fuzz_parameters(discovered_urls, config, limiter, profile_config)
        all_findings.extend(fuzz_findings)

    return merge_findings(all_findings)
