"""Subdomain enumeration module."""

import asyncio
import json

import httpx

from core.models import ReconConfig, Subdomain
from utils.dedupe import is_valid_subdomain, merge_subdomains, normalize_subdomain
from utils.rate_limit import get_limiter


async def _run_subfinder(target: str, config: ReconConfig, limiter) -> list[Subdomain]:
    """Run subfinder for subdomain enumeration."""
    subdomains = []
    try:
        proc = await asyncio.create_subprocess_exec(
            "subfinder",
            "-d",
            target,
            "-silent",
            "-json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=config.checkpoint_file.parent.stat().st_size if config.checkpoint_file else 120,
        )

        for line in stdout.decode().strip().split("\n"):
            if line:
                try:
                    data = json.loads(line)
                    host = data.get("host", "").strip()
                    if host and is_valid_subdomain(host):
                        subdomains.append(
                            Subdomain(
                                name=normalize_subdomain(host),
                                source="subfinder",
                                resolved=True,
                            )
                        )
                except json.JSONDecodeError:
                    continue
    except (TimeoutError, FileNotFoundError, Exception):
        pass
    return subdomains


async def _run_amass(target: str, config: ReconConfig, limiter) -> list[Subdomain]:
    """Run amass for subdomain enumeration."""
    subdomains = []
    try:
        proc = await asyncio.create_subprocess_exec(
            "amass",
            "enum",
            "-d",
            target,
            "-json",
            "-silent",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=180)

        for line in stdout.decode().strip().split("\n"):
            if line:
                try:
                    data = json.loads(line)
                    name = data.get("name", "").strip()
                    if name and is_valid_subdomain(name):
                        subdomains.append(
                            Subdomain(
                                name=normalize_subdomain(name),
                                source="amass",
                                resolved=True,
                            )
                        )
                except json.JSONDecodeError:
                    continue
    except (TimeoutError, FileNotFoundError, Exception):
        pass
    return subdomains


async def _run_assetfinder(target: str, config: ReconConfig, limiter) -> list[Subdomain]:
    """Run assetfinder for subdomain enumeration."""
    subdomains = []
    try:
        proc = await asyncio.create_subprocess_exec(
            "assetfinder",
            "--subs-only",
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)

        for line in stdout.decode().strip().split("\n"):
            host = line.strip()
            if host and is_valid_subdomain(host):
                subdomains.append(
                    Subdomain(
                        name=normalize_subdomain(host),
                        source="assetfinder",
                        resolved=False,
                    )
                )
    except (TimeoutError, FileNotFoundError, Exception):
        pass
    return subdomains


async def _run_crtsh(target: str, config: ReconConfig, limiter) -> list[Subdomain]:
    """Query crt.sh for subdomain enumeration."""
    subdomains = []
    try:
        await limiter.acquire("crtsh", rate=10)
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(f"https://crt.sh/?q=%25.{target}&output=json")
            if resp.status_code == 200:
                for entry in resp.json():
                    name = entry.get("name_value", "").strip()
                    for n in name.split("\n"):
                        n = n.strip()
                        if n and is_valid_subdomain(n) and not n.startswith("*"):
                            subdomains.append(
                                Subdomain(
                                    name=normalize_subdomain(n),
                                    source="crtsh",
                                    resolved=False,
                                )
                            )
    except Exception:
        pass
    return subdomains


async def run_subdomain_enum(config: ReconConfig) -> list[Subdomain]:
    """Run subdomain enumeration with configured sources."""
    limiter = get_limiter(config.rate_limit)
    profile_config = getattr(config, "_profile_config", {})

    sources = profile_config.get("subdomains", {}).get("sources", ["subfinder"])
    timeout = profile_config.get("subdomains", {}).get("timeout", 120)

    tasks = []
    if "subfinder" in sources:
        tasks.append(_run_subfinder(config.target, config, limiter))
    if "amass" in sources:
        tasks.append(_run_amass(config.target, config, limiter))
    if "assetfinder" in sources:
        tasks.append(_run_assetfinder(config.target, config, limiter))
    if "crtsh" in sources:
        tasks.append(_run_crtsh(config.target, config, limiter))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    all_subdomains = []
    for result in results:
        if isinstance(result, list):
            all_subdomains.extend(result)

    return merge_subdomains(all_subdomains)
