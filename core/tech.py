"""Technology fingerprinting module."""

import asyncio
import json

from core.models import PortService, ReconConfig, Technology
from utils.dedupe import merge_technologies
from utils.rate_limit import get_limiter

_TECH_CATEGORIES = {
    "cms": ["wordpress", "drupal", "joomla", "magento", "shopify", "wix", "squarespace"],
    "framework": [
        "react",
        "vue",
        "angular",
        "next.js",
        "nuxt",
        "svelte",
        "django",
        "flask",
        "fastapi",
        "express",
        "spring",
        "laravel",
        "rails",
        "asp.net",
    ],
    "language": ["php", "python", "node.js", "java", "go", "ruby", "asp.net"],
    "server": ["nginx", "apache", "iis", "lighttpd", "openresty", "caddy"],
    "cdn": ["cloudflare", "akamai", "fastly", "cloudfront", "maxcdn", "keycdn"],
    "waf": ["cloudflare", "incapsula", "sucuri", "akamai", "f5", "fortinet", "barracuda"],
    "analytics": ["google analytics", "matomo", "mixpanel", "segment", "hotjar"],
    "security": ["hsts", "csp", "x-frame-options", "x-xss-protection"],
}


def _categorize_tech(name: str) -> str:
    """Categorize technology by name."""
    name_lower = name.lower()
    for category, techs in _TECH_CATEGORIES.items():
        for tech in techs:
            if tech in name_lower:
                return category
    return "other"


async def _run_httpx(services: list[PortService], config: ReconConfig, limiter) -> list[Technology]:
    """Run httpx for technology detection."""
    technologies = []
    urls = []
    for svc in services:
        scheme = "https" if svc.port in (443, 8443) else "http"
        urls.append(f"{scheme}://{svc.host}:{svc.port}")

    if not urls:
        return technologies

    # Write URLs to temp file for httpx
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(urls))
        urls_file = f.name

    try:
        await limiter.acquire("httpx", rate=50)
        proc = await asyncio.create_subprocess_exec(
            "httpx",
            "-l",
            urls_file,
            "-json",
            "-tech-detect",
            "-status-code",
            "-title",
            "-web-server",
            "-cdn",
            "-waf",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)

        for line in stdout.decode().strip().split("\n"):
            if line:
                try:
                    data = json.loads(line)
                    url = data.get("url", "")
                    tech_list = data.get("tech", [])
                    webserver = data.get("webserver", "")
                    cdn = data.get("cdn", "")
                    waf = data.get("waf", "")

                    for tech_name in tech_list:
                        technologies.append(
                            Technology(
                                url=url,
                                category=_categorize_tech(tech_name),
                                name=tech_name,
                                source="httpx",
                                confidence=90,
                            )
                        )
                    if webserver:
                        technologies.append(
                            Technology(
                                url=url,
                                category="server",
                                name=webserver,
                                source="httpx",
                                confidence=95,
                            )
                        )
                    if cdn:
                        technologies.append(
                            Technology(
                                url=url,
                                category="cdn",
                                name=cdn,
                                source="httpx",
                                confidence=90,
                            )
                        )
                    if waf:
                        technologies.append(
                            Technology(
                                url=url,
                                category="waf",
                                name=waf,
                                source="httpx",
                                confidence=85,
                            )
                        )
                except json.JSONDecodeError:
                    continue
    except (TimeoutError, FileNotFoundError, Exception):
        pass
    finally:
        import os

        try:
            os.unlink(urls_file)
        except Exception:
            pass

    return technologies


async def _run_wappalyzer(
    services: list[PortService], config: ReconConfig, limiter
) -> list[Technology]:
    """Run Wappalyzer CLI for technology detection."""
    technologies = []
    urls = []
    for svc in services:
        scheme = "https" if svc.port in (443, 8443) else "http"
        urls.append(f"{scheme}://{svc.host}:{svc.port}")

    if not urls:
        return technologies

    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(urls))
        urls_file = f.name

    try:
        await limiter.acquire("wappalyzer", rate=20)
        proc = await asyncio.create_subprocess_exec(
            "wappalyzer",
            "-i",
            urls_file,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)

        for line in stdout.decode().strip().split("\n"):
            if line:
                try:
                    data = json.loads(line)
                    url = data.get("url", "")
                    for tech in data.get("technologies", []):
                        technologies.append(
                            Technology(
                                url=url,
                                category=_categorize_tech(tech.get("name", "")),
                                name=tech.get("name", ""),
                                version=tech.get("version"),
                                confidence=tech.get("confidence", 80),
                                source="wappalyzer",
                            )
                        )
                except json.JSONDecodeError:
                    continue
    except (TimeoutError, FileNotFoundError, Exception):
        pass
    finally:
        import os

        try:
            os.unlink(urls_file)
        except Exception:
            pass

    return technologies


async def run_tech_fingerprint(
    services: list[PortService], config: ReconConfig
) -> list[Technology]:
    """Run technology fingerprinting on discovered services."""
    limiter = get_limiter(config.rate_limit)
    profile_config = getattr(config, "_profile_config", {})

    tools = profile_config.get("tech", {}).get("tools", ["httpx"])

    tasks = []
    if "httpx" in tools:
        tasks.append(_run_httpx(services, config, limiter))
    if "wappalyzer" in tools:
        tasks.append(_run_wappalyzer(services, config, limiter))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    all_tech = []
    for result in results:
        if isinstance(result, list):
            all_tech.extend(result)

    return merge_technologies(all_tech)
