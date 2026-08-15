"""Enrichment utilities for additional context."""

import asyncio
import json
import socket
import ssl
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import httpx

from utils.rate_limit import get_limiter


async def enrich_whois(domain: str, limiter) -> dict[str, Any]:
    """WHOIS lookup for domain."""
    try:
        await limiter.acquire("whois", rate=5)
        proc = await asyncio.create_subprocess_exec(
            "whois", domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        return {"domain": domain, "whois": stdout.decode()[:5000]}
    except Exception:
        return {"domain": domain, "whois": None, "error": "lookup failed"}


async def enrich_dns(domain: str, limiter) -> dict[str, Any]:
    """DNS record enrichment."""
    records = {}
    record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]

    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        for rtype in record_types:
            try:
                await limiter.acquire("dns", rate=20)
                answers = resolver.resolve(domain, rtype)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                records[rtype] = []
    except ImportError:
        # Fallback: basic socket resolution
        try:
            await limiter.acquire("dns", rate=20)
            records["A"] = [socket.gethostbyname(domain)]
        except Exception:
            records["A"] = []

    return {"domain": domain, "dns": records}


async def enrich_ssl(host: str, port: int = 443, limiter=None) -> dict[str, Any]:
    """SSL/TLS certificate enrichment."""
    if limiter:
        await limiter.acquire("ssl", rate=10)

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return {
                    "host": host,
                    "port": port,
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "version": cert.get("version"),
                    "serial_number": cert.get("serialNumber"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "san": [x[1] for x in cert.get("subjectAltName", [])],
                    "signature_algorithm": cert.get("signatureAlgorithm"),
                }
    except Exception as e:
        return {"host": host, "port": port, "error": str(e)}


async def enrich_shodan(query: str, api_key: str, limiter) -> dict[str, Any]:
    """Shodan API enrichment."""
    if not api_key:
        return {"query": query, "results": None, "error": "no API key"}

    try:
        await limiter.acquire("shodan", rate=1)
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"https://api.shodan.io/shodan/host/search",
                params={"key": api_key, "query": query, "facets": "port,vuln"}
            )
            if resp.status_code == 200:
                return resp.json()
            return {"query": query, "error": f"API error: {resp.status_code}"}
    except Exception as e:
        return {"query": query, "error": str(e)}


async def enrich_censys(query: str, api_id: str, api_secret: str, limiter) -> dict[str, Any]:
    """Censys API enrichment."""
    if not api_id or not api_secret:
        return {"query": query, "results": None, "error": "no API credentials"}

    try:
        await limiter.acquire("censys", rate=1)
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                "https://search.censys.io/api/v2/hosts/search",
                json={"query": query, "per_page": 50},
                auth=(api_id, api_secret),
            )
            if resp.status_code == 200:
                return resp.json()
            return {"query": query, "error": f"API error: {resp.status_code}"}
    except Exception as e:
        return {"query": query, "error": str(e)}


async def run_enrichment(
    target: str,
    subdomains: list,
    services: list,
    config
) -> dict[str, Any]:
    """Run all enabled enrichment tasks."""
    limiter = get_limiter(config.rate_limit)
    profile_config = getattr(config, '_profile_config', {})
    enrich_config = profile_config.get("enrich", {})

    if not enrich_config.get("enabled", False):
        return {}

    results = {}

    # WHOIS
    if enrich_config.get("whois", False):
        results["whois"] = await enrich_whois(target, limiter)

    # DNS
    if enrich_config.get("dns", False):
        results["dns"] = await enrich_dns(target, limiter)

    # SSL for HTTPS services
    if enrich_config.get("ssl", False):
        ssl_results = []
        for svc in services:
            if svc.port in (443, 8443) or svc.service in ("https", "ssl"):
                ssl_results.append(await enrich_ssl(svc.host, svc.port, limiter))
        results["ssl"] = ssl_results

    # Shodan
    if enrich_config.get("shodan", False):
        import os
        api_key = os.getenv("SHODAN_API_KEY")
        results["shodan"] = await enrich_shodan(target, api_key, limiter)

    # Censys
    if enrich_config.get("censys", False):
        import os
        api_id = os.getenv("CENSYS_API_ID")
        api_secret = os.getenv("CENSYS_API_SECRET")
        results["censys"] = await enrich_censys(target, api_id, api_secret, limiter)

    return results