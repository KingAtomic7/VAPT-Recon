"""Cross-module deduplication utilities."""

import re
from urllib.parse import urlparse

from core.models import Finding, PortService, Subdomain, Technology

# Subdomain normalization
_DOMAIN_REGEX = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$", re.I
)


def normalize_subdomain(subdomain: str) -> str:
    """Normalize subdomain to lowercase, strip trailing dot."""
    return subdomain.strip().lower().rstrip(".")


def is_valid_subdomain(subdomain: str) -> bool:
    """Validate subdomain format."""
    normalized = normalize_subdomain(subdomain)
    return bool(_DOMAIN_REGEX.match(normalized))


def merge_subdomains(subdomains: list[Subdomain]) -> list[Subdomain]:
    """Merge subdomains from multiple sources, deduplicating by normalized name."""
    merged: dict[str, Subdomain] = {}
    for sd in subdomains:
        normalized = normalize_subdomain(sd.name)
        if normalized not in merged:
            # Create new with normalized name
            merged[normalized] = Subdomain(
                name=normalized,
                source=sd.source,
                resolved=sd.resolved,
                ip_addresses=sd.ip_addresses.copy(),
                cname=sd.cname,
                discovered_at=sd.discovered_at,
            )
        else:
            # Merge sources and IPs
            existing = merged[normalized]
            if sd.source not in existing.source:
                existing.source += f",{sd.source}"
            for ip in sd.ip_addresses:
                if ip not in existing.ip_addresses:
                    existing.ip_addresses.append(ip)
            if sd.resolved and not existing.resolved:
                existing.resolved = True
            if sd.cname and not existing.cname:
                existing.cname = sd.cname

    return list(merged.values())


# URL normalization
def normalize_url(url: str) -> str:
    """Normalize URL for deduplication."""
    parsed = urlparse(url)
    # Normalize scheme
    scheme = parsed.scheme.lower()
    # Normalize host
    host = parsed.netloc.lower()
    # Remove default ports
    if (scheme == "http" and host.endswith(":80")) or (scheme == "https" and host.endswith(":443")):
        host = host.rsplit(":", 1)[0]
    # Normalize path - remove fragments, sort query params
    path = parsed.path.rstrip("/") or "/"
    query = "&".join(sorted(parsed.query.split("&"))) if parsed.query else ""
    normalized = f"{scheme}://{host}{path}"
    if query:
        normalized += f"?{query}"
    return normalized


# Finding deduplication
_FINGERPRINT_FIELDS = ["template_id", "matched_at", "severity"]


def finding_fingerprint(finding: Finding) -> str:
    """Generate fingerprint for finding deduplication."""
    parts = []
    for field in _FINGERPRINT_FIELDS:
        value = getattr(finding, field, "")
        if value:
            parts.append(str(value).lower())
    return "|".join(parts)


def merge_findings(findings: list[Finding]) -> list[Finding]:
    """Merge findings, deduplicating by fingerprint."""
    merged: dict[str, Finding] = {}
    for f in findings:
        fp = finding_fingerprint(f)
        if fp not in merged:
            merged[fp] = f
        else:
            # Merge evidence and references
            existing = merged[fp]
            if f.evidence and f.evidence not in (existing.evidence or ""):
                existing.evidence = (existing.evidence or "") + "\n---\n" + f.evidence
            for ref in f.references:
                if ref not in existing.references:
                    existing.references.append(ref)
    return list(merged.values())


# Technology deduplication
def normalize_technology(tech: Technology) -> tuple[str, str, str]:
    """Create dedup key for technology."""
    return (tech.url, tech.category.lower(), tech.name.lower())


def merge_technologies(technologies: list[Technology]) -> list[Technology]:
    """Merge technologies, keeping highest confidence."""
    merged: dict[tuple[str, str, str], Technology] = {}
    for tech in technologies:
        key = normalize_technology(tech)
        if key not in merged or tech.confidence > merged[key].confidence:
            merged[key] = tech
    return list(merged.values())


# Port service deduplication
def merge_services(services: list[PortService]) -> list[PortService]:
    """Merge port services, keeping most informative."""
    merged: dict[tuple[str, int, str], PortService] = {}
    for svc in services:
        key = (svc.host, svc.port, svc.protocol)
        if key not in merged:
            merged[key] = svc
        else:
            existing = merged[key]
            # Prefer nmap over naabu for service info
            if svc.source == "nmap" and existing.source == "naabu":
                merged[key] = svc
            elif svc.source == existing.source:
                # Merge version info
                if svc.version and not existing.version:
                    existing.version = svc.version
                if svc.service and not existing.service:
                    existing.service = svc.service
    return list(merged.values())
