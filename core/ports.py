"""Port scanning module."""

import asyncio
import xml.etree.ElementTree as ET
from typing import Any

from core.models import PortService, ReconConfig, Subdomain
from utils.dedupe import merge_services
from utils.rate_limit import get_limiter


async def _run_naabu(hosts: list[str], config: ReconConfig, limiter, profile_config: dict) -> list[PortService]:
    """Run naabu for fast port scanning."""
    services = []
    ports_config = profile_config.get("ports", {})
    top_ports = ports_config.get("top_ports", 1000)
    rate = ports_config.get("rate", 300)

    if top_ports > 0:
        port_args = ["-top-ports", str(top_ports)]
    else:
        port_args = ["-p-"]

    args = [
        "naabu", "-host", ",".join(hosts),
        "-rate", str(rate),
        "-silent", "-json",
        *port_args,
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)

        for line in stdout.decode().strip().split('\n'):
            if line:
                try:
                    data = json.loads(line)
                    host = data.get("host", "")
                    port = data.get("port", 0)
                    if host and port:
                        services.append(PortService(
                            host=host,
                            port=port,
                            protocol="tcp",
                            source="naabu",
                        ))
                except json.JSONDecodeError:
                    continue
    except (FileNotFoundError, asyncio.TimeoutError, Exception):
        pass
    return services


async def _run_nmap(hosts: list[str], config: ReconConfig, limiter, profile_config: dict) -> list[PortService]:
    """Run nmap for service detection."""
    services = []
    ports_config = profile_config.get("ports", {})
    nmap_args = ports_config.get("nmap_args", "-sV --version-intensity 5")

    args = ["nmap", *nmap_args.split(), "-oX", "-", ",".join(hosts)]

    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)

        root = ET.fromstring(stdout.decode())
        for host_elem in root.findall("host"):
            address_elem = host_elem.find("address")
            if address_elem is None:
                continue
            host = address_elem.get("addr", "")

            for port_elem in host_elem.findall("ports/port"):
                port_id = int(port_elem.get("portid", 0))
                protocol = port_elem.get("protocol", "tcp")
                state_elem = port_elem.find("state")
                state = state_elem.get("state", "open") if state_elem is not None else "open"

                service_elem = port_elem.find("service")
                service = service_elem.get("name") if service_elem is not None else None
                version = None
                if service_elem is not None:
                    version_parts = []
                    if service_elem.get("product"):
                        version_parts.append(service_elem.get("product"))
                    if service_elem.get("version"):
                        version_parts.append(service_elem.get("version"))
                    if service_elem.get("extrainfo"):
                        version_parts.append(service_elem.get("extrainfo"))
                    version = " ".join(version_parts) if version_parts else None

                services.append(PortService(
                    host=host,
                    port=port_id,
                    protocol=protocol,
                    service=service,
                    version=version,
                    state=state,
                    source="nmap",
                ))
    except (FileNotFoundError, asyncio.TimeoutError, ET.ParseError, Exception):
        pass
    return services


async def run_port_scan(subdomains: list[Subdomain], config: ReconConfig) -> list[PortService]:
    """Run port scanning on resolved subdomains."""
    limiter = get_limiter(config.rate_limit)
    profile_config = getattr(config, '_profile_config', {})

    # Collect unique hosts (IPs and hostnames)
    hosts = []
    for sd in subdomains:
        if sd.ip_addresses:
            hosts.extend(sd.ip_addresses)
        elif sd.resolved:
            hosts.append(sd.name)

    if not hosts:
        return []

    # Deduplicate hosts
    hosts = list(set(hosts))

    # Run naabu first
    naabu_services = await _run_naabu(hosts, config, limiter, profile_config)

    # Run nmap followup if configured
    ports_config = profile_config.get("ports", {})
    if ports_config.get("nmap_followup", False):
        nmap_services = await _run_nmap(hosts, config, limiter, profile_config)
        all_services = naabu_services + nmap_services
    else:
        all_services = naabu_services

    return merge_services(all_services)