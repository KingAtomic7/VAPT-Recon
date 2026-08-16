"""Main recon orchestrator."""

import json
import time
from datetime import datetime

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from config.profiles import load_profiles
from core.models import (
    Finding,
    PortService,
    ReconConfig,
    ScanMetadata,
    ScanResult,
    Subdomain,
    Technology,
)
from core.params import run_param_discovery
from core.ports import run_port_scan
from core.subdomains import run_subdomain_enum
from core.tech import run_tech_fingerprint
from core.vulns import run_vuln_scan
from utils.enrich import run_enrichment

console = Console()

# Phase names in order for checkpoint tracking
PHASE_NAMES = [
    "Subdomain Enumeration",
    "Port Scanning",
    "Technology Fingerprinting",
    "Vulnerability Scanning",
    "Parameter Discovery",
    "Enrichment",
]


async def run_recon(config: ReconConfig) -> ScanResult:
    """Run complete reconnaissance pipeline."""
    start_time = time.monotonic()

    # Load profile configuration
    if config.config_path:
        profile_config = load_profiles(config.config_path).get(config.profile.value, {})
    else:
        profile_config = load_profiles().get(config.profile.value, {})

    # Attach profile config to config object for modules to access
    config._profile_config = profile_config

    # Initialize metadata
    metadata = ScanMetadata(
        target=config.target,
        profile=config.profile,
        started_at=datetime.utcnow(),
    )

    # Initialize result
    result = ScanResult(
        config=config,
        metadata=metadata,
    )

    # Load completed phases from checkpoint if resuming
    completed_phases: list[str] = []
    if config.resume and config.checkpoint_file and config.checkpoint_file.exists():
        completed_phases = await _load_checkpoint(config, result)

    # Progress tracking
    phases = [
        ("Subdomain Enumeration", _run_subdomains_phase, 0.15),
        ("Port Scanning", _run_ports_phase, 0.25),
        ("Technology Fingerprinting", _run_tech_phase, 0.15),
        ("Vulnerability Scanning", _run_vulns_phase, 0.30),
        ("Parameter Discovery", _run_params_phase, 0.10),
        ("Enrichment", _run_enrich_phase, 0.05),
    ]

    completed_weight = 0.0

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        main_task = progress.add_task("Overall Progress", total=100)

        for phase_name, phase_func, weight in phases:
            phase_task = progress.add_task(phase_name, total=100)
            progress.update(main_task, completed=completed_weight * 100)

            # Skip phase if already completed (resume)
            if phase_name in completed_phases:
                progress.update(
                    phase_task,
                    completed=100,
                    description=f"{phase_name} [yellow]SKIPPED (resumed)[/yellow]",
                )
                completed_weight += weight
                progress.update(main_task, completed=completed_weight * 100)
                continue

            try:
                await phase_func(
                    config,
                    result,
                    lambda completed, **kwargs: progress.update(
                        phase_task, completed=completed, **kwargs
                    ),
                )
                progress.update(phase_task, completed=100)
                completed_weight += weight
                progress.update(main_task, completed=completed_weight * 100)
                completed_phases.append(phase_name)
            except Exception as e:
                result.errors.append(f"{phase_name}: {e!s}")
                progress.update(
                    phase_task, completed=100, description=f"{phase_name} [red]FAILED[/red]"
                )
                completed_weight += weight
                progress.update(main_task, completed=completed_weight * 100)

            # Save checkpoint after each phase
            await _save_checkpoint(config, result, completed_phases)

    # Finalize metadata
    end_time = time.monotonic()
    metadata.completed_at = datetime.utcnow()
    metadata.duration_seconds = end_time - start_time

    # Save final checkpoint
    await _save_checkpoint(config, result, completed_phases)

    return result


async def _run_subdomains_phase(config: ReconConfig, result: ScanResult, update_progress) -> None:
    """Run subdomain enumeration phase."""
    update_progress(10, description="Starting subdomain enumeration...")
    subdomains = await run_subdomain_enum(config)
    update_progress(60, description=f"Found {len(subdomains)} subdomains, merging...")
    result.subdomains = subdomains
    update_progress(90, description="Updating metadata...")
    result.metadata.tools_versions["subfinder"] = "latest"
    update_progress(100, description=f"Completed: {len(subdomains)} subdomains")


async def _run_ports_phase(config: ReconConfig, result: ScanResult, update_progress) -> None:
    """Run port scanning phase."""
    update_progress(10, description="Resolving hosts...")
    update_progress(30, description="Running naabu...")
    services = await run_port_scan(result.subdomains, config)
    update_progress(80, description=f"Found {len(services)} services, merging...")
    result.services = services
    result.metadata.tools_versions["naabu"] = "latest"
    result.metadata.tools_versions["nmap"] = "latest"
    update_progress(100, description=f"Completed: {len(services)} services")


async def _run_tech_phase(config: ReconConfig, result: ScanResult, update_progress) -> None:
    """Run technology fingerprinting phase."""
    update_progress(20, description="Running httpx...")
    technologies = await run_tech_fingerprint(result.services, config)
    update_progress(80, description=f"Found {len(technologies)} technologies, merging...")
    result.technologies = technologies
    result.metadata.tools_versions["httpx"] = "latest"
    result.metadata.tools_versions["wappalyzer"] = "latest"
    update_progress(100, description=f"Completed: {len(technologies)} technologies")


async def _run_vulns_phase(config: ReconConfig, result: ScanResult, update_progress) -> None:
    """Run vulnerability scanning phase."""
    update_progress(10, description="Preparing targets...")
    update_progress(30, description="Running nuclei...")
    findings = await run_vuln_scan(result.technologies, config)
    update_progress(80, description=f"Found {len(findings)} findings, deduplicating...")
    result.findings = findings
    result.metadata.tools_versions["nuclei"] = "latest"
    update_progress(100, description=f"Completed: {len(findings)} findings")


async def _run_params_phase(config: ReconConfig, result: ScanResult, update_progress) -> None:
    """Run parameter discovery phase."""
    profile_config = getattr(config, "_profile_config", {})
    if not profile_config.get("params", {}).get("enabled", False):
        update_progress(100, description="Skipped (disabled in profile)")
        return

    update_progress(20, description="Discovering parameters...")
    param_findings = await run_param_discovery(result.technologies, config)
    update_progress(80, description=f"Found {len(param_findings)} param findings...")
    result.findings.extend(param_findings)
    result.metadata.tools_versions["katana"] = "latest"
    update_progress(100, description=f"Completed: {len(param_findings)} param findings")


async def _run_enrich_phase(config: ReconConfig, result: ScanResult, update_progress) -> None:
    """Run enrichment phase."""
    profile_config = getattr(config, "_profile_config", {})
    if not profile_config.get("enrich", {}).get("enabled", False):
        update_progress(100, description="Skipped (disabled in profile)")
        return

    update_progress(30, description="Running enrichment...")
    enrichment = await run_enrichment(config.target, result.subdomains, result.services, config)
    update_progress(100, description="Enrichment completed")
    result.metadata.config_snapshot["enrichment"] = enrichment


async def _save_checkpoint(
    config: ReconConfig, result: ScanResult, completed_phases: list[str] | None = None
) -> None:
    """Save scan progress checkpoint."""
    if not config.checkpoint_file:
        return

    try:
        checkpoint_data = {
            "config": {
                "target": config.target,
                "profile": config.profile.value,
                "rate_limit": config.rate_limit,
            },
            "result": result.model_dump(mode="json"),
            "completed_phases": completed_phases or [],
            "saved_at": datetime.utcnow().isoformat(),
        }
        config.checkpoint_file.write_text(json.dumps(checkpoint_data, indent=2))
    except Exception:
        pass  # Don't fail scan on checkpoint error


async def _load_checkpoint(config: ReconConfig, result: ScanResult) -> list[str]:
    """Load scan progress from checkpoint. Returns list of completed phase names."""
    if not config.checkpoint_file or not config.checkpoint_file.exists():
        return []

    try:
        data = json.loads(config.checkpoint_file.read_text())
        # Restore result data
        checkpoint_result = data.get("result", {})
        result.subdomains = [Subdomain(**s) for s in checkpoint_result.get("subdomains", [])]
        result.services = [PortService(**s) for s in checkpoint_result.get("services", [])]
        result.technologies = [Technology(**s) for s in checkpoint_result.get("technologies", [])]
        result.findings = [Finding(**s) for s in checkpoint_result.get("findings", [])]
        result.errors = checkpoint_result.get("errors", [])
        console.print(f"[yellow]Resumed from checkpoint: {config.checkpoint_file}[/yellow]")
        completed = data.get("completed_phases", [])
        console.print(f"[yellow]Completed phases loaded: {completed}[/yellow]")
    except Exception as e:
        console.print(f"[red]Checkpoint load error: {e}[/red]")
        return []  # Ignore checkpoint load errors
    else:
        return completed
