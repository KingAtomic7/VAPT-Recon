#!/usr/bin/env python3
"""VAPT-Recon: Automated VAPT Reconnaissance Pipeline"""

import asyncio
import sys
from collections import Counter
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from config.profiles import load_profiles
from core.models import (
    Profile,
    ReconConfig,
    ReportFormat,
    ScanResult,
)
from core.recon import run_recon
from reporting import generate_reports

app = typer.Typer(
    name="VAPT-Recon",
    help="Automated VAPT reconnaissance pipeline",
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()


def version_callback(value: bool) -> None:
    if value:
        console.print("VAPT-Recon 0.1.0")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option("--version", "-v", callback=version_callback, help="Show version"),
    ] = None,
) -> None:
    """Automated VAPT reconnaissance & vulnerability scanning pipeline."""


def _build_scan_config(
    target: str,
    profile: Profile,
    report: list[ReportFormat] | None,
    output: Path,
    rate_limit: int,
    resume: bool,
    config_file: Path | None,
) -> ReconConfig:
    """Build ReconConfig from scan parameters."""
    return ReconConfig(
        target=target,
        profile=profile,
        report_formats=report or [ReportFormat.HTML],
        output_dir=output,
        rate_limit=rate_limit,
        resume=resume,
        config_path=config_file,
    )


@app.command()
def scan(
    target: Annotated[str, typer.Argument(help="Target domain (e.g., example.com)")],
    profile: Annotated[
        Profile,
        typer.Option("--profile", "-p", help="Scan profile", case_sensitive=False),
    ] = Profile.STANDARD,
    report: Annotated[
        list[ReportFormat] | None,
        typer.Option("--report", "-r", help="Report formats"),
    ] = None,
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Output directory"),
    ] = Path("./reports"),
    rate_limit: Annotated[
        int,
        typer.Option("--rate", help="Requests per second (global)"),
    ] = 100,
    resume: Annotated[
        bool,
        typer.Option("--resume", help="Resume from last checkpoint"),
    ] = False,
    config_file: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Custom profiles YAML"),
    ] = None,
) -> None:
    """Run reconnaissance scan on target domain."""
    config = _build_scan_config(target, profile, report, output, rate_limit, resume, config_file)

    console.print(
        Panel.fit(
            f"[bold cyan]VAPT-Recon[/bold cyan] - {profile.value.upper()} scan\n"
            f"Target: [bold]{target}[/bold]\n"
            f"Reports: {', '.join(r.value for r in config.report_formats)}",
            title="Starting Scan",
            border_style="cyan",
        )
    )

    try:
        result = asyncio.run(run_recon(config))
        asyncio.run(generate_reports(config, result))
        _print_summary(result)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@app.command()
def profiles(
    config_file: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Custom profiles YAML"),
    ] = None,
) -> None:
    """List available scan profiles."""
    profiles_data = load_profiles(config_file)

    table = Table(title="Available Scan Profiles")
    table.add_column("Profile", style="cyan")
    table.add_column("Subdomains", style="green")
    table.add_column("Ports", style="yellow")
    table.add_column("Nuclei Templates", style="magenta")
    table.add_column("Est. Time", style="blue")

    for name, p in profiles_data.items():
        table.add_row(
            name,
            p.get("subdomains", "—"),
            p.get("ports", "—"),
            p.get("nuclei", "—"),
            p.get("time", "—"),
        )

    console.print(table)


@app.command()
def validate(
    config_file: Annotated[
        Path,
        typer.Argument(help="Profiles YAML to validate"),
    ],
) -> None:
    """Validate profiles configuration."""
    try:
        load_profiles(config_file)
        console.print("[green]✓ Configuration valid[/green]")
    except Exception as e:
        console.print(f"[red]Invalid config: {e}[/red]")
        raise typer.Exit(1) from e


def _print_summary(result: ScanResult) -> None:
    """Print scan summary table."""
    table = Table(title=f"Scan Summary: {result.config.target}")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", style="bold")

    table.add_row("Subdomains", str(len(result.subdomains)))
    table.add_row("Services", str(len(result.services)))
    table.add_row("Technologies", str(len(result.technologies)))
    table.add_row("Findings", str(len(result.findings)))

    if result.findings:
        sev_counts = Counter(f.severity.value for f in result.findings)
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev_counts.get(sev, 0) > 0:
                table.add_row(f"  {sev.capitalize()}", str(sev_counts[sev]))

    console.print(table)
    console.print(f"\n[green]✓ Reports saved to {result.config.output_dir}[/green]")


if __name__ == "__main__":
    app()
