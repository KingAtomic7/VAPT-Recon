"""Reporting facade for generating all report formats."""

from pathlib import Path
from typing import Any

from core.models import ScanResult, ReportFormat
from reporting.html import generate_html_report
from reporting.pdf import generate_pdf_report
from reporting.json import generate_json_report


async def generate_reports(config, result: ScanResult) -> dict[ReportFormat, Path]:
    """Generate all requested report formats."""
    outputs = {}

    for fmt in config.report_formats:
        output_path = config.output_dir / f"report_{config.target}_{config.profile.value}.{fmt.value}"

        if fmt == ReportFormat.HTML:
            outputs[fmt] = await generate_html_report(result, output_path)
        elif fmt == ReportFormat.PDF:
            outputs[fmt] = await generate_pdf_report(result, output_path)
        elif fmt == ReportFormat.JSON:
            outputs[fmt] = await generate_json_report(result, output_path)

    return outputs