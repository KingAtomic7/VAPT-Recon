"""PDF report generator using WeasyPrint."""

from pathlib import Path

try:
    from weasyprint import CSS, HTML
    from weasyprint.text.fonts import FontConfiguration

    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False

from core.models import ScanResult
from reporting.html import render_report


async def html_to_pdf(html_content: str, output_path: Path, base_url: str | None = None) -> Path:
    """Convert HTML to PDF using WeasyPrint."""
    if not WEASYPRINT_AVAILABLE:
        raise RuntimeError("WeasyPrint not installed. Install with: pip install weasyprint")

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    font_config = FontConfiguration()
    html_doc = HTML(string=html_content, base_url=base_url)

    # Custom CSS for print
    print_css = CSS(
        string="""
        @page {
            size: A4;
            margin: 2cm 1.5cm;
            @bottom-center {
                content: "Page " counter(page) " of " counter(pages);
                font-size: 9pt;
                color: #666;
            }
            @top-center {
                content: "VAPT Report - {{ config.target }}";
                font-size: 9pt;
                color: #666;
            }
        }
        body { font-size: 10pt; line-height: 1.4; }
        .page-break { page-break-before: always; }
        .card { break-inside: avoid; page-break-inside: avoid; }
        table { page-break-inside: auto; }
        tr { page-break-inside: avoid; page-break-after: auto; }
        thead { display: table-header-group; }
        pre { white-space: pre-wrap; word-wrap: break-word; }
        canvas { display: none; }  /* Hide charts in PDF */
        .no-print { display: none; }
    """,
        font_config=font_config,
    )

    html_doc.write_pdf(str(output_path), stylesheets=[print_css], font_config=font_config)
    return output_path


async def generate_pdf_report(result: ScanResult, output_path: Path) -> Path:
    """Generate PDF report from scan result."""
    html = render_report(result)
    return await html_to_pdf(html, output_path)
