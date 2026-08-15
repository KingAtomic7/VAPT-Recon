"""HTML report generator."""

from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.models import ScanResult


def render_report(result: ScanResult) -> str:
    """Render HTML report from scan result."""
    template_dir = Path(__file__).parent
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(['html', 'xml']),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    # Add custom filters
    env.filters['slice'] = lambda seq, start, end=None: seq[start:end]

    template = env.get_template("template.html.j2")
    return template.render(
        config=result.config,
        metadata=result.metadata,
        subdomains=result.subdomains,
        services=result.services,
        technologies=result.technologies,
        findings=result.findings,
    )


async def generate_html_report(result: ScanResult, output_path: Path) -> Path:
    """Generate HTML report file."""
    html = render_report(result)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding='utf-8')
    return output_path