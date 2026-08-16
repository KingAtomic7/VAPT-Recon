"""JSON report generator for CI/CD integration."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from core.models import ScanResult

SCHEMA_VERSION = "1.0"


def serialize_scan_result(result: ScanResult) -> dict[str, Any]:
    """Serialize scan result to JSON-compatible dict."""
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "metadata": {
            "scan_id": result.metadata.scan_id,
            "target": result.config.target,
            "profile": result.config.profile.value,
            "started_at": result.metadata.started_at.isoformat() + "Z",
            "completed_at": result.metadata.completed_at.isoformat() + "Z"
            if result.metadata.completed_at
            else None,
            "duration_seconds": result.metadata.duration_seconds,
            "tools_versions": result.metadata.tools_versions,
        },
        "summary": {
            "subdomains": len(result.subdomains),
            "services": len(result.services),
            "technologies": len(result.technologies),
            "findings": len(result.findings),
            "findings_by_severity": result.summary(),
        },
        "subdomains": [
            {
                "name": sd.name,
                "source": sd.source,
                "resolved": sd.resolved,
                "ip_addresses": sd.ip_addresses,
                "cname": sd.cname,
            }
            for sd in result.subdomains
        ],
        "services": [
            {
                "host": svc.host,
                "port": svc.port,
                "protocol": svc.protocol,
                "service": svc.service,
                "version": svc.version,
                "state": svc.state,
                "source": svc.source,
            }
            for svc in result.services
        ],
        "technologies": [
            {
                "url": tech.url,
                "category": tech.category,
                "name": tech.name,
                "version": tech.version,
                "confidence": tech.confidence,
                "source": tech.source,
            }
            for tech in result.technologies
        ],
        "findings": [
            {
                "id": f.id,
                "template_id": f.template_id,
                "name": f.name,
                "severity": f.severity.value,
                "cvss": f.cvss,
                "description": f.description,
                "matched_at": f.matched_at,
                "evidence": f.evidence,
                "extraction": f.extraction,
                "references": f.references,
                "tags": f.tags,
                "mitre_techniques": f.mitre_techniques,
                "cwe": f.cwe,
            }
            for f in result.findings
        ],
        "errors": result.errors,
    }


async def generate_json_report(result: ScanResult, output_path: Path) -> Path:
    """Generate JSON report file."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    data = serialize_scan_result(result)
    output_path.write_text(json.dumps(data, indent=2, default=str))
    return output_path
