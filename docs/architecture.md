# Architecture Documentation

## System Overview

vapt-recon is an async-first, modular reconnaissance pipeline built for penetration testing workflows. It follows a phased approach where each phase produces structured data consumed by subsequent phases.

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Subdomain  │────▶│    Port     │────▶│   Tech      │────▶│   Vuln      │
│  Enum       │     │   Scan      │     │  Fingerprint│     │   Scan      │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
       │                   │                   │                   │
       ▼                   ▼                   ▼                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        Parameter Discovery (optional)                   │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                            Enrichment (optional)                        │
│                    WHOIS, DNS, SSL, Shodan, Censys                      │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                          Report Generation                              │
│                     HTML │ PDF │ JSON (configurable)                   │
└─────────────────────────────────────────────────────────────────────────┘
```

## Design Decisions

### Why Async/Subprocess?
- **Tool ecosystem**: Best recon tools (subfinder, nuclei, naabu) are Go binaries
- **Performance**: Async subprocess allows concurrent execution across targets
- **Isolation**: Tool failures don't crash the main process
- **Version management**: Docker pins tool versions; host CLI uses system PATH

### Rate Limiting Strategy
- **Token bucket** per tool (not global) — different tools have different rate tolerances
- **Global cap** via config — prevents overwhelming target infrastructure
- **Burst allowance** — handles initial connection bursts gracefully

### Data Flow
```
ReconConfig (input)
      │
      ▼
ScanResult (accumulator) ──▶ Checkpoint (JSON, per-phase)
      │
      ▼
Report Formats (HTML/PDF/JSON)
```

### Deduplication Philosophy
- **Subdomains**: Exact match after normalization (case, www, trailing dot)
- **Services**: Host+port+protocol tuple; prefer nmap over naabu for service info
- **Technologies**: URL+category+name tuple; keep highest confidence
- **Findings**: Template_id+matched_at+severity fingerprint; merge evidence

## Component Details

### Core Models (`core/models.py`)
Pydantic v2 models with:
- Validation on input (target format, port ranges)
- Serialization for JSON reports
- Checkpoint persistence
- Schema versioning for forward compatibility

### Orchestrator (`core/recon.py`)
- Phase-based execution with progress callbacks
- Checkpoint save after each phase
- Error collection (continues on module failures)
- Tool version detection for reproducibility

### Subdomain Enum (`core/subdomains.py`)
- **Sources**: subfinder (primary), amass (comprehensive), assetfinder (fast), crt.sh (CT logs)
- **Concurrency**: All sources run in parallel via `asyncio.gather`
- **Deduplication**: Immediate merge after each source completes
- **Validation**: RFC-compliant domain regex

### Port Scanning (`core/ports.py`)
- **naabu**: Fast SYN scan, top-N ports, JSON output
- **nmap**: Service versioning (`-sV`), script scanning (`-sC`), XML output parsing
- **Hosts**: Resolved IPs from subdomains + hostnames

### Tech Fingerprinting (`core/tech.py`)
- **httpx**: HTTP probing + tech detection + WAF/CDN identification
- **Wappalyzer**: Deep fingerprinting via Go CLI
- **Categorization**: Auto-categorize (CMS, framework, server, CDN, WAF, etc.)

### Vulnerability Scanning (`core/vulns.py`)
- **Nuclei**: Template-based scanning with severity/tag filtering
- **Profiles**: Quick=critical only, Standard=critical+high, Deep=all but dos/fuzz
- **Output**: Parsed JSON → Finding models with MITRE ATT&CK extraction

### Parameter Discovery (`core/params.py`)
- **Katana**: Web crawling, JS parsing, known file discovery
- **ParamSpider**: Parameter discovery from archives/wayback
- **Arjun**: HTTP parameter discovery
- **Fuzzing**: Nuclei fuzzing templates on discovered params

### Enrichment (`utils/enrich.py`)
- **WHOIS**: System `whois` command
- **DNS**: dnspython (A, AAAA, CNAME, MX, TXT, NS, SOA)
- **SSL**: Python `ssl` module for cert details
- **Shodan/Censys**: Optional API integration

### Reporting
- **HTML**: Jinja2 + Tailwind CDN + Chart.js (self-contained)
- **PDF**: WeasyPrint with print CSS (TOC, headers, page breaks)
- **JSON**: Schema versioned, CI/CD ready

## Extension Points

### Adding a New Tool
1. Create module in `core/newtool.py` with `async def run_newtool(config)`
2. Add to orchestrator phase in `recon.py`
3. Update `ScanResult` model if new data type
4. Add template to `reporting/template.html.j2`

### Adding a Report Format
1. Create `reporting/newfmt.py` with `generate_newfmt_report(result, path)`
2. Add format to `ReportFormat` enum
3. Update `reporting/__init__.py` facade

### Custom Nuclei Templates
Place in `config/nuclei-templates/` and enable in profile:
```yaml
vulns:
  nuclei:
    custom_templates: true
```

## Performance Benchmarks

| Profile | Targets | Subdomains | Duration | Memory |
|---------|---------|------------|----------|--------|
| quick   | 1       | ~50        | ~45s     | ~150MB |
| standard| 1       | ~200       | ~12min   | ~300MB |
| deep    | 1       | ~1000      | ~45min   | ~500MB |

*Benchmarks on 8-core, 16GB RAM, 100Mbps connection*

## Security Considerations

- **Non-root Docker user** (UID 1000)
- **No secrets in image** — API keys via env vars at runtime
- **Tool isolation** — Each subprocess sandboxed
- **Output sanitization** — HTML escaping in reports
- **Rate limiting** — Prevents accidental DoS

## Future Improvements

- [ ] Distributed scanning via Celery/Ray
- [ ] Webhook notifications per phase
- [ ] Delta reporting (compare scans)
- [ ] Custom wordlist management
- [ ] Authenticated scanning support