# Configuration Guide

## Configuration Files

### `config/profiles.yaml` — Scan Profiles
Main configuration controlling tool behavior per profile.

```yaml
profiles:
  profile_name:
    name: "Display Name"
    description: "Profile description"
    subdomains:       # Subdomain enumeration config
    ports:            # Port scanning config
    tech:             # Technology fingerprinting config
    vulns:            # Vulnerability scanning config
    params:           # Parameter discovery config
    enrich:           # Enrichment config
```

### Profile Configuration Reference

#### Subdomains
```yaml
subdomains:
  sources: [subfinder, amass, assetfinder, crtsh, subjack, dnsdumpster]
  recursive: true|false
  timeout: 120          # seconds per source
  bruteforce: true|false
  wordlist: "path/to/wordlist.txt"
```

| Source | Description | Speed | Coverage |
|--------|-------------|-------|----------|
| `subfinder` | Passive sources (APIs, search engines) | Fast | High |
| `amass` | Active + passive, graph-based | Slow | Highest |
| `assetfinder` | Passive, subfinder sibling | Fast | Medium |
| `crtsh` | Certificate Transparency logs | Medium | Medium |
| `subjack` | Subdomain takeover detection | Slow | Specialized |
| `dnsdumpster` | DNS enumeration via API | Medium | Medium |

#### Ports
```yaml
ports:
  tool: "naabu"           # or "nmap"
  top_ports: 1000         # 0 = full scan (65535)
  rate: 300               # packets/second
  nmap_followup: true|false
  nmap_args: "-sV --version-intensity 5"
```

| Setting | Quick | Standard | Deep |
|---------|-------|----------|------|
| `top_ports` | 100 | 1000 | 0 (all) |
| `rate` | 500 | 300 | 200 |
| `nmap_followup` | false | true | true |

#### Technology Fingerprinting
```yaml
tech:
  tools: [httpx, wappalyzer, whatweb]
  timeout: 60
```

| Tool | Purpose |
|------|---------|
| `httpx` | HTTP probing + tech detect + WAF/CDN |
| `wappalyzer` | Deep fingerprinting (JS, meta tags, headers) |
| `whatweb` | Lightweight CMS/framework detection |

#### Vulnerability Scanning (Nuclei)
```yaml
vulns:
  nuclei:
    severity: [critical, high, medium, low, info]
    tags: [cve, rce, sqli, xss, ssrf, idor, lfi, misconfig, exposure]
    exclude_tags: [dos, fuzz, info]
    rate_limit: 100
    templates_dir: null           # null = built-in nuclei templates
    custom_templates: false       # true = use config/nuclei-templates/
    include_templates: []         # specific template names
```

| Profile | Severity | Tags |
|---------|----------|------|
| quick | critical | cve, rce, sqli |
| standard | critical, high | cve, rce, sqli, xss, ssrf, idor, lfi, rfi |
| deep | critical, high, medium | all except dos, fuzz, info |
| compliance | critical, high, medium | cve, misconfig, exposure, ssl, tls + compliance tags |

#### Parameter Discovery
```yaml
params:
  enabled: true|false
  tools: [katana, paramspider, arjun]
  max_urls: 500
  fuzz_params: true|false
  fuzz_wordlist: "fuzz-params.txt"
  fuzz_templates: "fuzzing"       # nuclei template category
```

| Tool | Purpose |
|------|---------|
| `katana` | Web crawling, JS parsing, endpoint discovery |
| `paramspider` | Parameter extraction from archives/wayback |
| `arjun` | HTTP parameter brute-force |

#### Enrichment
```yaml
enrich:
  enabled: true|false
  whois: true|false
  dns: true|false
  ssl: true|false
  shodan: true|false        # requires SHODAN_API_KEY
  censys: true|false        # requires CENSYS_API_ID/SECRET
```

### Global Settings
```yaml
global:
  default_profile: "standard"
  max_concurrent_scans: 1
  checkpoint_interval: 30
  default_output_dir: "./reports"
  default_rate_limit: 100
```

## Environment Variables

| Variable | Purpose | Required |
|----------|---------|----------|
| `SHODAN_API_KEY` | Shodan enrichment | No |
| `CENSYS_API_ID` | Censys enrichment | No |
| `CENSYS_API_SECRET` | Censys enrichment | No |
| `NUCLEI_TEMPLATES_PATH` | Custom nuclei templates dir | No |

## CLI Override Precedence

1. **CLI flags** (highest) — `--profile`, `--rate`, `--report`, etc.
2. **Profile config** — `config/profiles.yaml`
3. **Global config** — `global:` section
4. **Defaults** (lowest) — hardcoded defaults

## Custom Nuclei Templates

### Directory Structure
```
config/nuclei-templates/
├── cves/
│   ├── 2024/
│   └── 2023/
├── exposures/
├── misconfigurations/
├── injection/
├── auth/
├── info/
├── cloud/
└── custom/
    └── india/
```

### Template Format
```yaml
id: custom-india-razorpay-webhook
info:
  name: Razorpay Webhook Validation Bypass
  author: yourname
  severity: high
  tags: [india, payment, razorpay, bypass]
  reference:
    - https://razorpay.com/docs/webhooks/
  metadata:
    verified: true
requests:
  - method: POST
    path:
      - "{{BaseURL}}/webhook/razorpay"
    headers:
      Content-Type: application/json
    body: '{"payload": {"payment": {"entity": {}}}}'
    matchers:
      - type: word
        words: ["success", "verified"]
        part: body
```

### Enabling Custom Templates
```yaml
# In profiles.yaml
vulns:
  nuclei:
    custom_templates: true
```

Or via CLI:
```bash
vapt-recon scan example.com --profile standard \
  --config ./custom-profiles.yaml
```

## Report Customization

### Custom Logo/Branding
Modify `reporting/template.html.j2`:
```html
<!-- Replace cover page title -->
<h1>Your Company - VAPT Report</h1>

<!-- Add logo -->
<img src="data:image/png;base64,..." alt="Logo" class="w-32 h-32 mx-auto">
```

### Custom Colors
Update CSS variables in template:
```css
:root {
  --primary: #1e40af;      /* Your brand blue */
  --critical: #dc2626;
  --high: #ea580c;
  --medium: #d97706;
}
```

### Section Toggle
Add config to `ReconConfig` and condition in template:
```jinja2
{% if config.show_raw_output %}
  <section id="raw-output">...</section>
{% endif %}
```

## Example: Internal Network Profile

```yaml
# config/profiles.yaml - add to profiles:
internal:
  name: "Internal Network"
  description: "Internal VAPT with credentialed checks"
  subdomains:
    sources: [subfinder, assetfinder]
    recursive: false
    timeout: 60
  ports:
    tool: "naabu"
    top_ports: 0
    rate: 500
    nmap_followup: true
    nmap_args: "-sV -sC -p- --script auth,default,vuln"
  tech:
    tools: [httpx, wappalyzer]
  vulns:
    nuclei:
      severity: [critical, high, medium]
      tags: [cve, rce, sqli, default-login, misconfig]
      rate_limit: 200
  params:
    enabled: false
  enrich:
    enabled: false
  estimated_time_minutes: 45
```

## Validation

```bash
# Validate profiles config
vapt-recon validate config/profiles.yaml

# Debug profile loading
python -c "from config.profiles import load_profiles; print(load_profiles())"
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Tool not found | Ensure Go tools in PATH: `export PATH=$PATH:$(go env GOPATH)/bin` |
| Rate limit errors | Reduce `--rate` or increase tool-specific rates in profile |
| Timeout on nmap | Increase timeout in profile or reduce port range |
| PDF generation fails | Install system deps: `apt-get install libpango-1.0-0 libharfbuzz0b` |
| Nuclei templates not updating | Run `nuclei -update-templates` in container |