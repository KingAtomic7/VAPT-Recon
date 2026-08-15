# Curated Nuclei Templates for VAPT

This directory contains a curated set of Nuclei templates optimized for VAPT engagements. Templates are organized by category and mapped to scan profiles.

## Template Categories

### 1. CVEs (Critical/High)
| Template | CVE | Severity | Profile |
|----------|-----|----------|---------|
| `cves/2024/cve-2024-*.yaml` | Recent critical CVEs | Critical | All |
| `cves/2023/cve-2023-*.yaml` | 2023 critical CVEs | Critical/High | Standard+ |
| `cves/legacy/cve-2022-*.yaml` | Important legacy CVEs | High | Deep+ |

### 2. Exposures & Misconfigurations
| Template | Description | Profile |
|----------|-------------|---------|
| `exposures/git-config.yaml` | Exposed .git directories | All |
| `exposures/env-files.yaml` | Exposed .env files | All |
| `exposures/backup-files.yaml` | Backup files (.bak, .old, ~) | Standard+ |
| `exposures/docker-config.yaml` | Docker daemon exposure | Standard+ |
| `exposures/kubernetes.yaml` | K8s API exposure | Deep+ |
| `exposures/cloud-metadata.yaml` | Cloud metadata services (AWS/GCP/Azure) | Standard+ |

### 3. Authentication & Authorization
| Template | Description | Profile |
|----------|-------------|---------|
| `auth/bypass/admin-bypass.yaml` | Admin panel bypass | All |
| `auth/bypass/auth-bypass.yaml` | Authentication bypass | All |
| `auth/weak/default-creds.yaml` | Default credentials | Standard+ |
| `auth/weak/jwt-none.yaml` | JWT none algorithm | Standard+ |
| `auth/broken/idor.yaml` | IDOR patterns | Deep+ |

### 4. Injection Vulnerabilities
| Template | Description | Profile |
|----------|-------------|---------|
| `injection/sqli/basic.yaml` | Basic SQL injection | All |
| `injection/sqli/blind.yaml` | Blind SQL injection | Standard+ |
| `injection/xss/reflected.yaml` | Reflected XSS | All |
| `injection/xss/stored.yaml` | Stored XSS | Standard+ |
| `injection/ssrf/basic.yaml` | SSRF | All |
| `injection/rce/cmd-injection.yaml` | Command injection | All |
| `injection/xxe/basic.yaml` | XXE | Standard+ |
| `injection/deserialization/java.yaml` | Java deserialization | Deep+ |

### 5. Information Disclosure
| Template | Description | Profile |
|----------|-------------|---------|
| `info/disclosure/debug-pages.yaml` | Debug endpoints | Standard+ |
| `info/disclosure/api-docs.yaml` | Swagger/OpenAPI exposure | Standard+ |
| `info/disclosure/source-code.yaml` | Source code exposure | Deep+ |
| `info/tech/version-disclosure.yaml` | Version disclosure | Standard+ |

### 6. Cloud & Container Security
| Template | Description | Profile |
|----------|-------------|---------|
| `cloud/aws/s3-public.yaml` | Public S3 buckets | Standard+ |
| `cloud/aws/iam-misconfig.yaml` | IAM misconfigurations | Deep+ |
| `cloud/azure/storage.yaml` | Azure storage exposure | Deep+ |
| `cloud/gcp/iam.yaml` | GCP IAM issues | Deep+ |
| `cloud/kubernetes/rbac.yaml` | K8s RBAC misconfig | Deep+ |

### 7. Indian Application Patterns (Custom)
| Template | Description | Profile |
|----------|-------------|---------|
| `custom/india/razorpay-webhook.yaml` | Razorpay webhook validation | Standard+ |
| `custom/india/upi-deeplink.yaml` | UPI deep link handling | Standard+ |
| `custom/india/gst-api.yaml` | GST API exposure | Standard+ |
| `custom/india/aadhaar-api.yaml` | Aadhaar API integration | Standard+ |
| `custom/india/payment-gateway.yaml` | Generic payment gateway issues | Standard+ |

## Profile Mapping

| Profile | Templates Included |
|---------|-------------------|
| **quick** | CVE critical only, exposures (git, env), auth bypass, basic injection |
| **standard** | Quick + CVE high, misconfigurations, weak auth, reflected/stored XSS, SSRF, info disclosure, cloud metadata |
| **deep** | Standard + all CVEs, all injection, deserialization, source code disclosure, cloud configs, custom India templates |
| **compliance** | Standard + SSL/TLS, PCI-DSS, HIPAA, GDPR, ISO27001 specific templates |

## Usage

```bash
# Use with profile (automatic)
vapt-recon scan example.com --profile standard

# Use custom templates directory
nuclei -l targets.txt -t config/nuclei-templates/ -severity critical,high

# Use specific category
nuclei -l targets.txt -t config/nuclei-templates/exposures/
```

## Adding Custom Templates

1. Create YAML file in appropriate category directory
2. Follow Nuclei template format
3. Add to profile mapping in `config/profiles.yaml`
4. Test with `nuclei -t your-template.yaml -u https://example.com`

## Template Sources

- [ProjectDiscovery Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates) - Primary source
- [Nuclei Templates Community](https://github.com/nuclei-templates) - Community contributions
- Custom templates for Indian application patterns