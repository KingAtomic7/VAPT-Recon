# Multi-stage Dockerfile for VAPT-Recon
# Download pre-built binaries from GitHub releases (no Go compilation)

# Stage 1: Download all tool binaries
FROM alpine:3.20 AS tool-downloader

RUN apk add --no-cache curl tar gzip unzip

# Tool versions - release tags include 'v' (e.g., v2.14.0), asset filenames don't
# Updated to latest versions built with Go >=1.24.13 to fix CVE-2025-68121
ARG SUBFINDER_VERSION=v2.15.0
ARG NAABU_VERSION=v2.6.1
ARG NUCLEI_VERSION=v3.11.1
ARG HTTPX_VERSION=v1.10.0
ARG KATANA_VERSION=v1.7.0
ARG DNSX_VERSION=v1.3.0
ARG AMASS_VERSION=v5.1.1

# Detect architecture
RUN set -ex; \
    arch=$(uname -m); \
    case $arch in \
        x86_64) echo "GOARCH=amd64" > /tmp/arch.txt ;; \
        aarch64) echo "GOARCH=arm64" > /tmp/arch.txt ;; \
        *) echo "Unsupported arch: $arch"; exit 1 ;; \
    esac

# Download each tool in separate RUN commands for isolation and cache busting
RUN . /tmp/arch.txt && SF_VER=${SUBFINDER_VERSION#v} && curl -sSL "https://github.com/projectdiscovery/subfinder/releases/download/${SUBFINDER_VERSION}/subfinder_${SF_VER}_linux_${GOARCH}.zip" -o /tmp/subfinder.zip && unzip -o /tmp/subfinder.zip -d /usr/local/bin/ subfinder && rm /tmp/subfinder.zip

RUN . /tmp/arch.txt && NB_VER=${NAABU_VERSION#v} && curl -sSL "https://github.com/projectdiscovery/naabu/releases/download/${NAABU_VERSION}/naabu_${NB_VER}_linux_${GOARCH}.zip" -o /tmp/naabu.zip && unzip -o /tmp/naabu.zip -d /usr/local/bin/ naabu && rm /tmp/naabu.zip

RUN . /tmp/arch.txt && NC_VER=${NUCLEI_VERSION#v} && curl -sSL "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NC_VER}_linux_${GOARCH}.zip" -o /tmp/nuclei.zip && unzip -o /tmp/nuclei.zip -d /usr/local/bin/ nuclei && rm /tmp/nuclei.zip

RUN . /tmp/arch.txt && HX_VER=${HTTPX_VERSION#v} && curl -sSL "https://github.com/projectdiscovery/httpx/releases/download/${HTTPX_VERSION}/httpx_${HX_VER}_linux_${GOARCH}.zip" -o /tmp/httpx.zip && unzip -o /tmp/httpx.zip -d /usr/local/bin/ httpx && rm /tmp/httpx.zip

RUN . /tmp/arch.txt && KT_VER=${KATANA_VERSION#v} && curl -sSL "https://github.com/projectdiscovery/katana/releases/download/${KATANA_VERSION}/katana_${KT_VER}_linux_${GOARCH}.zip" -o /tmp/katana.zip && unzip -o /tmp/katana.zip -d /usr/local/bin/ katana && rm /tmp/katana.zip

RUN . /tmp/arch.txt && DX_VER=${DNSX_VERSION#v} && curl -sSL "https://github.com/projectdiscovery/dnsx/releases/download/${DNSX_VERSION}/dnsx_${DX_VER}_linux_${GOARCH}.zip" -o /tmp/dnsx.zip && unzip -o /tmp/dnsx.zip -d /usr/local/bin/ dnsx && rm /tmp/dnsx.zip

# amass v5.1.1 uses .tar.gz format (extracts to amass_linux_${GOARCH}/amass)
ARG AMASS_VERSION=v5.1.1
RUN . /tmp/arch.txt && curl -sSL "https://github.com/owasp-amass/amass/releases/download/${AMASS_VERSION}/amass_linux_${GOARCH}.tar.gz" -o /tmp/amass.tar.gz && mkdir -p /tmp/amass && tar -xzf /tmp/amass.tar.gz -C /tmp/amass/ && mv /tmp/amass/amass_linux_${GOARCH}/amass /usr/local/bin/ && rm -rf /tmp/amass.tar.gz /tmp/amass

# Stage 2: Python runtime with tools
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    whois \
    dnsutils \
    curl \
    wget \
    ca-certificates \
    libpango-1.0-0 \
    libharfbuzz0b \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    shared-mime-info \
    libpcap0.8 \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Copy all binaries from downloader
COPY --from=tool-downloader /usr/local/bin/* /usr/local/bin/

# Verify tools
RUN subfinder -version && naabu -version && nuclei -version && httpx -version

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash scanner
WORKDIR /home/scanner

# Copy Python project
COPY pyproject.toml ./
COPY README.md ./

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -e .

# Copy source code
COPY --chown=scanner:scanner . .

# Switch to non-root user
USER scanner

# Create output directory
RUN mkdir -p reports

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import vapt_recon; print('OK')" || exit 1

ENTRYPOINT ["vapt-recon"]
CMD ["--help"]