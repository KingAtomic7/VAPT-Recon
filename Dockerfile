# Multi-stage Dockerfile for vapt-recon
# Download pre-built binaries from GitHub releases (no Go compilation)

# Stage 1: Download all tool binaries
FROM alpine:3.20 AS tool-downloader

RUN apk add --no-cache curl tar gzip unzip

# Tool versions - release tags include 'v' (e.g., v2.14.0), asset filenames don't
ARG SUBFINDER_VERSION=v2.14.0
ARG NAABU_VERSION=v2.3.0
ARG NUCLEI_VERSION=v3.11.1
ARG HTTPX_VERSION=v1.6.10
ARG KATANA_VERSION=v1.1.3
ARG DNSX_VERSION=v1.2.1
ARG AMASS_VERSION=v4.2.0

# Download and install from GitHub releases
RUN set -ex; \
    arch=$(uname -m); \
    case $arch in \
        x86_64) GOARCH=amd64 ;; \
        aarch64) GOARCH=arm64 ;; \
        *) echo "Unsupported arch: $arch"; exit 1 ;; \
    esac; \
    \
    # Note: release tags include 'v' (v2.14.0), asset filenames don't (subfinder_2.14.0_linux_amd64.zip)
    # subfinder
    SF_VER=${SUBFINDER_VERSION#v} \
    && curl -sSL "https://github.com/projectdiscovery/subfinder/releases/download/${SUBFINDER_VERSION}/subfinder_${SF_VER}_linux_${GOARCH}.zip" -o /tmp/subfinder.zip \
    && unzip -o /tmp/subfinder.zip -d /usr/local/bin/ subfinder \
    && rm /tmp/subfinder.zip; \
    \
    # naabu
    NB_VER=${NAABU_VERSION#v} \
    && curl -sSL "https://github.com/projectdiscovery/naabu/releases/download/${NAABU_VERSION}/naabu_${NB_VER}_linux_${GOARCH}.zip" -o /tmp/naabu.zip \
    && unzip -o /tmp/naabu.zip -d /usr/local/bin/ naabu \
    && rm /tmp/naabu.zip; \
    \
    # nuclei
    NC_VER=${NUCLEI_VERSION#v} \
    && curl -sSL "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NC_VER}_linux_${GOARCH}.zip" -o /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin/ nuclei \
    && rm /tmp/nuclei.zip; \
    \
    # httpx
    HX_VER=${HTTPX_VERSION#v} \
    && curl -sSL "https://github.com/projectdiscovery/httpx/releases/download/${HTTPX_VERSION}/httpx_${HX_VER}_linux_${GOARCH}.zip" -o /tmp/httpx.zip \
    && unzip -o /tmp/httpx.zip -d /usr/local/bin/ httpx \
    && rm /tmp/httpx.zip; \
    \
    # katana
    KT_VER=${KATANA_VERSION#v} \
    && curl -sSL "https://github.com/projectdiscovery/katana/releases/download/${KATANA_VERSION}/katana_${KT_VER}_linux_${GOARCH}.zip" -o /tmp/katana.zip \
    && unzip -o /tmp/katana.zip -d /usr/local/bin/ katana \
    && rm /tmp/katana.zip; \
    \
    # dnsx
    DX_VER=${DNSX_VERSION#v} \
    && curl -sSL "https://github.com/projectdiscovery/dnsx/releases/download/${DNSX_VERSION}/dnsx_${DX_VER}_linux_${GOARCH}.zip" -o /tmp/dnsx.zip \
    && unzip -o /tmp/dnsx.zip -d /usr/local/bin/ dnsx \
    && rm /tmp/dnsx.zip; \
    \
    # amass
    curl -sSL "https://github.com/owasp-amass/amass/releases/download/${AMASS_VERSION}/amass_linux_${GOARCH}.zip" -o /tmp/amass.zip \
    && unzip -o /tmp/amass.zip -d /tmp/amass/ \
    && mv /tmp/amass/amass /usr/local/bin/ \
    && rm -rf /tmp/amass.zip /tmp/amass

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