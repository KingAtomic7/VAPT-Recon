# Multi-stage Dockerfile for vapt-recon
# Stage 1: Download pre-built Go tool binaries
FROM alpine:3.20 AS tool-downloader

RUN apk add --no-cache curl tar gzip

# Tool versions (pinned to known working releases)
ARG SUBFINDER_VERSION=v2.14.0
ARG NAABU_VERSION=v2.3.0
ARG NUCLEI_VERSION=v3.3.7
ARG HTTPX_VERSION=v1.6.8
ARG KATANA_VERSION=v1.1.0
ARG ASNMAP_VERSION=v1.1.0
ARG ALTERX_VERSION=v1.0.1
ARG DNSX_VERSION=v1.2.1
ARG TLSX_VERSION=v1.1.4
ARG UNCOVER_VERSION=v1.0.4
ARG COVER_VERSION=v1.0.2
ARG AMASS_VERSION=v4.2.0
ARG ASSETFINDER_VERSION=latest
ARG WAYBACKUNIQUE_VERSION=latest
ARG GAU_VERSION=v2.2.4
ARG DALFOX_VERSION=v2.8.0

# Download and install ProjectDiscovery tools from GitHub releases
RUN set -ex; \
    arch=$(uname -m); \
    case $arch in \
        x86_64) GOARCH=amd64 ;; \
        aarch64) GOARCH=arm64 ;; \
        *) echo "Unsupported arch: $arch"; exit 1 ;; \
    esac; \
    #
    # subfinder
    curl -sSL "https://github.com/projectdiscovery/subfinder/releases/download/${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION#v}_linux_${GOARCH}.zip" -o /tmp/subfinder.zip \
    && unzip -o /tmp/subfinder.zip -d /usr/local/bin/ subfinder \
    && rm /tmp/subfinder.zip; \
    #
    # naabu
    curl -sSL "https://github.com/projectdiscovery/naabu/releases/download/${NAABU_VERSION}/naabu_${NAABU_VERSION#v}_linux_${GOARCH}.zip" -o /tmp/naabu.zip \
    && unzip -o /tmp/naabu.zip -d /usr/local/bin/ naabu \
    && rm /tmp/naabu.zip; \
    #
    # nuclei
    curl -sSL "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION#v}_linux_${GOARCH}.zip" -o /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin/ nuclei \
    && rm /tmp/nuclei.zip; \
    #
    # httpx
    curl -sSL "https://github.com/projectdiscovery/httpx/releases/download/${HTTPX_VERSION}/httpx_${HTTPX_VERSION#v}_linux_${GOARCH}.zip" -o /tmp/httpx.zip \
    && unzip -o /tmp/httpx.zip -d /usr/local/bin/ httpx \
    && rm /tmp/httpx.zip; \
    #
    # katana
    curl -sSL "https://github.com/projectdiscovery/katana/releases/download/${KATANA_VERSION}/katana_${KATANA_VERSION#v}_linux_${GOARCH}.zip" -o /tmp/katana.zip \
    && unzip -o /tmp/katana.zip -d /usr/local/bin/ katana \
    && rm /tmp/katana.zip; \
    #
    # asnmap
    curl -sSL "https://github.com/projectdiscovery/asnmap/releases/download/${ASNMAP_VERSION}/asnmap_${ASNMAP_VERSION#v}_linux_${GOARCH}.zip" -o /tmp/asnmap.zip \
    && unzip -o /tmp/asnmap.zip -d /usr/local/bin/ asnmap \
    && rm /tmp/asnmap.zip; \
    #
    # alterx
    curl -sSL "https://github.com/projectdiscovery/alterx/releases/download/${ALTERX_VERSION}/alterx_${ALTERX_VERSION#v}_linux_${GOARCH}.zip" -o /tmp/alterx.zip \
    && unzip -o /tmp/alterx.zip -d /usr/local/bin/ alterx \
    && rm /tmp/alterx.zip; \
    #
    # dnsx
    curl -sSL "https://github.com/projectdiscovery/dnsx/releases/download/${DNSX_VERSION}/dnsx_${DNSX_VERSION#v}_linux_${GOARCH}.zip" -o /tmp/dnsx.zip \
    && unzip -o /tmp/dnsx.zip -d /usr/local/bin/ dnsx \
    && rm /tmp/dnsx.zip; \
    #
    # tlsx
    curl -sSL "https://github.com/projectdiscovery/tlsx/releases/download/${TLSX_VERSION}/tlsx_${TLSX_VERSION#v}_linux_${GOARCH}.zip" -o /tmp/tlsx.zip \
    && unzip -o /tmp/tlsx.zip -d /usr/local/bin/ tlsx \
    && rm /tmp/tlsx.zip; \
    #
    # uncover
    curl -sSL "https://github.com/projectdiscovery/uncover/releases/download/${UNCOVER_VERSION}/uncover_${UNCOVER_VERSION#v}_linux_${GOARCH}.zip" -o /tmp/uncover.zip \
    && unzip -o /tmp/uncover.zip -d /usr/local/bin/ uncover \
    && rm /tmp/uncover.zip; \
    #
    # cover
    curl -sSL "https://github.com/projectdiscovery/cover/releases/download/${COVER_VERSION}/cover_${COVER_VERSION#v}_linux_${GOARCH}.zip" -o /tmp/cover.zip \
    && unzip -o /tmp/cover.zip -d /usr/local/bin/ cover \
    && rm /tmp/cover.zip

# Download and install amass
RUN set -ex; \
    arch=$(uname -m); \
    case $arch in \
        x86_64) GOARCH=amd64 ;; \
        aarch64) GOARCH=arm64 ;; \
        *) echo "Unsupported arch: $arch"; exit 1 ;; \
    esac; \
    curl -sSL "https://github.com/owasp-amass/amass/releases/download/${AMASS_VERSION}/amass_linux_${GOARCH}.zip" -o /tmp/amass.zip \
    && unzip -o /tmp/amass.zip -d /tmp/amass/ \
    && mv /tmp/amass/amass /usr/local/bin/ \
    && rm -rf /tmp/amass.zip /tmp/amass

# Download and install other tools (using go install for these as they're simpler)
FROM golang:1.23-alpine AS go-tools
RUN apk add --no-cache git make gcc musl-dev libpcap-dev
RUN go install -v github.com/tomnomnom/assetfinder@latest \
    && go install -v github.com/tomnomnom/waybackunique@latest \
    && go install -v github.com/lc/gau/v2/cmd/gau@v2.2.4 \
    && go install -v github.com/hahwul/dalfox/v2@v2.8.0

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
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Copy Go binaries from downloaders
COPY --from=tool-downloader /usr/local/bin/* /usr/local/bin/
COPY --from=go-tools /go/bin/* /usr/local/bin/

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