# Multi-stage Dockerfile for vapt-recon
# Uses official ProjectDiscovery images where available

# Stage 1: Use official ProjectDiscovery images (available on Docker Hub)
FROM projectdiscovery/subfinder:v2.14.0 AS subfinder
FROM projectdiscovery/naabu:v2.3.0 AS naabu
FROM projectdiscovery/nuclei:v3.11.1 AS nuclei
FROM projectdiscovery/httpx:v1.6.10 AS httpx
FROM projectdiscovery/dnsx:v1.2.1 AS dnsx

# Stage 2: Build amass and katana from source (Go 1.23)
FROM golang:1.23-alpine AS go-tools
RUN apk add --no-cache git make gcc musl-dev libpcap-dev
# Install essential tools only
RUN go install -v github.com/owasp-amass/amass/v4/...@v4.2.0
RUN go install -v github.com/projectdiscovery/katana/cmd/katana@v1.1.3

# Stage 3: Python runtime with all tools
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
    && rm -rf /var/lib/apt/lists/*

# Copy tools from ProjectDiscovery images (copy all binaries from common locations)
COPY --from=subfinder /usr/bin/* /usr/local/bin/
COPY --from=naabu /usr/bin/* /usr/local/bin/
COPY --from=nuclei /usr/bin/* /usr/local/bin/
COPY --from=httpx /usr/bin/* /usr/local/bin/
COPY --from=dnsx /usr/bin/* /usr/local/bin/

# Copy remaining tools from go-tools
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