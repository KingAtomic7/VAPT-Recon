# Multi-stage Dockerfile for vapt-recon
# Stage 1: Build essential Go tools (Go 1.22 - known compatible)
FROM golang:1.22-alpine AS go-builder

RUN apk add --no-cache git make gcc musl-dev libpcap-dev

# Install only essential ProjectDiscovery tools with versions known to work with Go 1.22
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.14.0 \
    && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.3.0 \
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.3.7 \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@v1.6.8 \
    && go install -v github.com/projectdiscovery/katana/cmd/katana@v1.1.0 \
    && go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.1

# Install amass
RUN go install -v github.com/owasp-amass/amass/v4/...@v4.2.0

# Install other essential Go tools
RUN go install -v github.com/tomnomnom/assetfinder@latest \
    && go install -v github.com/tomnomnom/waybackunique@latest \
    && go install -v github.com/lc/gau/v2/cmd/gau@latest \
    && go install -v github.com/hahwul/dalfox/v2@latest

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
    && rm -rf /var/lib/apt/lists/*

# Copy Go binaries from builder
COPY --from=go-builder /go/bin/* /usr/local/bin/

# Verify essential tools
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