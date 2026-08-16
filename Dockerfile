# Multi-stage Dockerfile for vapt-recon
# Single Go builder stage with separated installs (Go 1.21 - stable)

# Stage 1: Build all Go tools from source
FROM golang:1.21-alpine AS go-builder

RUN apk add --no-cache git make gcc musl-dev libpcap-dev

# Install tools with separated RUN commands for isolation
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.14.0
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.3.0
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@v1.6.10
RUN go install -v github.com/projectdiscovery/katana/cmd/katana@v1.1.3
RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.1
RUN go install -v github.com/owasp-amass/amass/v4/...@v4.2.0

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