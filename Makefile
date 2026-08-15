# vapt-recon Makefile
# Developer convenience commands

.PHONY: help install lint typecheck test test-cov docker-build docker-run scan clean

# Default target
help:
	@echo "vapt-recon - Automated VAPT Reconnaissance Pipeline"
	@echo ""
	@echo "Usage:"
	@echo "  make install       Install package in development mode"
	@echo "  make lint          Run ruff linter"
	@echo "  make format        Format code with ruff"
	@echo "  make typecheck     Run mypy type checker"
	@echo "  make test          Run tests"
	@echo "  make test-cov      Run tests with coverage"
	@echo "  make docker-build  Build Docker image"
	@echo "  make docker-run    Run container interactively"
	@echo "  make scan          Run scan (requires TARGET)"
	@echo "  make clean         Clean build artifacts"

# Install in development mode
install:
	pip install -e .[dev]

# Linting
lint:
	ruff check .

format:
	ruff format .

typecheck:
	mypy .

# Testing
test:
	pytest tests/ -v --tb=short

test-cov:
	pytest tests/ -v --tb=short --cov=core --cov=reporting --cov=utils --cov-report=term-missing --cov-report=html

# Docker
docker-build:
	docker build -t vapt-recon:local .

docker-run:
	docker run -it --rm -v $(PWD)/reports:/home/scanner/reports vapt-recon:local --help

docker-scan:
	docker run -it --rm -v $(PWD)/reports:/home/scanner/reports vapt-recon:local scan $(TARGET) --profile $(or $(PROFILE),standard)

# Quick scan commands
scan:
	@if [ -z "$(TARGET)" ]; then echo "Usage: make scan TARGET=example.com [PROFILE=standard]"; exit 1; fi
	vapt-recon scan $(TARGET) --profile $(or $(PROFILE),standard) --report html,pdf,json --output ./reports

scan-quick:
	@if [ -z "$(TARGET)" ]; then echo "Usage: make scan-quick TARGET=example.com"; exit 1; fi
	vapt-recon scan $(TARGET) --profile quick --report html --output ./reports

scan-deep:
	@if [ -z "$(TARGET)" ]; then echo "Usage: make scan-deep TARGET=example.com"; exit 1; fi
	vapt-recon scan $(TARGET) --profile deep --report html,pdf,json --output ./reports

# Development helpers
watch:
	watch -n 2 'ls -la reports/'

logs:
	docker logs -f vapt-recon

# Cleanup
clean:
	rm -rf build/ dist/ *.egg-info/ .pytest_cache/ .coverage htmlcov/ .mypy_cache/ .ruff_cache/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

# Pre-commit
pre-commit:
	pre-commit run --all-files

# Release helpers
version-patch:
	bump2version patch

version-minor:
	bump2version minor

version-major:
	bump2version major