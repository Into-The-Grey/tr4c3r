# TR4C3R OSINT Platform
# Multi-stage build for optimized production image

# ============================================
# Stage 1: Builder
# ============================================
FROM python:3.14-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install pipenv
RUN pip install --no-cache-dir pipenv

# Copy dependency files
COPY Pipfile Pipfile.lock ./

# Generate requirements.txt from Pipfile
RUN pipenv requirements > requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ============================================
# Stage 2: Production
# ============================================
FROM python:3.14-slim as production

# Labels
LABEL maintainer="TR4C3R Team"
LABEL description="TR4C3R OSINT Platform"
LABEL version="1.0.0"

# Create non-root user for security
RUN groupadd -r tr4c3r && useradd -r -g tr4c3r tr4c3r

WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgl1-mesa-glx \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY src/ ./src/
COPY lib/ ./lib/
COPY config/ ./config/

# Create directories for data and logs
RUN mkdir -p /app/data /app/logs /app/exports \
    && chown -R tr4c3r:tr4c3r /app

# Environment variables
ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TR4C3R_ENV=production \
    TR4C3R_LOG_DIR=/app/logs \
    TR4C3R_DATA_DIR=/app/data \
    TR4C3R_EXPORT_DIR=/app/exports

# Switch to non-root user
USER tr4c3r

# Expose API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health')" || exit 1

# Default command: Run API server
CMD ["python", "-m", "uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

# ============================================
# Stage 3: Development
# ============================================
FROM production as development

USER root

# Install development dependencies
RUN pip install --no-cache-dir \
    pytest \
    pytest-asyncio \
    pytest-httpx \
    pytest-cov \
    black \
    flake8 \
    isort \
    mypy

# Copy test files
COPY tests/ ./tests/
COPY pyproject.toml Makefile ./

# Set development environment
ENV TR4C3R_ENV=development

USER tr4c3r

# Development command: Run tests
CMD ["python", "-m", "pytest", "-v"]
