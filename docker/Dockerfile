# Multi-stage build for PKI Management System
# Stage 1: Dependencies
FROM python:3.12-slim as deps

WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libssl-dev && \
    rm -rf /var/lib/apt/lists/*

COPY ../requirements.txt .
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir -r requirements.txt

# Stage 2: Application
FROM python:3.12-slim

WORKDIR /app

# Create non-root user 'pki'
RUN useradd -m -u 1000 pki && \
    mkdir -p /app/data /app/database && \
    chown -R pki:pki /app

# Copy venv from builder
COPY --from=deps --chown=pki:pki /opt/venv /opt/venv

# Copy application code only (exclude tests, docs, config files)
COPY --chown=pki:pki ../backend/ /app/backend/
COPY --chown=pki:pki ../frontend/ /app/frontend/
COPY --chown=pki:pki ../scripts/ /app/scripts/
COPY --chown=pki:pki ../database/ /app/database/
COPY --chown=pki:pki ../start_webapp.sh /app/

# Set environment defaults
# Note: PKI_DATA_DIR and PKI_DB_PATH are explicitly set to match volume mount points
ENV PATH="/opt/venv/bin:$PATH" \
    PKI_HOST=0.0.0.0 \
    PKI_PORT=8000 \
    PKI_LOG_LEVEL=INFO \
    PKI_DATA_DIR=/app/data \
    PKI_DB_PATH=/app/database/pki.db

# Switch to non-root user
USER pki

# Expose port
EXPOSE 8000

# Health check: unauthenticated /healthz endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz').read()"

# Run application with single worker (SQLite constraint)
# Note: Persistent volumes required at:
#   /app/data       - certificate artifacts (encrypted)
#   /app/database   - SQLite database file
CMD ["uvicorn", "backend.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
