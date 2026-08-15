# =============================================================================
# CRA-AGENT Dockerfile
# =============================================================================
# Multi-stage build for the CRA compliance agent
#
# Build: docker build -t cra-agent .
# Run agent: docker run -it cra-agent python -m src.main
# Run dashboard: docker run -it -p 8501:8501 cra-agent streamlit run src/dashboard/app.py
# Run webhook: docker run -it -p 8080:8080 cra-agent uvicorn src.webhook.server:app --host 0.0.0.0 --port 8080

# -----------------------------------------------------------------------------
# Base stage
# -----------------------------------------------------------------------------
FROM python:3.11-slim as base

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# -----------------------------------------------------------------------------
# Dependencies stage
# -----------------------------------------------------------------------------
FROM base as dependencies

# Copy dependency files
COPY pyproject.toml README.md ./

# Install Python dependencies
RUN pip install --no-cache-dir -e ".[dev]"

# -----------------------------------------------------------------------------
# Development stage
# -----------------------------------------------------------------------------
FROM dependencies as development

# Copy source code
COPY . .

# Create data directory
RUN mkdir -p /app/data

# Expose ports
# 8080 - Webhook server
# 8501 - Streamlit dashboard
EXPOSE 8080 8501

# Default command (can be overridden)
CMD ["python", "-m", "src.main"]

# -----------------------------------------------------------------------------
# Production stage (optional, for optimized builds)
# -----------------------------------------------------------------------------
FROM base as production

# Copy only necessary files from dependencies stage
COPY --from=dependencies /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=dependencies /usr/local/bin /usr/local/bin

# Copy application code
COPY src/ ./src/
COPY config/ ./config/
COPY pyproject.toml ./

# Create data directory
RUN mkdir -p /app/data

# Create non-root user
RUN useradd -m -r appuser && chown -R appuser:appuser /app
USER appuser

# Expose ports
EXPOSE 8080 8501

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Default command
CMD ["python", "-m", "src.main"]