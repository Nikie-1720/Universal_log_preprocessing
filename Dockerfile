# ULPF - Universal Log Pre-processing Framework

FROM python:3.12-slim

LABEL org.opencontainers.image.title="ULPF"
LABEL org.opencontainers.image.description="Universal Log Pre-processing Framework"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

# ---------------------------------------------------------
# Project metadata
# ---------------------------------------------------------

COPY pyproject.toml README.md LICENSE ./

# ---------------------------------------------------------
# Application source
# ---------------------------------------------------------

COPY ulpf ./ulpf
COPY correlation ./correlation
COPY storage ./storage
COPY configs ./configs
COPY plugins ./plugins
COPY samples ./samples
COPY web ./web
COPY agent ./agent
COPY installer ./installer
COPY scripts ./scripts


# ---------------------------------------------------------
# Install ULPF and runtime dependencies
# ---------------------------------------------------------

RUN pip install --no-cache-dir ".[postgres]" \
    && useradd --create-home --shell /bin/bash ulpf \
    && mkdir -p /data /etc/ulpf \
    && chown -R ulpf:ulpf /app /data /etc/ulpf

# ---------------------------------------------------------
# Run as non-root user
# ---------------------------------------------------------

USER ulpf

# ---------------------------------------------------------
# Environment
# ---------------------------------------------------------

ENV PYTHONUNBUFFERED=1 \
    ULPF_DATA_DIR=/data \
    ULPF_WEB_HOST=0.0.0.0 \
    ULPF_WEB_PORT=5173 \
    ULPF_CONFIG=/app/configs/pipeline.yaml

# ---------------------------------------------------------
# Persistent data
# ---------------------------------------------------------

VOLUME ["/data"]

# ---------------------------------------------------------
# Ports
# ---------------------------------------------------------

EXPOSE 5173/tcp
EXPOSE 5514/udp
EXPOSE 5514/tcp

# ---------------------------------------------------------
# Health check
# ---------------------------------------------------------

HEALTHCHECK --interval=30s \
    --timeout=10s \
    --start-period=10s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5173/api/ready', timeout=3)" || exit 1

# ---------------------------------------------------------
# Start ULPF
# ---------------------------------------------------------

CMD ["python", "-m", "ulpf.web"]