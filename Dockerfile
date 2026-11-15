# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# secaudit — Security Headers & DNS Misconfiguration Auditor
#
#   docker build -t secaudit .
#   docker run --rm secaudit -d example.com
#   docker run --rm -v "$PWD/reports:/reports" secaudit \
#       -d example.com --fail-under 85 -oH /reports/audit.html -oS /reports/audit.sarif
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build
# Build wheels first so the runtime image does not need a compiler toolchain.
COPY requirements.txt ./
RUN pip wheel --wheel-dir /wheels -r requirements.txt

COPY pyproject.toml README.md main.py ./
COPY core ./core
COPY auditors ./auditors
COPY reporters ./reporters
COPY data ./data
COPY config ./config
RUN pip wheel --wheel-dir /wheels --no-deps .

# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# CA bundle is mandatory: certificate validation is a core feature.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /usr/sbin/nologin --uid 10001 auditor \
    && mkdir -p /work /reports \
    && chown -R auditor:auditor /work /reports

COPY --from=builder /wheels /wheels
RUN pip install --no-index --find-links=/wheels secaudit \
    && rm -rf /wheels

WORKDIR /work
USER auditor

ENTRYPOINT ["secaudit"]
CMD ["--help"]

LABEL org.opencontainers.image.title="secaudit" \
      org.opencontainers.image.description="Security Headers, TLS and DNS/E-mail misconfiguration auditor" \
      org.opencontainers.image.source="https://github.com/laithfarhat-cell/Security-Headers-DNS-Misconfiguration-Auditor" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="1.0.0"
