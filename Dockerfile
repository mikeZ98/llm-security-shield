# syntax=docker/dockerfile:1.7
#
# llm-security-shield: hardened multi-stage image.
#   builder: uv resolves the frozen lockfile into /app/.venv (no dev deps, project as wheel).
#   runtime: python:3.13-slim with the venv copied in, no pip/uv/compilers, non-root,
#            read-only-rootfs compatible, offline at runtime (spaCy model baked in).
# For reproducible releases, pin both FROM images by digest (@sha256:...).

ARG PYTHON_VERSION=3.13
ARG UV_VERSION=0.11.7

FROM ghcr.io/astral-sh/uv:${UV_VERSION} AS uv

# ---------------------------------------------------------------------------
# Build stage
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim AS builder

COPY --from=uv /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PYTHON=/usr/local/bin/python3 \
    UV_PROJECT_ENVIRONMENT=/app/.venv

WORKDIR /app

# Dependencies first (cached unless the lockfile changes). The en_core_web_sm wheel is
# a URL source pinned by sha256 in uv.lock, so it is fetched once here and verified.
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

# Then the project itself, installed as a regular (non-editable) package so the
# runtime image needs no source tree.
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable

# Fail the build, not the first request, if the offline model is missing.
RUN /app/.venv/bin/python -c "import spacy, sys; sys.exit(0 if spacy.util.is_package('en_core_web_sm') else 1)"

# ---------------------------------------------------------------------------
# Runtime stage
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim AS runtime

ARG VERSION=0.1.0
LABEL org.opencontainers.image.title="llm-security-shield" \
      org.opencontainers.image.description="OWASP LLM Top 10 security middleware for FastAPI/Starlette" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="MIT"

# Shrink the attack surface: no package installers in the final image.
RUN set -eux; \
    rm -rf /usr/local/bin/pip* \
           /usr/local/lib/python3*/site-packages/pip \
           /usr/local/lib/python3*/site-packages/pip-*.dist-info \
           /usr/local/lib/python3*/ensurepip; \
    groupadd --system --gid 10001 appuser; \
    useradd --system --uid 10001 --gid 10001 --no-create-home \
            --home-dir /nonexistent --shell /usr/sbin/nologin appuser; \
    mkdir -p /app/.cache; \
    chown 10001:10001 /app/.cache

# Owned by root and read-only to appuser: the application cannot modify itself.
COPY --from=builder /app/.venv /app/.venv

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    HOME=/tmp \
    XDG_CACHE_HOME=/app/.cache

WORKDIR /app
USER 10001:10001
EXPOSE 8000

# Probe with the stdlib only (no curl/wget in the image). Any non-200, including the
# 503 a degraded shield returns, marks the container unhealthy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/v1/shield/health', timeout=4).status == 200 else 1)"]

# Access logs are off: request lines include query strings, which may carry prompts
# or PII. Workers can be raised with WEB_CONCURRENCY (each loads its own spaCy model).
ENTRYPOINT ["python", "-m", "uvicorn"]
CMD ["llm_security_shield.api:create_app", "--factory", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--no-access-log", "--no-server-header", "--timeout-graceful-shutdown", "10"]
