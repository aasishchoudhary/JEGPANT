FROM python:3.13-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends ffmpeg ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 jegpant \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin jegpant \
    && mkdir -p /app /data \
    && chown -R 10001:10001 /app /data

WORKDIR /app

COPY --chown=10001:10001 pyproject.toml README.md ./
COPY --chown=10001:10001 src ./src

RUN python -m pip install --upgrade pip \
    && python -m pip install ".[server]"

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=3).read()"

CMD ["uvicorn", "jegpant.server:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--proxy-headers"]
