FROM python:3.11.16-slim-trixie@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=10000

WORKDIR /app

# Refresh Debian packages from the pinned base distribution before installing fonts.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

RUN addgroup --system threatlens && adduser --system --ingroup threatlens threatlens

COPY requirements.txt ./
RUN python -m pip install --upgrade pip==26.2.1 setuptools==84.0.0 wheel==0.48.0 \
    && python -m pip install -r requirements.txt

COPY . .
RUN chown -R threatlens:threatlens /app

# THREATLENS_BATCH7F_TARGETED_PYTHON_PATCH_BEGIN
# Generated from exact V2 Trivy fixable Python-package findings.
RUN python -m pip install --no-cache-dir --upgrade --upgrade-strategy only-if-needed "msgpack==1.2.2" "setuptools==84.0.0" "urllib3==2.8.0"
# THREATLENS_BATCH7F_TARGETED_PYTHON_PATCH_END

USER threatlens

EXPOSE 10000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:' + __import__('os').environ.get('PORT','10000') + '/api/v1/health/live', timeout=3)" || exit 1


CMD ["sh", "scripts/start_production.sh"]
