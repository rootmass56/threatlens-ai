FROM python:3.11.16-slim-bookworm@sha256:528257d48c1da0dcecc2e725d1ae34498d60c965f1241e39cd6a85a8859bdf84

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=10000

WORKDIR /app

# THREATLENS_H4_PCRE2_SECURITY_PATCH_BEGIN
# Remediate CVE-2026-86145 and CVE-2026-89161 in Debian libpcre2-8-0.
# The pinned base image contains 10.42-1; Debian bookworm-security publishes
# 10.42-1+deb12u1 or newer. Keep this targeted and remove APT metadata afterward.
RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade libpcre2-8-0 \
    && rm -rf /var/lib/apt/lists/*
# THREATLENS_H4_PCRE2_SECURITY_PATCH_END

RUN addgroup --system threatlens && adduser --system --ingroup threatlens threatlens

COPY requirements.txt ./
RUN python -m pip install --upgrade pip==26.2.1 setuptools==84.0.0 wheel==0.47.0 \
    && python -m pip install -r requirements.txt

COPY . .
RUN chown -R threatlens:threatlens /app

# THREATLENS_BATCH7F_TARGETED_PYTHON_PATCH_BEGIN
# Generated from exact V2 Trivy fixable Python-package findings.
RUN python -m pip install --no-cache-dir --upgrade --upgrade-strategy only-if-needed "msgpack==1.2.1" "setuptools==84.0.0"
# THREATLENS_BATCH7F_TARGETED_PYTHON_PATCH_END

USER threatlens

EXPOSE 10000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:' + __import__('os').environ.get('PORT','10000') + '/api/v1/health/live', timeout=3)" || exit 1


CMD ["sh", "scripts/start_production.sh"]
