# Debian 13 (trixie) based image. Rebuild regularly (docker compose build --pull)
# to pick up OS security patches, and scan with e.g. `trivy image netwatch`.
FROM python:3.13-slim-trixie

# Apply all available OS security updates; libcap2-bin provides setcap.
RUN apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends tzdata libcap2-bin \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/netwatch
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Run as an unprivileged user. Python gets only the NET_RAW file capability,
# which is all that ARP scanning needs. pip/libcap are removed afterwards so
# nothing else in the image can change capabilities.
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin netwatch \
 && mkdir -p /data && chown netwatch:netwatch /data \
 && setcap cap_net_raw+ep "$(readlink -f /usr/local/bin/python3)" \
 && apt-get purge -y --auto-remove libcap2-bin \
 && rm -rf /var/lib/apt/lists/*

ENV DB_PATH=/data/netwatch.db \
    PORT=8080 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/tmp
USER netwatch
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=60s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request,os; urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"PORT\"]}/healthz', timeout=4)"

CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT} --no-server-header --proxy-headers --forwarded-allow-ips=127.0.0.1"]
