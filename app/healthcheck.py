"""Docker HEALTHCHECK: probe /healthz on whichever port serves the dashboard."""
import ssl
import sys
import urllib.request

from .config import Config

cfg = Config.from_env()
if cfg.tls_mode == "off":
    url, ctx = f"http://127.0.0.1:{cfg.http_port}/healthz", None
else:
    # Local loopback probe; the certificate is checked by browsers, not here.
    url, ctx = f"https://127.0.0.1:{cfg.https_port}/healthz", ssl._create_unverified_context()
try:
    urllib.request.urlopen(url, timeout=4, context=ctx).read()
except Exception as e:
    print(f"unhealthy: {e}", file=sys.stderr)
    sys.exit(1)
