"""Container entry point: serves the dashboard over HTTPS (or HTTP if TLS=off)
and, when HTTPS is on, redirects plain-HTTP requests to the HTTPS address."""
import logging
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import uvicorn

from .config import Config
from . import tls

log = logging.getLogger("netwatch.serve")


def _redirect_server(http_port, https_port, allowed_hosts):
    class Redirect(BaseHTTPRequestHandler):
        server_version = "NetWatch"
        sys_version = ""

        def _go(self):
            if self.path == "/healthz":
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(b"ok")
                return
            host = urlsplit("//" + (self.headers.get("Host") or "")).hostname or ""
            if not host or (allowed_hosts and host.lower() not in allowed_hosts):
                self.send_error(400, "Invalid Host header")
                return
            if ":" in host:                     # IPv6 literal
                host = f"[{host}]"
            port = "" if https_port == 443 else f":{https_port}"
            path = self.path if self.path.startswith("/") else "/"
            self.send_response(308)
            self.send_header("Location", f"https://{host}{port}{path}")
            self.send_header("Content-Length", "0")
            self.end_headers()

        do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = _go

        def log_message(self, *args):
            pass

    srv = ThreadingHTTPServer(("0.0.0.0", http_port), Redirect)
    threading.Thread(target=srv.serve_forever, name="http-redirect", daemon=True).start()
    log.info("Redirecting http://:%d -> https://:%d", http_port, https_port)


def main():
    cfg = Config.from_env()
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    common = dict(host="0.0.0.0", server_header=False, proxy_headers=True,
                  forwarded_allow_ips="127.0.0.1", log_level=os.getenv("LOG_LEVEL", "info").lower())

    if cfg.tls_mode == "off":
        log.warning("TLS=off: the dashboard and its login are served over plain HTTP")
        uvicorn.run("app.main:app", port=cfg.http_port, **common)
        return

    if cfg.tls_mode == "custom":
        cert, key = cfg.tls_cert_file, cfg.tls_key_file
        if not (cert and key and os.path.exists(cert) and os.path.exists(key)):
            raise SystemExit("TLS=custom needs TLS_CERT_FILE and TLS_KEY_FILE pointing to readable files")
    else:
        cert, key = tls.ensure_self_signed(cfg.tls_dir, cfg.tls_hostnames)
    info = tls.describe(cert)
    log.info("HTTPS on port %d · certificate SHA-256 %s", cfg.https_port, info["sha256"])

    if cfg.http_port and cfg.http_port != cfg.https_port:
        _redirect_server(cfg.http_port, cfg.https_port, set(cfg.allowed_hosts))
    uvicorn.run("app.main:app", port=cfg.https_port, ssl_certfile=cert, ssl_keyfile=key, **common)


if __name__ == "__main__":
    main()
