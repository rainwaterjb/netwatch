"""HTTP security layer: optional login, cross-site request blocking, Host
header allow-list, and browser security headers."""
import base64
import binascii
import logging
import secrets
from urllib.parse import urlsplit

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import PlainTextResponse, Response

log = logging.getLogger("netwatch.security")

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
PUBLIC_PATHS = {"/healthz"}          # used by the container health check

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}
# The dashboard is a single self-contained page; /docs (Swagger UI) loads
# assets from a CDN, so it gets the default headers without this CSP.
PAGE_CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


def _host_only(value):
    """'example.lan:8080' -> 'example.lan', '[::1]:80' -> '::1'."""
    if not value:
        return ""
    return (urlsplit("//" + value).hostname or "").lower()


class SecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, cfg):
        super().__init__(app)
        self.cfg = cfg
        self.allowed_hosts = set(cfg.allowed_hosts)
        if not cfg.web_password:
            log.warning("WEB_PASSWORD is not set: the dashboard has no login. "
                        "Only expose it on a trusted network.")

    async def dispatch(self, request, call_next):
        path = request.url.path

        # 1. Host allow-list (protects against DNS-rebinding attacks).
        if self.allowed_hosts and path not in PUBLIC_PATHS:
            if _host_only(request.headers.get("host")) not in self.allowed_hosts:
                return PlainTextResponse("Invalid Host header", status_code=400)

        # 2. Block cross-site state-changing requests (CSRF). A malicious web
        #    page open in your browser can't toggle alerts or delete devices.
        if request.method not in SAFE_METHODS:
            site = request.headers.get("sec-fetch-site")
            origin = request.headers.get("origin")
            if site and site not in ("same-origin", "none"):
                return PlainTextResponse("Cross-site request blocked", status_code=403)
            if origin and urlsplit(origin).netloc.lower() != request.headers.get("host", "").lower():
                return PlainTextResponse("Cross-origin request blocked", status_code=403)

        # 3. Optional HTTP Basic login.
        if self.cfg.web_password and path not in PUBLIC_PATHS and not self._authorized(request):
            return Response("Login required", status_code=401,
                            headers={"WWW-Authenticate": 'Basic realm="NetWatch", charset="UTF-8"'})

        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if path == "/":
            response.headers["Content-Security-Policy"] = PAGE_CSP
            response.headers["Cache-Control"] = "no-store"
        if path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    def _authorized(self, request):
        header = request.headers.get("authorization", "")
        scheme, _, encoded = header.partition(" ")
        if scheme.lower() != "basic" or not encoded:
            return False
        try:
            user, _, password = base64.b64decode(encoded, validate=True).decode("utf-8").partition(":")
        except (binascii.Error, UnicodeDecodeError):
            return False
        # Constant-time comparisons (no timing side channel).
        ok_user = secrets.compare_digest(user.encode(), self.cfg.web_username.encode())
        ok_pass = secrets.compare_digest(password.encode(), self.cfg.web_password.encode())
        return ok_user and ok_pass
