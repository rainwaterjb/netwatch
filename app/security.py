"""HTTP security layer: optional login, cross-site request blocking, Host
header allow-list, and browser security headers."""
import logging
from urllib.parse import urlsplit

from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse

from .auth import OPEN, AuthError

log = logging.getLogger("netwatch.security")

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
# Health check, public certificate, and the sign-in page itself.
PUBLIC_PATHS = {"/healthz", "/netwatch.crt", "/login", "/api/auth/login", "/api/auth/options",
                "/api/auth/oidc/start", "/api/auth/oidc/callback",
                "/manifest.webmanifest", "/sw.js"}       # the app's manifest and service worker (no data in them)
PUBLIC_PREFIXES = ("/icons/",)
# Only the health check and certificate download skip the Host allow-list.
HOST_EXEMPT = {"/healthz", "/netwatch.crt"}
# Read-only accounts may still sign out and change their own password.
VIEWER_WRITE_PATHS = {"/api/auth/logout", "/api/auth/password"}
# Only admins may see these, even read-only.
ADMIN_ONLY_PREFIXES = ("/api/users", "/api/tokens", "/api/export/backup", "/api/alert-channels", "/api/alert-rules",
                       "/api/links")
# ...and acknowledge alerts.
VIEWER_WRITE_PREFIXES = ("/api/incidents/", "/api/push/")

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
    def __init__(self, app, cfg, auth):
        super().__init__(app)
        self.cfg = cfg
        self.auth = auth
        self.allowed_hosts = set(cfg.allowed_hosts)
        if not cfg.web_password and cfg.allow_no_login:
            log.warning("WEB_PASSWORD is not set and ALLOW_NO_LOGIN=true: the dashboard has no login. "
                        "Anyone who can reach it can change settings.")
        elif not cfg.web_password:
            log.warning("WEB_PASSWORD is not set: the dashboard is closed until you set it in .env "
                        "and restart. Monitoring and alerts keep running.")

    async def dispatch(self, request, call_next):
        path = request.url.path

        # 1. Host allow-list (protects against DNS-rebinding attacks).
        if self.allowed_hosts and path not in HOST_EXEMPT:
            if _host_only(request.headers.get("host")) not in self.allowed_hosts:
                return PlainTextResponse("Invalid Host header", status_code=400)

        # 2. Block cross-site state-changing requests (CSRF). A malicious web
        #    page open in your browser can't toggle alerts or delete devices.
        unsafe = request.method not in SAFE_METHODS
        if unsafe:
            site = request.headers.get("sec-fetch-site")
            origin = request.headers.get("origin")
            if site and site not in ("same-origin", "none"):
                return PlainTextResponse("Cross-site request blocked", status_code=403)
            if origin and urlsplit(origin).netloc.lower() != request.headers.get("host", "").lower():
                return PlainTextResponse("Cross-origin request blocked", status_code=403)

        # 3. Who is this? (API token, session cookie or Basic login.)
        if path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES):
            who = None
        else:
            ip = request.client.host if request.client else "?"
            try:
                who = await run_in_threadpool(self.auth.resolve, request.headers, request.cookies, ip)
            except AuthError as e:
                return self._denied(request, path, str(e), e.status)
            if who is None:
                if self.auth.login_required:
                    return self._denied(request, path, "Sign in required", 401)
                if not self.cfg.allow_no_login:
                    return self._setup_needed(path)
                who = OPEN
            # Cookies are sent automatically by the browser, so state changes made
            # with a session must also carry NetWatch's own header, which other
            # sites can't add without a CORS preflight that we never allow.
            if unsafe and who["kind"] == "session" and request.headers.get("x-netwatch") != "1":
                return PlainTextResponse("Missing X-NetWatch header", status_code=403)
            # Read-only accounts and tokens can look but not change anything.
            if who["role"] != "admin" and (unsafe and path not in VIEWER_WRITE_PATHS
                                           and not path.startswith(VIEWER_WRITE_PREFIXES)
                                           or path.startswith(ADMIN_ONLY_PREFIXES)):
                return JSONResponse({"detail": "Your account is read-only"}, status_code=403)
            # Accounts and tokens are managed by a person who signed in, never by a token.
            if path.startswith(("/api/users", "/api/tokens")) and who["kind"] == "token":
                return JSONResponse({"detail": "API tokens can't manage accounts or tokens"}, status_code=403)
        request.state.principal = who

        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        # HSTS only with a certificate browsers already trust; with a self-signed
        # certificate it would stop users from clicking through the warning.
        if self.cfg.tls_mode == "custom" and request.url.scheme == "https":
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        if path in ("/", "/login"):
            response.headers["Content-Security-Policy"] = PAGE_CSP
            response.headers["Cache-Control"] = "no-store"
        if path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @staticmethod
    def _setup_needed(path):
        """No password and no accounts: keep the dashboard closed instead of open to the whole network."""
        msg = ("NetWatch has no sign-in set up. Set WEB_PASSWORD in .env and restart "
               "(docker compose up -d). Monitoring and alerts keep running meanwhile.")
        if path.startswith("/api/") or path == "/metrics":
            return JSONResponse({"detail": msg}, status_code=503)
        return HTMLResponse(SETUP_PAGE, status_code=503, headers={"Content-Security-Policy": PAGE_CSP,
                                                                  "Cache-Control": "no-store"})

    def _denied(self, request, path, message, status):
        if path == "/" and request.method == "GET" and status == 401:
            return RedirectResponse("/login", status_code=303)
        if status == 429:
            return JSONResponse({"detail": message}, status_code=429)
        headers = {}
        # Tools like curl and Homepage get a Basic login challenge; the dashboard's
        # own requests (X-NetWatch) don't, so the browser never pops up a dialog.
        if status == 401 and request.headers.get("x-netwatch") != "1":
            headers["WWW-Authenticate"] = 'Basic realm="NetWatch", charset="UTF-8"'
        return JSONResponse({"detail": message}, status_code=status, headers=headers)


SETUP_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>NetWatch: set a password</title>
<style>body{font:16px/1.5 system-ui,sans-serif;background:#0d1117;color:#e6edf3;display:grid;place-items:center;
min-height:100vh;margin:0}main{max-width:34rem;padding:2rem}code{background:#161b22;padding:.1rem .35rem;border-radius:4px}
pre{background:#161b22;padding:1rem;border-radius:8px;overflow:auto}</style></head><body><main>
<h1>Set a password first</h1>
<p>NetWatch won't show the dashboard to your whole network without a sign-in.
Monitoring and alerts are already running.</p>
<p>In the NetWatch folder, set <code>WEB_PASSWORD</code> in <code>.env</code> and restart:</p>
<pre>openssl rand -base64 24
nano .env
docker compose up -d</pre>
<p>Then reload this page and sign in as <code>WEB_USERNAME</code> (default <code>admin</code>).</p>
</main></body></html>"""
