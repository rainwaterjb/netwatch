"""Single sign-on with OpenID Connect (Authentik, Keycloak, Authelia, Google, ...).

Flow: authorization code with PKCE. NetWatch sends you to the provider with a
one-time `state` (tied to your browser by a short-lived cookie) and `nonce`,
then swaps the returned code for an ID token over a direct server-to-server
call. The ID token's signature (from the provider's published keys), issuer,
audience, expiry and nonce are all checked before anyone is signed in.

Roles come from the provider's groups on every sign-in:
OIDC_ADMIN_GROUPS -> admin, OIDC_VIEWER_GROUPS -> viewer, anyone else gets
OIDC_DEFAULT_ROLE (default "none": not allowed in).

SSO accounts are stored in the users table with an unusable password, so an
older NetWatch version (or the password form) can never sign them in.
"""
import base64
import hashlib
import json
import logging
import re
import secrets
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import jwt

from .auth import USERNAME_RE, AuthError, principal

log = logging.getLogger("netwatch.sso")

FLOW_TTL = 600                 # seconds to finish signing in at the provider
ALLOWED_ALGS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"]
SSO_PASSWORD = "!sso"          # never matches a password: verify_password() rejects it
FLOW_COOKIE = "netwatch_sso"


class SSOError(AuthError):
    """`code` is a short fixed word shown on the sign-in page (never provider text)."""
    def __init__(self, code, detail=""):
        super().__init__(detail or code, 400)
        self.code = code


def _b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class OIDC:
    def __init__(self, cfg, store, auth):
        self.cfg = cfg
        self.store = store
        self.auth = auth
        self.lock = threading.Lock()
        self._flows = {}                 # state -> flow details
        self._meta = None                # (fetched_at, discovery document)
        self._jwks = None                # (fetched_at, {kid: key})
        ctx = ssl.create_default_context()
        if cfg.oidc_ca_file:
            try:
                ctx.load_verify_locations(cafile=cfg.oidc_ca_file)
            except (OSError, ssl.SSLError) as e:
                log.error("OIDC_CA_FILE %s can't be loaded: %s", cfg.oidc_ca_file, e)
        if not cfg.oidc_verify_tls:
            log.warning("OIDC_VERIFY_TLS=false: the sign-in provider's certificate isn't checked")
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self._opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))

    @property
    def enabled(self):
        return bool(self.cfg.oidc_issuer and self.cfg.oidc_client_id and self.auth.accounts_enabled)

    def problems(self):
        """Settings that stop SSO from working, for the logs and the Access tab."""
        out = []
        if self.cfg.oidc_issuer and not self.cfg.oidc_client_id:
            out.append("OIDC_CLIENT_ID is not set")
        if self.cfg.oidc_issuer and not self.auth.accounts_enabled:
            out.append("WEB_PASSWORD must be set to use single sign-on")
        if self.cfg.oidc_issuer and not (self.cfg.oidc_admin_groups or self.cfg.oidc_viewer_groups
                                         or self.cfg.oidc_default_role == "viewer"):
            out.append("No one can sign in: set OIDC_ADMIN_GROUPS and/or OIDC_VIEWER_GROUPS")
        if self.cfg.oidc_issuer and not self.cfg.oidc_issuer.startswith("https://"):
            out.append("OIDC_ISSUER should be an https:// address")
        return out

    # ---------- provider metadata ----------
    def _get_json(self, url, data=None, headers=None):
        req = urllib.request.Request(url, data=data, headers={"Accept": "application/json", **(headers or {})})
        try:
            with self._opener.open(req, timeout=10) as r:
                body = r.read(1_000_000)
                return json.loads(body.decode())
        except urllib.error.HTTPError as e:
            raise SSOError("provider", f"{urllib.parse.urlsplit(url).netloc} answered HTTP {e.code}") from None
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise SSOError("provider", f"can't reach {urllib.parse.urlsplit(url).netloc}: {e.__class__.__name__}") from None

    def metadata(self):
        if self._meta and time.time() - self._meta[0] < 3600:
            return self._meta[1]
        meta = self._get_json(self.cfg.oidc_issuer + "/.well-known/openid-configuration")
        if (meta.get("issuer") or "").rstrip("/") != self.cfg.oidc_issuer:
            raise SSOError("provider", "The provider's issuer doesn't match OIDC_ISSUER")
        for k in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            if not str(meta.get(k, "")).startswith(("https://", "http://")):
                raise SSOError("provider", f"The provider's {k} is missing")
        self._meta = (time.time(), meta)
        return meta

    def _keys(self, force=False):
        if not force and self._jwks and time.time() - self._jwks[0] < 3600:
            return self._jwks[1]
        doc = self._get_json(self.metadata()["jwks_uri"])
        keys = {}
        for k in doc.get("keys", []):
            if k.get("use", "sig") != "sig":
                continue
            try:
                keys[k.get("kid")] = jwt.PyJWK(k)
            except Exception:                     # unsupported key types are skipped
                continue
        self._jwks = (time.time(), keys)
        return keys

    # ---------- the flow ----------
    def redirect_uri(self, request_base):
        return self.cfg.oidc_redirect_url or request_base.rstrip("/") + "/api/auth/oidc/callback"

    def start(self, request_base, ip):
        """Return (provider URL to send the browser to, browser-binding cookie value)."""
        meta = self.metadata()
        state, nonce, verifier, binding = (secrets.token_urlsafe(32) for _ in range(4))
        now = time.time()
        with self.lock:
            for s in [s for s, f in self._flows.items() if now - f["created"] > FLOW_TTL]:
                del self._flows[s]
            if len(self._flows) >= 500 or sum(1 for f in self._flows.values() if f["ip"] == ip) >= 10:
                raise SSOError("busy", "Too many sign-ins in progress; try again shortly")
            self._flows[state] = {"nonce": nonce, "verifier": verifier, "binding": hashlib.sha256(binding.encode()).hexdigest(),
                                  "created": now, "redirect_uri": self.redirect_uri(request_base), "ip": ip}
        params = {
            "response_type": "code", "client_id": self.cfg.oidc_client_id,
            "redirect_uri": self.redirect_uri(request_base), "scope": self.cfg.oidc_scopes,
            "state": state, "nonce": nonce,
            "code_challenge": _b64url(hashlib.sha256(verifier.encode()).digest()), "code_challenge_method": "S256",
        }
        sep = "&" if "?" in meta["authorization_endpoint"] else "?"
        return meta["authorization_endpoint"] + sep + urllib.parse.urlencode(params), binding

    def finish(self, state, code, binding, ip):
        """Validate the provider's answer and return a principal for the signed-in user."""
        with self.lock:
            flow = self._flows.pop(state or "", None)       # one use only
        if not flow or time.time() - flow["created"] > FLOW_TTL:
            raise SSOError("expired", "Sign-in link expired or already used")
        if not binding or not secrets.compare_digest(hashlib.sha256(binding.encode()).hexdigest(), flow["binding"]):
            raise SSOError("browser", "Sign-in was started in a different browser")
        if not code or len(code) > 2048:
            raise SSOError("denied", "The provider didn't return a sign-in code")
        meta = self.metadata()
        form = {"grant_type": "authorization_code", "code": code, "redirect_uri": flow["redirect_uri"],
                "code_verifier": flow["verifier"], "client_id": self.cfg.oidc_client_id}
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if self.cfg.oidc_client_secret:
            basic = f"{urllib.parse.quote(self.cfg.oidc_client_id, safe='')}:{urllib.parse.quote(self.cfg.oidc_client_secret, safe='')}"
            headers["Authorization"] = "Basic " + base64.b64encode(basic.encode()).decode()
        tokens = self._get_json(meta["token_endpoint"], urllib.parse.urlencode(form).encode(), headers)
        claims = self.validate_id_token(tokens.get("id_token"), flow["nonce"])
        return self._sign_in(claims, ip)

    def validate_id_token(self, id_token, nonce):
        if not isinstance(id_token, str) or len(id_token) > 20000:
            raise SSOError("token", "No ID token from the provider")
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError:
            raise SSOError("token", "Malformed ID token") from None
        if header.get("alg") not in ALLOWED_ALGS:
            raise SSOError("token", f"Unsupported ID token algorithm {str(header.get('alg'))[:10]}")
        keys = self._keys()
        key = keys.get(header.get("kid"))
        if key is None:
            keys = self._keys(force=True)                    # the provider may have rotated keys
            key = keys.get(header.get("kid")) or (next(iter(keys.values())) if len(keys) == 1 and not header.get("kid") else None)
        if key is None:
            raise SSOError("token", "ID token signed with an unknown key")
        try:
            claims = jwt.decode(id_token, key=key, algorithms=[header["alg"]], audience=self.cfg.oidc_client_id,
                                issuer=self.metadata()["issuer"], leeway=60,
                                options={"require": ["iss", "aud", "exp", "iat", "sub"]})
        except jwt.PyJWTError as e:
            raise SSOError("token", f"ID token rejected: {e.__class__.__name__}") from None
        aud = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
        if len(aud) > 1 and claims.get("azp") != self.cfg.oidc_client_id:
            raise SSOError("token", "ID token was issued to another application")
        if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
            raise SSOError("token", "ID token nonce doesn't match")
        return claims

    # ---------- mapping to a NetWatch account ----------
    def role_for(self, claims):
        groups = claims.get(self.cfg.oidc_groups_claim) or []
        if isinstance(groups, str):
            groups = [groups]
        groups = {str(g) for g in groups}
        if groups & set(self.cfg.oidc_admin_groups):
            return "admin"
        if groups & set(self.cfg.oidc_viewer_groups):
            return "viewer"
        return "viewer" if self.cfg.oidc_default_role == "viewer" else None

    def _pick_username(self, claims, user_id=None):
        base = str(claims.get("preferred_username") or claims.get("email", "").split("@")[0] or "sso-user")
        base = re.sub(r"[^A-Za-z0-9._-]", "-", base).strip(".-_")[:24] or "sso-user"
        if not base[0].isalnum():
            base = "u" + base
        if len(base) < 2:
            base += "-sso"
        candidates = [base] + [f"{base}-sso"] + [f"{base}-sso{i}" for i in range(2, 50)]
        for name in candidates:
            if not USERNAME_RE.match(name) or name.lower() == self.cfg.web_username.lower():
                continue
            rows = self.store._query("SELECT id FROM users WHERE username = ? COLLATE NOCASE", (name,))
            if not rows or rows[0]["id"] == user_id:
                return name
        raise SSOError("account", "Couldn't find a free username")

    def _sign_in(self, claims, ip):
        issuer, subject = self.metadata()["issuer"], str(claims["sub"])[:255]
        role = self.role_for(claims)
        rows = self.store._query("SELECT * FROM users WHERE sso_issuer = ? AND sso_subject = ?", (issuer, subject))
        user = rows[0] if rows else None
        name = str(claims.get("preferred_username") or claims.get("email") or subject)[:64]
        if role is None:
            if user:                                      # removed from the groups: lock them out now
                self.store._exec("UPDATE users SET role = 'viewer' WHERE id = ?", (user["id"],))
                self.store._exec("UPDATE api_tokens SET revoked = 1 WHERE created_by = ?", (user["id"],))
                self.auth.end_user_sessions(user["id"])
                self.auth._changed()
            self.store.add_event("auth", None, ip, f"SSO sign-in refused for '{name}': not in an allowed group")
            raise SSOError("group", "Your account isn't in a group that's allowed to use NetWatch")
        if user and user["disabled"]:
            self.store.add_event("auth", None, ip, f"SSO sign-in refused for '{user['username']}': account disabled")
            raise SSOError("disabled", "This account is disabled in NetWatch")
        now = time.time()
        if user:
            if user["role"] != role:
                self.store.add_event("auth", None, ip, f"SSO role for '{user['username']}' changed to {role} (groups)")
            self.store._exec("UPDATE users SET role = ? WHERE id = ?", (role, user["id"]))
            uid = user["id"]
        else:
            username = self._pick_username(claims)
            with self.store.lock:
                cur = self.store.conn.execute(
                    "INSERT INTO users (username, password_hash, role, created, disabled, sso_issuer, sso_subject) "
                    "VALUES (?, ?, ?, ?, 0, ?, ?)", (username, SSO_PASSWORD, role, now, issuer, subject))
                self.store.conn.commit()
                uid = cur.lastrowid
            self.store.add_event("auth", None, ip, f"SSO account '{username}' created ({role})")
        self.auth._changed()
        user = self.auth.get_user(uid)
        return principal("user", user["username"], user["role"], user_id=uid)
