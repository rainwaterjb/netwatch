"""User accounts, login sessions and API tokens.

Who can sign in:
- The built-in admin from WEB_USERNAME / WEB_PASSWORD (.env). It always works,
  so you can't lock yourself out, and it's what older NetWatch versions use.
- Accounts created in the dashboard (admin or read-only "viewer"). Creating
  them requires WEB_PASSWORD to be set, so rolling back to a version without
  accounts never leaves the dashboard open.
- API tokens (admin or viewer) for tools like Homepage: "Authorization: Bearer nw_...".

Passwords are hashed with scrypt. Session IDs and tokens are random 256-bit
values stored only as SHA-256 hashes, so a copy of the database can't be used
to sign in. Changing a password (or the built-in one in .env) ends that
account's sessions.
"""
import base64
import binascii
import hashlib
import hmac
import logging
import re
import secrets
import threading
import time
from collections import defaultdict, deque

log = logging.getLogger("netwatch.auth")

ROLES = ("admin", "viewer")
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,31}$")
TOKEN_NAME_RE = re.compile(r"^[\w][\w .:@()/-]{0,39}$")
MIN_PASSWORD, MAX_PASSWORD = 10, 256
SESSION_IDLE = 7 * 86400          # sign out after a week without use
SESSION_MAX = 30 * 86400          # and after 30 days at most
FAIL_WINDOW = 15 * 60
MAX_FAILS_PER_IP = 10
MAX_FAILS_PER_USER = 5
SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1}
TOKEN_PREFIX = "nw_"
BUILTIN_ID = 0


class AuthError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


class Locked(AuthError):
    def __init__(self, seconds):
        super().__init__(f"Too many failed sign-ins. Try again in {max(1, seconds // 60 + 1)} minutes.", 429)
        self.seconds = seconds


def _sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def hash_password(password):
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, dklen=32, **SCRYPT)
    return "scrypt${n}${r}${p}${salt}${dk}".format(
        **SCRYPT, salt=base64.b64encode(salt).decode(), dk=base64.b64encode(dk).decode())


def verify_password(password, stored):
    try:
        algo, n, r, p, salt, dk = stored.split("$")
        if algo != "scrypt":
            return False
        expected = base64.b64decode(dk)
        got = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), dklen=len(expected),
                             n=int(n), r=int(r), p=int(p))
        return hmac.compare_digest(got, expected)
    except (ValueError, binascii.Error):
        return False


def principal(kind, username, role, user_id=None, token_id=None, session_hash=None):
    return {"kind": kind, "username": username, "role": role, "user_id": user_id,
            "token_id": token_id, "session_hash": session_hash}


OPEN = principal("open", None, "admin")


class AuthManager:
    def __init__(self, store, cfg):
        self.store = store
        self.cfg = cfg
        self.lock = threading.Lock()
        self._fails = defaultdict(deque)          # "ip:x" / "user:x" -> failure times
        self._basic_cache = {}                    # sha(header) -> (principal, cred_tag, expires)
        self._dummy = hash_password(secrets.token_hex(8))   # equalises timing for unknown users
        self._active_users = None

    # ---------- state ----------
    @property
    def accounts_enabled(self):
        """Accounts can be created only while the built-in admin password is set."""
        return bool(self.cfg.web_password)

    @property
    def login_required(self):
        return bool(self.cfg.web_password) or self.active_user_count() > 0

    def active_user_count(self):
        if self._active_users is None:
            self._active_users = self.store._query(
                "SELECT COUNT(*) AS n FROM users WHERE disabled = 0")[0]["n"]
        return self._active_users

    def _changed(self):
        self._active_users = None
        self._basic_cache.clear()

    def _builtin_tag(self):
        return _sha(f"{self.cfg.web_username}\0{self.cfg.web_password}")[:16]

    @staticmethod
    def _user_tag(user):
        return _sha(user["password_hash"])[:16]

    # ---------- rate limiting ----------
    def _check_locked(self, ip, username):
        now = time.time()
        with self.lock:
            worst = 0
            for key, limit in ((f"ip:{ip}", MAX_FAILS_PER_IP), (f"user:{(username or '').lower()}", MAX_FAILS_PER_USER)):
                q = self._fails[key]
                while q and now - q[0] > FAIL_WINDOW:
                    q.popleft()
                if len(q) >= limit:
                    worst = max(worst, int(FAIL_WINDOW - (now - q[0])))
            if worst:
                raise Locked(worst)

    def _record_fail(self, ip, username, how):
        now = time.time()
        with self.lock:
            self._fails[f"ip:{ip}"].append(now)
            if username:
                self._fails[f"user:{username.lower()}"].append(now)
            if len(self._fails) > 5000:           # don't let random usernames grow memory forever
                for k in [k for k, q in self._fails.items() if not q or now - q[-1] > FAIL_WINDOW]:
                    del self._fails[k]
        self.store.add_event("auth", None, ip, f"Failed sign-in ({how}) for '{(username or '')[:32]}'")

    def _clear_fails(self, username):
        with self.lock:
            self._fails.pop(f"user:{(username or '').lower()}", None)

    # ---------- checking credentials ----------
    def check_password(self, username, password, ip, how="form"):
        """Return a principal for a correct username/password, else raise AuthError."""
        username = (username or "")[:64]
        password = (password or "")[:MAX_PASSWORD]
        self._check_locked(ip, username)
        if self.cfg.web_password and hmac.compare_digest(username.encode(), self.cfg.web_username.encode()):
            if hmac.compare_digest(password.encode(), self.cfg.web_password.encode()):
                self._clear_fails(username)
                return principal("builtin", self.cfg.web_username, "admin", user_id=BUILTIN_ID)
            self._record_fail(ip, username, how)
            raise AuthError("Wrong username or password", 401)
        rows = self.store._query("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,))
        user = rows[0] if rows else None
        ok = verify_password(password, user["password_hash"] if user else self._dummy)
        if user and ok and not user["disabled"]:
            self._clear_fails(username)
            return principal("user", user["username"], user["role"], user_id=user["id"])
        self._record_fail(ip, username, how)
        raise AuthError("Wrong username or password", 401)

    def resolve(self, headers, cookies, ip):
        """Work out who is making a request. Returns a principal, or None if anonymous.

        Raises AuthError for credentials that were sent but are wrong or locked out.
        """
        header = headers.get("authorization", "")
        scheme, _, value = header.partition(" ")
        scheme = scheme.lower()
        if scheme == "bearer" and value:
            p = self.resolve_token(value.strip())
            if not p:
                self._record_fail(ip, None, "API token")
                raise AuthError("Invalid or expired API token", 401)
            return p
        if scheme == "basic" and value:
            return self._resolve_basic(header, value, ip)
        raw = cookies.get(self.cookie_name(True)) or cookies.get(self.cookie_name(False))
        if raw:
            return self.resolve_session(raw)
        return None

    def _resolve_basic(self, header, value, ip):
        key = _sha(header)
        hit = self._basic_cache.get(key)
        if hit and hit[2] > time.time():
            return hit[0]
        try:
            username, _, password = base64.b64decode(value, validate=True).decode("utf-8").partition(":")
        except (binascii.Error, UnicodeDecodeError):
            raise AuthError("Malformed login", 401)
        p = self.check_password(username, password, ip, how="basic")
        self._basic_cache[key] = (p, None, time.time() + 300)
        if len(self._basic_cache) > 200:
            self._basic_cache.pop(next(iter(self._basic_cache)))
        return p

    # ---------- sessions ----------
    @staticmethod
    def cookie_name(https):
        return "__Host-netwatch" if https else "netwatch_session"

    def create_session(self, p, ip, user_agent):
        raw = secrets.token_urlsafe(32)
        now = time.time()
        if p["kind"] == "builtin":
            tag = self._builtin_tag()
        else:
            tag = self._user_tag(self.get_user(p["user_id"]))
            self.store._exec("UPDATE users SET last_login = ? WHERE id = ?", (now, p["user_id"]))
        self.store._exec(
            "INSERT INTO sessions (id_hash, user_id, cred_tag, created, last_seen, expires, ip, user_agent) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (_sha(raw), p["user_id"], tag, now, now, now + SESSION_IDLE, ip, (user_agent or "")[:200]))
        self.store._exec("DELETE FROM sessions WHERE expires < ? OR created < ?", (now, now - SESSION_MAX))
        self.store.add_event("auth", None, ip, f"Signed in: {p['username']}")
        return raw

    def resolve_session(self, raw):
        h = _sha(raw)
        rows = self.store._query("SELECT * FROM sessions WHERE id_hash = ?", (h,))
        if not rows:
            return None
        s, now = rows[0], time.time()
        if s["expires"] < now or s["created"] < now - SESSION_MAX:
            self.store._exec("DELETE FROM sessions WHERE id_hash = ?", (h,))
            return None
        if s["user_id"] == BUILTIN_ID:
            if not self.cfg.web_password or s["cred_tag"] != self._builtin_tag():
                return None
            p = principal("session", self.cfg.web_username, "admin", user_id=BUILTIN_ID, session_hash=h)
        else:
            user = self.get_user(s["user_id"])
            if not user or user["disabled"] or s["cred_tag"] != self._user_tag(user):
                return None
            p = principal("session", user["username"], user["role"], user_id=user["id"], session_hash=h)
        if now - s["last_seen"] > 60:
            self.store._exec("UPDATE sessions SET last_seen = ?, expires = ? WHERE id_hash = ?",
                             (now, now + SESSION_IDLE, h))
        return p

    def end_session(self, session_hash):
        self.store._exec("DELETE FROM sessions WHERE id_hash = ?", (session_hash,))

    def end_user_sessions(self, user_id):
        self.store._exec("DELETE FROM sessions WHERE user_id = ?", (user_id,))

    # ---------- users ----------
    def get_user(self, user_id):
        rows = self.store._query("SELECT * FROM users WHERE id = ?", (user_id,))
        return rows[0] if rows else None

    @staticmethod
    def public_user(u):
        out = {k: u[k] for k in ("id", "username", "role", "created", "last_login", "disabled")}
        out["sso"] = bool(u.get("sso_subject"))
        return out

    def list_users(self):
        return [self.public_user(u) for u in self.store._query("SELECT * FROM users ORDER BY username COLLATE NOCASE")]

    def _validate_password(self, password, username=None):
        if not isinstance(password, str) or not (MIN_PASSWORD <= len(password) <= MAX_PASSWORD):
            raise AuthError(f"Passwords must be {MIN_PASSWORD} to {MAX_PASSWORD} characters")
        if username and password.lower() == username.lower():
            raise AuthError("The password can't be the same as the username")
        if password == self.cfg.web_password:
            raise AuthError("Use a different password from the built-in admin's")

    def create_user(self, username, password, role, by):
        if not self.accounts_enabled:
            raise AuthError("Set WEB_PASSWORD in .env first: it stays the fallback admin login", 409)
        username = (username or "").strip()
        if not USERNAME_RE.match(username):
            raise AuthError("Usernames are 2-32 letters, numbers, dots, dashes or underscores")
        if username.lower() == self.cfg.web_username.lower():
            raise AuthError("That username is the built-in admin's")
        if role not in ROLES:
            raise AuthError("Role must be admin or viewer")
        self._validate_password(password, username)
        if self.store._query("SELECT 1 FROM users WHERE username = ? COLLATE NOCASE", (username,)):
            raise AuthError("That username is taken", 409)
        if self.store._query("SELECT COUNT(*) AS n FROM users")[0]["n"] >= 100:
            raise AuthError("At most 100 accounts")
        with self.store.lock:
            cur = self.store.conn.execute(
                "INSERT INTO users (username, password_hash, role, created, disabled) VALUES (?, ?, ?, ?, 0)",
                (username, hash_password(password), role, time.time()))
            self.store.conn.commit()
            uid = cur.lastrowid
        self._changed()
        self.store.add_event("auth", None, None, f"{by} created {role} account '{username}'")
        return self.public_user(self.get_user(uid))

    def update_user(self, user_id, by, role=None, disabled=None, password=None):
        user = self.get_user(user_id)
        if not user:
            raise AuthError("Unknown account", 404)
        changes, end_sessions = [], False
        if user.get("sso_subject") and (role is not None or password is not None):
            raise AuthError("This account signs in with SSO: its role comes from the provider's groups and it has no password", 400)
        if role is not None:
            if role not in ROLES:
                raise AuthError("Role must be admin or viewer")
            self.store._exec("UPDATE users SET role = ? WHERE id = ?", (role, user_id)); changes.append(f"role {role}")
        if disabled is not None:
            self.store._exec("UPDATE users SET disabled = ? WHERE id = ?", (int(disabled), user_id))
            changes.append("disabled" if disabled else "enabled"); end_sessions |= bool(disabled)
        if password is not None:
            self._validate_password(password, user["username"])
            self.store._exec("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(password), user_id))
            changes.append("password reset"); end_sessions = True
        if end_sessions:
            self.end_user_sessions(user_id)
        self._changed()
        if changes:
            self.store.add_event("auth", None, None, f"{by} changed account '{user['username']}': {', '.join(changes)}")
        return self.public_user(self.get_user(user_id))

    def change_own_password(self, user_id, current, new, keep_session_hash):
        user = self.get_user(user_id)
        if user and user.get("sso_subject"):
            raise AuthError("This account signs in with SSO; change your password at the provider", 400)
        if not user or not verify_password(current or "", user["password_hash"]):
            raise AuthError("Current password is wrong", 403)
        self._validate_password(new, user["username"])
        self.store._exec("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(new), user_id))
        # Sign out everywhere else; keep this browser signed in with a fresh tag.
        self.store._exec("DELETE FROM sessions WHERE user_id = ? AND id_hash != ?", (user_id, keep_session_hash))
        self.store._exec("UPDATE sessions SET cred_tag = ? WHERE id_hash = ?",
                         (self._user_tag(self.get_user(user_id)), keep_session_hash))
        self._changed()
        self.store.add_event("auth", None, None, f"'{user['username']}' changed their password")

    def delete_user(self, user_id, by):
        user = self.get_user(user_id)
        if not user:
            raise AuthError("Unknown account", 404)
        self.end_user_sessions(user_id)
        self.store._exec("UPDATE api_tokens SET revoked = 1 WHERE created_by = ?", (user_id,))
        self.store._exec("DELETE FROM users WHERE id = ?", (user_id,))
        self.store.delete_prefs(f"user:{int(user_id)}")
        self._changed()
        self.store.add_event("auth", None, None, f"{by} deleted account '{user['username']}'")

    # ---------- API tokens ----------
    def create_token(self, name, role, expires_days, by_principal):
        name = (name or "").strip()
        if not TOKEN_NAME_RE.match(name):
            raise AuthError("Token names are 1-40 characters: letters, numbers, spaces and . : @ ( ) / -")
        if role not in ROLES:
            raise AuthError("Role must be admin or viewer")
        if expires_days is not None and not (1 <= int(expires_days) <= 3650):
            raise AuthError("Expiry must be 1 to 3650 days, or never")
        if self.store._query("SELECT COUNT(*) AS n FROM api_tokens WHERE revoked = 0")[0]["n"] >= 50:
            raise AuthError("At most 50 active tokens")
        raw = TOKEN_PREFIX + secrets.token_urlsafe(32)
        now = time.time()
        with self.store.lock:
            cur = self.store.conn.execute(
                "INSERT INTO api_tokens (name, token_hash, prefix, role, created_by, created, expires, revoked) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
                (name, _sha(raw), raw[:10], role, by_principal["user_id"], now,
                 now + int(expires_days) * 86400 if expires_days else None))
            self.store.conn.commit()
            tid = cur.lastrowid
        self.store.add_event("auth", None, None, f"{by_principal['username']} created {role} API token '{name}'")
        return raw, self.public_token(self._get_token(tid))

    def _get_token(self, token_id):
        rows = self.store._query("SELECT * FROM api_tokens WHERE id = ?", (token_id,))
        return rows[0] if rows else None

    @staticmethod
    def public_token(t):
        return {k: t[k] for k in ("id", "name", "prefix", "role", "created", "expires", "last_used", "revoked")}

    def list_tokens(self):
        return [self.public_token(t) for t in self.store._query(
            "SELECT * FROM api_tokens WHERE revoked = 0 ORDER BY created DESC")]

    def revoke_token(self, token_id, by):
        t = self._get_token(token_id)
        if not t or t["revoked"]:
            raise AuthError("Unknown token", 404)
        self.store._exec("UPDATE api_tokens SET revoked = 1 WHERE id = ?", (token_id,))
        self.store.add_event("auth", None, None, f"{by} revoked API token '{t['name']}'")

    def resolve_token(self, raw):
        if not raw.startswith(TOKEN_PREFIX) or len(raw) > 100:
            return None
        rows = self.store._query("SELECT * FROM api_tokens WHERE token_hash = ? AND revoked = 0", (_sha(raw),))
        if not rows:
            return None
        t, now = rows[0], time.time()
        if t["expires"] and t["expires"] < now:
            return None
        if t["created_by"] not in (None, BUILTIN_ID):
            owner = self.get_user(t["created_by"])
            if not owner or owner["disabled"]:
                return None
            if owner["role"] != "admin":
                t["role"] = "viewer"           # a token can't do more than the account that made it
        if not t["last_used"] or now - t["last_used"] > 60:
            self.store._exec("UPDATE api_tokens SET last_used = ? WHERE id = ?", (now, t["id"]))
        return principal("token", f"token:{t['name']}", t["role"], token_id=t["id"])
