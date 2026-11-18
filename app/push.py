"""Web Push: notifications on phones and computers that installed the NetWatch app.

Standards: Web Push (RFC 8030), message encryption (RFC 8291, aes128gcm) and
VAPID (RFC 8292). Built on the `cryptography` package NetWatch already uses.

- NetWatch's VAPID key pair is created on first start and kept in the data
  folder (readable only by NetWatch). Only the public half is ever sent out.
- Each browser that turns on notifications gives a push-service address
  (Apple, Google, Mozilla or Microsoft) plus its own keys. Messages are
  end-to-end encrypted for that browser: the push service can't read them.
- Push addresses must be https:// on a known push service, so a signed-in user
  can't make NetWatch send requests to arbitrary hosts.
"""
import base64
import json
import logging
import os
import struct
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

log = logging.getLogger("netwatch.push")

PUSH_HOSTS = (".push.apple.com", "fcm.googleapis.com", "android.googleapis.com", ".push.services.mozilla.com",
              ".notify.windows.com", "push.services.mozilla.com")
MAX_SUBSCRIPTIONS = 100
RECORD_SIZE = 4096


def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64u(s):
    s = str(s)
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class PushError(Exception):
    pass


def encrypt(payload, ua_public, auth_secret, sender_key=None, salt=None):
    """RFC 8291 aes128gcm content encoding. Returns the request body."""
    sender_key = sender_key or ec.generate_private_key(ec.SECP256R1())
    salt = salt or os.urandom(16)
    as_public = sender_key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    ua_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua_public)
    shared = sender_key.exchange(ec.ECDH(), ua_key)
    ikm = HKDF(hashes.SHA256(), 32, auth_secret, b"WebPush: info\x00" + ua_public + as_public).derive(shared)
    cek = HKDF(hashes.SHA256(), 16, salt, b"Content-Encoding: aes128gcm\x00").derive(ikm)
    nonce = HKDF(hashes.SHA256(), 12, salt, b"Content-Encoding: nonce\x00").derive(ikm)
    if len(payload) > RECORD_SIZE - 17 - 86:
        raise PushError("message too long")
    ciphertext = AESGCM(cek).encrypt(nonce, payload + b"\x02", None)      # \x02 = last record
    return salt + struct.pack("!IB", RECORD_SIZE, len(as_public)) + as_public + ciphertext


class Pusher:
    def __init__(self, cfg, store):
        self.cfg = cfg
        self.store = store
        self.contact = getattr(cfg, "push_contact", "") or "mailto:netwatch@example.org"
        self.extra_hosts = tuple(getattr(cfg, "push_allowed_hosts", []) or [])
        self.key_path = os.path.join(os.path.dirname(cfg.db_path) or ".", "vapid_private.pem")
        self._key = None
        self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="push")
        self.lock = threading.Lock()

    # ---------- VAPID keys ----------
    def key(self):
        with self.lock:
            if self._key is None:
                if os.path.exists(self.key_path):
                    with open(self.key_path, "rb") as f:
                        self._key = serialization.load_pem_private_key(f.read(), None)
                else:
                    self._key = ec.generate_private_key(ec.SECP256R1())
                    pem = self._key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption())
                    fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, "wb") as f:
                        f.write(pem)
                    log.info("Created the push notification key")
            return self._key

    def public_key(self):
        return b64u(self.key().public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))

    def vapid_header(self, endpoint, now=None):
        u = urllib.parse.urlsplit(endpoint)
        claims = {"aud": f"{u.scheme}://{u.netloc}", "exp": int((now or time.time()) + 12 * 3600), "sub": self.contact}
        head = b64u(json.dumps({"typ": "JWT", "alg": "ES256"}, separators=(",", ":")).encode())
        body = b64u(json.dumps(claims, separators=(",", ":")).encode())
        r, s = decode_dss_signature(self.key().sign(f"{head}.{body}".encode(), ec.ECDSA(hashes.SHA256())))
        sig = b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
        return f"vapid t={head}.{body}.{sig}, k={self.public_key()}"

    # ---------- subscriptions ----------
    def endpoint_ok(self, endpoint):
        try:
            u = urllib.parse.urlsplit(endpoint)
        except ValueError:
            return False
        host = (u.hostname or "").lower()
        if u.scheme != "https" or not host or len(endpoint) > 1000 or u.username or u.password:
            return False
        allowed = PUSH_HOSTS + self.extra_hosts
        return any(host == h.lstrip(".") or (h.startswith(".") and host.endswith(h)) for h in allowed)

    def subscribe(self, who, sub, user_agent=""):
        endpoint = str((sub or {}).get("endpoint") or "")
        keys = (sub or {}).get("keys") or {}
        if not self.endpoint_ok(endpoint):
            raise PushError("That isn't a known push service address")
        try:
            p256dh, auth = unb64u(keys.get("p256dh", "")), unb64u(keys.get("auth", ""))
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), p256dh)
        except Exception:
            raise PushError("The browser's push keys aren't valid") from None
        if len(auth) != 16:
            raise PushError("The browser's push keys aren't valid")
        if self.store._query("SELECT COUNT(*) n FROM push_subscriptions")[0]["n"] >= MAX_SUBSCRIPTIONS and \
                not self.store._query("SELECT 1 FROM push_subscriptions WHERE endpoint = ?", (endpoint,)):
            raise PushError(f"At most {MAX_SUBSCRIPTIONS} devices can get notifications")
        now = time.time()
        self.store._exec(
            "INSERT INTO push_subscriptions (endpoint, p256dh, auth, username, user_id, label, created, fails) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 0) ON CONFLICT(endpoint) DO UPDATE SET p256dh = excluded.p256dh, "
            "auth = excluded.auth, username = excluded.username, user_id = excluded.user_id, label = excluded.label, fails = 0",
            (endpoint, b64u(p256dh), b64u(auth), (who or {}).get("username") or "admin", (who or {}).get("user_id"),
             _device_label(user_agent), now))
        return self.store._query("SELECT id FROM push_subscriptions WHERE endpoint = ?", (endpoint,))[0]["id"]

    def unsubscribe(self, endpoint):
        return self.store._exec("DELETE FROM push_subscriptions WHERE endpoint = ?", (str(endpoint)[:1000],))

    def subscriptions(self, username=None):
        q, args = "SELECT id, username, label, created, last_ok, last_error, fails FROM push_subscriptions", ()
        if username is not None:
            q, args = q + " WHERE username = ?", (username,)
        return self.store._query(q + " ORDER BY created DESC", args)

    def remove(self, sub_id, username=None):
        q, args = "DELETE FROM push_subscriptions WHERE id = ?", [sub_id]
        if username is not None:
            q += " AND username = ?"
            args.append(username)
        return self.store._exec(q, tuple(args))

    def count(self):
        return self.store._query("SELECT COUNT(*) n FROM push_subscriptions")[0]["n"]

    # ---------- sending ----------
    def _send_one(self, row, payload, urgency="high", ttl=86400):
        body = encrypt(payload, unb64u(row["p256dh"]), unb64u(row["auth"]))
        req = urllib.request.Request(row["endpoint"], data=body, method="POST", headers={
            "TTL": str(ttl), "Urgency": urgency, "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream",
            "Authorization": self.vapid_header(row["endpoint"])})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                r.read(2000)
            self.store._exec("UPDATE push_subscriptions SET last_ok = ?, fails = 0, last_error = NULL WHERE id = ?", (time.time(), row["id"]))
            return "ok"
        except urllib.error.HTTPError as e:
            if e.code in (404, 410):                      # the browser unsubscribed or the app was removed
                self.store._exec("DELETE FROM push_subscriptions WHERE id = ?", (row["id"],))
                return "gone"
            err = f"HTTP {e.code}"
        except (urllib.error.URLError, OSError) as e:
            err = f"can't reach push service: {getattr(e, 'reason', e)}"[:120]
        self.store._exec("UPDATE push_subscriptions SET last_error = ?, fails = fails + 1 WHERE id = ?", (err, row["id"]))
        self.store._exec("DELETE FROM push_subscriptions WHERE id = ? AND fails >= 50", (row["id"],))
        return err

    def send(self, title, body, url="/", tag=None, severity="alert", username=None, wait=False):
        """Send to every app install (or one user's). Returns {"sent": n, "failed": n} when wait=True."""
        rows = self.store._query("SELECT * FROM push_subscriptions" + (" WHERE username = ?" if username else ""),
                                 (username,) if username else ())
        if not rows:
            return {"sent": 0, "failed": 0}
        payload = json.dumps({"title": str(title)[:120], "body": str(body)[:900], "url": url if str(url).startswith("/") else "/",
                              "tag": str(tag or "")[:60] or None, "severity": severity}).encode()
        futures = [self._pool.submit(self._send_one, r, payload, "high" if severity in ("alert", "escalation") else "normal")
                   for r in rows]
        if not wait:
            return {"queued": len(futures)}
        results = [f.result() for f in futures]
        return {"sent": results.count("ok"), "failed": len([r for r in results if r not in ("ok", "gone")]),
                "removed": results.count("gone")}

    def start(self):
        try:
            self.key()
        except OSError as e:
            log.error("Can't create the push key in %s: %s", self.key_path, e)

    def stop(self):
        self._pool.shutdown(wait=False, cancel_futures=True)


def _device_label(ua):
    ua = ua or ""
    os_ = next((n for k, n in (("iPhone", "iPhone"), ("iPad", "iPad"), ("Android", "Android"), ("Mac OS X", "Mac"),
                                ("Windows", "Windows"), ("Linux", "Linux")) if k in ua), "Device")
    br = next((n for k, n in (("Edg/", "Edge"), ("Firefox/", "Firefox"), ("Chrome/", "Chrome"), ("Safari/", "Safari")) if k in ua), "browser")
    return f"{os_} · {br}"
