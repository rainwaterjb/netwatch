"""Phone (ntfy / Pushover) and email (SMTP) notifications."""
import json
import logging
import smtplib
import ssl
import threading
import urllib.parse
import urllib.request
from email.message import EmailMessage

log = logging.getLogger("netwatch.notifier")


class Notifier:
    def __init__(self, cfg):
        self.cfg = cfg

    @property
    def phone_enabled(self):
        c = self.cfg
        return bool(c.ntfy_url or (c.pushover_user_key and c.pushover_app_token))

    @property
    def email_enabled(self):
        return bool(self.cfg.smtp_host and self.cfg.smtp_to)

    def notify(self, title, message, phone=False, email=False, tags=None):
        """Fire-and-forget so a slow mail server never stalls a scan."""
        if not ((phone and self.phone_enabled) or (email and self.email_enabled)):
            return
        threading.Thread(
            target=self.send_now, args=(title, message, phone, email, tags), daemon=True
        ).start()

    def send_now(self, title, message, phone=False, email=False, tags=None):
        results = {}
        if phone:
            results["phone"] = self._safe(self._send_phone, title, message, tags) \
                if self.phone_enabled else "not configured"
        if email:
            results["email"] = self._safe(self._send_email, title, message) \
                if self.email_enabled else "not configured"
        return results

    @staticmethod
    def _safe(fn, *args):
        try:
            fn(*args)
            return "ok"
        except Exception as e:
            log.error("Notification via %s failed: %s", fn.__name__, e)
            return "failed (see container logs)"

    # Phone
    def _send_phone(self, title, message, tags=None):
        c = self.cfg
        errors = []
        if c.ntfy_url:
            try:
                self._ntfy(title, message, tags)
            except Exception as e:
                errors.append(f"ntfy: {e}")
        if c.pushover_user_key and c.pushover_app_token:
            try:
                self._pushover(title, message)
            except Exception as e:
                errors.append(f"pushover: {e}")
        if errors:
            raise RuntimeError("; ".join(errors))

    def _ntfy(self, title, message, tags=None):
        # JSON publishing lets titles contain any characters.
        u = urllib.parse.urlparse(self.cfg.ntfy_url)
        server = f"{u.scheme}://{u.netloc}"
        topic = u.path.strip("/")
        body = json.dumps({
            "topic": topic, "title": title, "message": message,
            "priority": 4, "tags": tags or [],
        }).encode()
        req = urllib.request.Request(server, data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        if self.cfg.ntfy_token:
            req.add_header("Authorization", f"Bearer {self.cfg.ntfy_token}")
        urllib.request.urlopen(req, timeout=15).read()

    def _pushover(self, title, message):
        data = urllib.parse.urlencode({
            "token": self.cfg.pushover_app_token, "user": self.cfg.pushover_user_key,
            "title": title, "message": message, "priority": 1,
        }).encode()
        urllib.request.urlopen("https://api.pushover.net/1/messages.json",
                               data=data, timeout=15).read()

    # Email
    def _send_email(self, title, message):
        c = self.cfg
        msg = EmailMessage()
        msg["Subject"] = f"[NetWatch] {title}"
        msg["From"] = c.smtp_from or c.smtp_user
        msg["To"] = ", ".join(c.smtp_to)
        msg.set_content(message)
        if c.smtp_security == "ssl":
            server = smtplib.SMTP_SSL(c.smtp_host, c.smtp_port, timeout=20,
                                      context=ssl.create_default_context())
        else:
            server = smtplib.SMTP(c.smtp_host, c.smtp_port, timeout=20)
        with server:
            if c.smtp_security == "starttls":
                server.starttls(context=ssl.create_default_context())
            if c.smtp_user:
                if c.smtp_security not in ("starttls", "ssl"):
                    raise RuntimeError("Refusing to send the SMTP password over an unencrypted "
                                       "connection; set SMTP_SECURITY to starttls or ssl")
                server.login(c.smtp_user, c.smtp_password)
            server.send_message(msg)
