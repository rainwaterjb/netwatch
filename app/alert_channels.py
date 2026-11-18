"""Extra alert channels: Discord, Slack, Telegram, Gotify, ntfy, webhooks and MQTT.

Every channel gets the same message: {title, message, kind, severity, ...}.
Messages are sent as plain text (no markup is interpreted), and Discord is told
not to turn "@everyone" in a device name into a ping.

Channel settings live in the database. Secret fields (tokens, passwords, webhook
URLs that contain a key) are never sent back to the browser.
"""
import hashlib
import hmac
import json
import logging
import re
import socket
import ssl
import struct
import time
import urllib.error
import urllib.parse
import urllib.request

log = logging.getLogger("netwatch.channels")
TIMEOUT = 10
TELEGRAM_API = "https://api.telegram.org"          # overridable in tests

# kind -> (label, [(field, label, required, secret, kind)])
KINDS = {
    "discord":  ("Discord", [("webhook_url", "Webhook URL", True, True, "https")]),
    "slack":    ("Slack", [("webhook_url", "Webhook URL", True, True, "https")]),
    "telegram": ("Telegram", [("bot_token", "Bot token", True, True, "text"), ("chat_id", "Chat ID", True, False, "chat")]),
    "gotify":   ("Gotify", [("url", "Server URL", True, False, "url"), ("app_token", "App token", True, True, "text"),
                            ("priority", "Priority (0-10)", False, False, "int")]),
    "ntfy":     ("ntfy", [("url", "Topic URL", True, False, "url"), ("token", "Access token", False, True, "text"),
                          ("priority", "Priority (1-5)", False, False, "int")]),
    "webhook":  ("Webhook / Home Assistant", [("url", "URL", True, True, "url"),
                                              ("secret", "Signing secret", False, True, "text")]),
    "mqtt":     ("MQTT", [("host", "Broker host", True, False, "host"), ("port", "Port", False, False, "int"),
                          ("tls", "Use TLS", False, False, "bool"), ("username", "Username", False, False, "text"),
                          ("password", "Password", False, True, "text"), ("topic", "Topic", False, False, "topic")]),
}
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,252})$|^\[?[0-9a-fA-F:]+\]?$")
TOPIC_RE = re.compile(r"^[^#+\x00]{1,200}$")
CHAT_RE = re.compile(r"^(-?\d{1,20}|@[A-Za-z0-9_]{5,32})$")


class ChannelError(Exception):
    pass


def validate(kind, config, old=None):
    """Return a clean config. Empty secret fields keep their old value."""
    if kind not in KINDS:
        raise ChannelError("Unknown channel type")
    old = old or {}
    out = {}
    for field, label, required, secret, ftype in KINDS[kind][1]:
        v = config.get(field)
        if isinstance(v, str):
            v = v.strip()
        if secret and (v is None or v == ""):
            v = old.get(field, "")
        if v in (None, "") and ftype != "bool":
            if required:
                raise ChannelError(f"{label} is required")
            continue
        if ftype in ("url", "https"):
            u = urllib.parse.urlsplit(str(v))
            if u.scheme not in (("https",) if ftype == "https" else ("http", "https")) or not u.hostname or len(v) > 500:
                raise ChannelError(f"{label} must be a{'n https' if ftype == 'https' else 'n http(s)'}:// address")
        elif ftype == "int":
            try:
                v = int(v)
            except (TypeError, ValueError):
                raise ChannelError(f"{label} must be a number") from None
            if field == "port" and not 1 <= v <= 65535 or field == "priority" and not 0 <= v <= 10:
                raise ChannelError(f"{label} is out of range")
        elif ftype == "bool":
            v = bool(v) and v not in ("false", "0", "off")
        elif ftype == "host":
            if not HOST_RE.match(str(v)):
                raise ChannelError(f"{label} isn't a valid host name or address")
        elif ftype == "topic":
            if not TOPIC_RE.match(str(v)):
                raise ChannelError(f"{label} can't contain # or + (MQTT wildcards)")
        elif ftype == "chat":
            if not CHAT_RE.match(str(v)):
                raise ChannelError(f"{label} must be a number (e.g. -1001234) or @channelname")
        else:
            v = str(v)
            if len(v) > 300 or any(ord(ch) < 32 for ch in v):
                raise ChannelError(f"{label} is too long or has odd characters")
        out[field] = v
    return out


def public_config(kind, config):
    """Config safe to show in the browser: secrets replaced by whether they're set."""
    out, secrets_set = {}, []
    for field, _label, _req, secret, _t in KINDS.get(kind, ("", []))[1]:
        if secret:
            if config.get(field):
                secrets_set.append(field)
        elif field in config:
            out[field] = config[field]
    return out, secrets_set


def describe_kinds():
    return {k: {"label": lab, "fields": [{"name": f, "label": l, "required": r, "secret": s, "type": t}
                                         for f, l, r, s, t in fields]}
            for k, (lab, fields) in KINDS.items()}


# ---------- sending ----------
def _post(url, body, headers=None):
    data = body if isinstance(body, bytes) else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "NetWatch", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            r.read(10000)
    except urllib.error.HTTPError as e:
        raise ChannelError(f"HTTP {e.code} from {urllib.parse.urlsplit(url).hostname}") from None
    except (urllib.error.URLError, OSError) as e:
        raise ChannelError(f"can't reach {urllib.parse.urlsplit(url).hostname}: {getattr(e, 'reason', e)}") from None


COLORS = {"alert": 0xF85149, "escalation": 0xA371F7, "resolved": 0x3FB950, "test": 0x58A6FF}


def send(kind, config, msg):
    """Deliver one message. Raises ChannelError with a short reason on failure."""
    title, text = msg["title"][:200], msg["message"][:3500]
    if msg.get("url"):
        text += f"\n\nOpen NetWatch: {msg['url']}"
    if kind == "discord":
        _post(config["webhook_url"], {"username": "NetWatch", "allowed_mentions": {"parse": []},
                                      "embeds": [{"title": title, "description": text,
                                                  "color": COLORS.get(msg["severity"], 0x58A6FF)}]})
    elif kind == "slack":
        esc = lambda s: s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        _post(config["webhook_url"], {"text": f"*{esc(title)}*\n{esc(text)}", "unfurl_links": False})
    elif kind == "telegram":
        _post(f"{TELEGRAM_API}/bot{config['bot_token']}/sendMessage",
              {"chat_id": config["chat_id"], "text": f"{title}\n\n{text}", "disable_web_page_preview": True})
    elif kind == "gotify":
        prio = config.get("priority", 8 if msg["severity"] in ("alert", "escalation") else 4)
        _post(config["url"].rstrip("/") + "/message", {"title": title, "message": text, "priority": prio},
              {"X-Gotify-Key": config["app_token"]})
    elif kind == "ntfy":
        u = urllib.parse.urlsplit(config["url"])
        headers = {"Authorization": f"Bearer {config['token']}"} if config.get("token") else {}
        prio = config.get("priority", 4 if msg["severity"] in ("alert", "escalation") else 3)
        _post(f"{u.scheme}://{u.netloc}", {"topic": u.path.strip("/"), "title": title, "message": text,
                                           "priority": max(1, min(5, prio)),
                                           "tags": {"alert": ["warning"], "escalation": ["rotating_light"],
                                                    "resolved": ["white_check_mark"]}.get(msg["severity"], [])}, headers)
    elif kind == "webhook":
        body = json.dumps({"source": "netwatch", **{k: v for k, v in msg.items()}}, default=str).encode()
        headers = {"X-NetWatch-Event": msg.get("event", "")}
        if config.get("secret"):
            sig = hmac.new(config["secret"].encode(), body, hashlib.sha256).hexdigest()
            headers["X-NetWatch-Signature"] = "sha256=" + sig
        _post(config["url"], body, headers)
    elif kind == "mqtt":
        payload = json.dumps({"source": "netwatch", **msg}, default=str).encode()
        mqtt_publish(config["host"], int(config.get("port") or (8883 if config.get("tls") else 1883)),
                     config.get("topic") or "netwatch/alerts", payload, config.get("username"), config.get("password"),
                     bool(config.get("tls")))
    else:
        raise ChannelError("Unknown channel type")


# ---------- a tiny MQTT 3.1.1 publisher (QoS 0), so there's no extra dependency ----------
def _mqtt_str(s):
    b = s.encode()
    return struct.pack("!H", len(b)) + b


def _mqtt_len(n):
    out = bytearray()
    while True:
        byte, n = n % 128, n // 128
        out.append(byte | (0x80 if n else 0))
        if not n:
            return bytes(out)


def mqtt_publish(host, port, topic, payload, username=None, password=None, use_tls=False, client_id=None):
    client_id = client_id or f"netwatch-{int(time.time() * 1000) % 10 ** 9}"
    flags = 0x02 | (0x80 if username else 0) | (0x40 if username and password else 0)   # clean session
    body = _mqtt_str("MQTT") + bytes([4, flags]) + struct.pack("!H", 30) + _mqtt_str(client_id)
    if username:
        body += _mqtt_str(username)
        if password:
            body += _mqtt_str(password)
    connect = bytes([0x10]) + _mqtt_len(len(body)) + body
    pub_body = _mqtt_str(topic) + payload
    publish = bytes([0x30]) + _mqtt_len(len(pub_body)) + pub_body
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        if use_tls:
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        with sock:
            sock.sendall(connect)
            ack = sock.recv(4)
            if len(ack) < 4 or ack[0] != 0x20:
                raise ChannelError("MQTT broker didn't accept the connection")
            if ack[3] != 0:
                raise ChannelError({4: "MQTT username or password rejected", 5: "MQTT not authorised"}.get(
                    ack[3], f"MQTT broker refused (code {ack[3]})"))
            sock.sendall(publish + bytes([0xE0, 0]))           # PUBLISH, then DISCONNECT
    except (OSError, ssl.SSLError) as e:
        raise ChannelError(f"can't reach MQTT broker {host}:{port}: {e.__class__.__name__}") from None
