"""Configuration, read from environment variables (see .env.example)."""
import os
from dataclasses import dataclass, field


def _env(name, default=""):
    return os.getenv(name, default).strip()


@dataclass
class Config:
    # Network
    subnet: str | None = None          # e.g. 192.168.1.0/24 (auto-detected if empty)
    iface: str | None = None           # e.g. eth0 / vmbr0 (auto-detected if empty)
    scan_interval: int = 60            # seconds between scans
    offline_after: int = 3             # missed scans before a device counts as offline
    arp_timeout: float = 3.0
    db_path: str = "/data/netwatch.db"
    event_retention_days: int = 90

    # Phone: ntfy and/or Pushover
    ntfy_url: str = ""                 # e.g. https://ntfy.sh/my-secret-topic
    ntfy_token: str = ""
    pushover_user_key: str = ""
    pushover_app_token: str = ""

    # Email: SMTP
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_security: str = "starttls"    # starttls | ssl | none
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_to: list[str] = field(default_factory=list)

    # Optional: alert when an unknown device joins (none | phone | email | both)
    notify_new_devices: str = "none"

    # Web UI security
    web_username: str = "admin"
    web_password: str = ""              # empty = no login (LAN-only use)
    allowed_hosts: list[str] = field(default_factory=list)  # empty = any Host header

    @classmethod
    def from_env(cls):
        return cls(
            subnet=_env("SUBNET") or None,
            iface=_env("INTERFACE") or None,
            scan_interval=max(10, int(_env("SCAN_INTERVAL", "60"))),
            offline_after=max(1, int(_env("OFFLINE_AFTER_MISSED_SCANS", "3"))),
            arp_timeout=float(_env("ARP_TIMEOUT", "3")),
            db_path=_env("DB_PATH", "/data/netwatch.db"),
            event_retention_days=int(_env("EVENT_RETENTION_DAYS", "90")),
            ntfy_url=_env("NTFY_URL"),
            ntfy_token=_env("NTFY_TOKEN"),
            pushover_user_key=_env("PUSHOVER_USER_KEY"),
            pushover_app_token=_env("PUSHOVER_APP_TOKEN"),
            smtp_host=_env("SMTP_HOST"),
            smtp_port=int(_env("SMTP_PORT", "587")),
            smtp_security=_env("SMTP_SECURITY", "starttls").lower(),
            smtp_user=_env("SMTP_USER"),
            smtp_password=_env("SMTP_PASSWORD"),
            smtp_from=_env("SMTP_FROM") or _env("SMTP_USER"),
            smtp_to=[a.strip() for a in _env("SMTP_TO").split(",") if a.strip()],
            notify_new_devices=_env("NOTIFY_NEW_DEVICES", "none").lower(),
            web_username=_env("WEB_USERNAME", "admin"),
            web_password=_env("WEB_PASSWORD"),
            allowed_hosts=[h.strip().lower() for h in _env("ALLOWED_HOSTS").split(",") if h.strip()],
        )
