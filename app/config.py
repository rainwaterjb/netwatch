"""Configuration, read from environment variables (see .env.example)."""
import os
from dataclasses import dataclass, field


def _targets(value):
    out = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        host, _, port = item.rpartition(":")
        if not host:
            host, port = item, "443"
        out.append((host, int(port)))
    return out


def _tls_mode(value):
    v = value.lower()
    if v in ("off", "false", "no", "0", "none"):
        return "off"
    if v in ("custom", "file", "files"):
        return "custom"
    return "self-signed"


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

    # HTTPS
    tls_mode: str = "self-signed"       # self-signed | custom | off
    https_port: int = 8443
    http_port: int = 8080               # redirects to HTTPS (or serves the UI when TLS is off)
    tls_dir: str = "/data/tls"
    tls_cert_file: str = ""
    tls_key_file: str = ""
    tls_hostnames: list[str] = field(default_factory=list)

    # Internet (WAN) monitoring
    wan_check_enabled: bool = True
    wan_check_interval: int = 30
    wan_targets: list[tuple[str, int]] = field(
        default_factory=lambda: [("1.1.1.1", 443), ("8.8.8.8", 443), ("9.9.9.9", 443)])

    # Pi-hole v6 integration (read-only)
    pihole_urls: list[str] = field(default_factory=list)
    pihole_passwords: list[str] = field(default_factory=list)
    pihole_verify_tls: bool = True
    pihole_poll_interval: int = 300

    # Web UI security
    web_username: str = "admin"
    web_password: str = ""              # empty = no login (LAN-only use)
    allowed_hosts: list[str] = field(default_factory=list)  # empty = any Host header

    # Router integration (ROUTER_TYPE: linksys | opnsense | pfsense | unifi | openwrt)
    router_type: str = ""
    router_url: str = ""
    router_username: str = ""
    router_password: str = ""
    router_api_key: str = ""
    router_api_secret: str = ""
    router_verify_tls: bool = True
    router_allow_changes: bool = False
    router_site: str = "default"        # UniFi site name
    router_interface: str = "lan"       # pfSense DHCP interface / OpenWrt interface
    router_dhcp: str = "auto"           # OPNsense: auto | dnsmasq | kea

    # Legacy names (v1.1-v1.5); still read, mapped onto router_* above
    # Optional read-only Linksys Velop/Atlas router integration (JNAP)
    linksys_url: str = ""               # e.g. http://192.168.1.1
    linksys_username: str = "admin"
    linksys_password: str = ""
    router_poll_interval: int = 300
    linksys_allow_changes: bool = False # allow adding/removing DHCP reservations
    router_backup_dir: str = "/data/router-backups"

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
            tls_mode=_tls_mode(_env("TLS", "self-signed")),
            https_port=int(_env("HTTPS_PORT", "8443")),
            http_port=int(_env("PORT", "8080") or 0),
            tls_dir=_env("TLS_DIR") or os.path.join(
                os.path.dirname(_env("DB_PATH", "/data/netwatch.db")) or ".", "tls"),
            tls_cert_file=_env("TLS_CERT_FILE"),
            tls_key_file=_env("TLS_KEY_FILE"),
            tls_hostnames=[h.strip() for h in _env("TLS_HOSTNAMES").split(",") if h.strip()],
            wan_check_enabled=_env("WAN_CHECK", "true").lower() not in ("0", "false", "no", "off"),
            wan_check_interval=max(10, int(_env("WAN_CHECK_INTERVAL", "30"))),
            wan_targets=_targets(_env("WAN_CHECK_TARGETS", "1.1.1.1:443,8.8.8.8:443,9.9.9.9:443")),
            pihole_urls=[u.strip().rstrip("/") for u in _env("PIHOLE_URLS").split(",") if u.strip()],
            pihole_passwords=[p for p in _env("PIHOLE_PASSWORD").split(",")] if _env("PIHOLE_PASSWORD") else [],
            pihole_verify_tls=_env("PIHOLE_VERIFY_TLS", "true").lower() not in ("0", "false", "no", "off"),
            pihole_poll_interval=max(60, int(_env("PIHOLE_POLL_INTERVAL", "300"))),
            web_username=_env("WEB_USERNAME", "admin"),
            web_password=_env("WEB_PASSWORD"),
            allowed_hosts=[h.strip().lower() for h in _env("ALLOWED_HOSTS").split(",") if h.strip()],
            router_type=_env("ROUTER_TYPE").lower() or ("linksys" if _env("LINKSYS_URL") else ""),
            router_url=_env("ROUTER_URL") or _env("LINKSYS_URL"),
            router_username=_env("ROUTER_USERNAME") or _env("LINKSYS_USERNAME"),
            router_password=_env("ROUTER_PASSWORD") or _env("LINKSYS_PASSWORD"),
            router_api_key=_env("ROUTER_API_KEY"),
            router_api_secret=_env("ROUTER_API_SECRET"),
            router_verify_tls=_env("ROUTER_VERIFY_TLS", "true").lower() not in ("0", "false", "no", "off"),
            router_allow_changes=(_env("ROUTER_ALLOW_CHANGES") or _env("LINKSYS_ALLOW_CHANGES") or "false").lower()
                in ("1", "true", "yes"),
            router_site=_env("ROUTER_SITE", "default"),
            router_interface=_env("ROUTER_INTERFACE", "lan"),
            router_dhcp=_env("ROUTER_DHCP", "auto").lower(),
            linksys_url=_env("LINKSYS_URL"),
            linksys_username=_env("LINKSYS_USERNAME", "admin"),
            linksys_password=_env("LINKSYS_PASSWORD"),
            router_poll_interval=max(60, int(_env("ROUTER_POLL_INTERVAL", "300"))),
            linksys_allow_changes=_env("LINKSYS_ALLOW_CHANGES", "false").lower() in ("1", "true", "yes"),
            router_backup_dir=_env("ROUTER_BACKUP_DIR")
                or os.path.join(os.path.dirname(_env("DB_PATH", "/data/netwatch.db")) or ".", "router-backups"),
        )
