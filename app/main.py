"""NetWatch web app: REST API + dashboard."""
import ipaddress
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path as FsPath

import csv
import io
import re
import tempfile

from fastapi import FastAPI, HTTPException, Path, Query
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field
from starlette.background import BackgroundTask

from . import history as dev_history
from . import wol
from .alerts import CHANNEL_CHOICES, DEFAULT_SETTINGS, AlertManager, in_quiet_hours, validate_time
from .config import Config
from .db import Store
from .monitor import Monitor, display_name
from .pihole import PiholeIntegration
from .services import KINDS as CHECK_KINDS, ServiceChecker
from .wan import WanMonitor
from .notifier import Notifier
from .router_linksys import LinksysRouter, RouterError
from .security import SecurityMiddleware
from . import tls

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")

cfg = Config.from_env()
store = Store(cfg.db_path)
notifier = Notifier(cfg)
router = LinksysRouter(cfg)
alerts = AlertManager(store, notifier)
monitor = Monitor(cfg, store, notifier, router=router, alerts=alerts)
checker = ServiceChecker(store, alerts, router=router)
wan = WanMonitor(cfg, store, alerts, monitor=monitor)
pihole = PiholeIntegration(cfg, store, alerts, router=router)
BACKGROUND = (monitor, router, alerts, checker, wan, pihole)
STATIC = FsPath(__file__).parent / "static"


@asynccontextmanager
async def lifespan(_app):
    if os.getenv("NETWATCH_DISABLE_SCANNER") != "1":
        for svc in BACKGROUND:
            svc.start()
    yield
    for svc in BACKGROUND:
        svc.stop()


app = FastAPI(title="NetWatch", lifespan=lifespan)
app.add_middleware(SecurityMiddleware, cfg=cfg)

MAC_PATTERN = r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$"


@app.get("/healthz")
def healthz():
    return {"ok": True}


def _cert_path():
    if cfg.tls_mode == "custom":
        return cfg.tls_cert_file
    if cfg.tls_mode == "self-signed":
        return os.path.join(cfg.tls_dir, "netwatch.crt")
    return None


@app.get("/netwatch.crt")
def certificate():
    """Public certificate, so you can install it as trusted on your devices."""
    path = _cert_path()
    if not path or not os.path.exists(path):
        raise HTTPException(404, "No certificate (HTTPS is off)")
    return FileResponse(path, media_type="application/x-x509-ca-cert", filename="netwatch.crt")


_tls_cache = {}


def _tls_status():
    path = _cert_path()
    if not path or not os.path.exists(path):
        return {"mode": cfg.tls_mode}
    mtime = os.path.getmtime(path)
    if _tls_cache.get("mtime") != mtime:
        try:
            _tls_cache.update(mtime=mtime, info=tls.describe(path))
        except Exception:
            _tls_cache.update(mtime=mtime, info={})
    return {"mode": cfg.tls_mode, **_tls_cache["info"]}


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/status")
def status():
    devices = store.all_devices()
    return {
        "now": time.time(),
        "subnet": str(monitor.network) if monitor.network else cfg.subnet,
        "interface": monitor.iface,
        "scan_interval": cfg.scan_interval,
        "offline_after": cfg.offline_after,
        "last_scan": monitor.last_scan,
        "last_scan_duration": monitor.last_scan_duration,
        "last_error": monitor.last_error,
        "online": sum(1 for d in devices if d["online"]),
        "known": len(devices),
        "phone_enabled": notifier.phone_enabled,
        "email_enabled": notifier.email_enabled,
        "router": _router_status(),
        "tls": _tls_status(),
        "version": os.getenv("NETWATCH_VERSION", "dev"),
        "unacknowledged": sum(1 for d in devices if not d.get("acknowledged", 1)),
        "internet": wan.status(),
        "pihole": pihole.status(),
        "held_alerts": store.count_pending(),
        "quiet_now": in_quiet_hours(alerts.settings()),
        "checks_down": sum(1 for c in store.checks() if c["enabled"] and c["state"] == "down"),
    }


def _router_status():
    if not router.enabled:
        return {"enabled": False}
    s = router.snapshot()
    can_change, reason = _change_permission()
    return {
        "enabled": True, "last_sync": s["last_sync"], "error": s["error"],
        "dhcp_first": s["dhcp_first"], "dhcp_last": s["dhcp_last"],
        "reservations": len(s["reservations"]), "max_desc": s["max_desc"],
        "can_change": can_change, "change_disabled_reason": reason,
    }


def _change_permission():
    if not router.enabled:
        return False, "Linksys integration is not configured"
    if not cfg.linksys_allow_changes:
        return False, "Set LINKSYS_ALLOW_CHANGES=true in .env to manage reservations here"
    if not cfg.web_password:
        return False, "Set WEB_PASSWORD in .env first: router changes require a dashboard login"
    return True, None


@app.get("/api/reservations")
def reservations():
    if not router.enabled:
        raise HTTPException(404, "Linksys integration is not configured")
    snap = router.snapshot()
    devices = {d["mac"]: d for d in store.all_devices()}
    out = []
    for mac, r in snap["reservations"].items():
        d = devices.get(mac)
        if d is None:
            state = "never_seen"
        elif not d["online"]:
            state = "offline"
        elif d["ip"] == r["ip"]:
            state = "active"
        else:
            state = "pending"           # online, but hasn't picked up the reserved IP yet
        out.append({
            "mac": mac, "ip": r["ip"], "description": r["description"], "state": state,
            "current_ip": d["ip"] if d else None,
            "device_name": (d and (d["nickname"] or d["hostname"] or d["vendor"])) or snap["names"].get(mac),
            "last_seen": d["last_seen"] if d else None,
        })
    out.sort(key=lambda r: ipaddress.IPv4Address(r["ip"]))
    return {"reservations": out, "router": _router_status()}


class NewReservation(BaseModel):
    mac: str = Field(max_length=17)
    ip: str = Field(max_length=15)
    description: str = Field(default="", max_length=63)


def _require_change_permission():
    ok, reason = _change_permission()
    if not ok:
        raise HTTPException(403, reason)


@app.post("/api/reservations")
def add_reservation(body: NewReservation):
    _require_change_permission()
    try:
        mac, ip, _ = router.validate_new(body.mac, body.ip, body.description)
    except ValueError as e:
        raise HTTPException(400, str(e)) from None
    clash = next((d for d in store.all_devices()
                  if d["online"] and d["ip"] == ip and d["mac"] != mac), None)
    if clash:
        raise HTTPException(409, f"{ip} is currently in use by "
                                 f"{clash['nickname'] or clash['hostname'] or clash['mac']}. Pick a free address.")
    try:
        router.add_reservation(mac, ip, body.description)
    except ValueError as e:
        raise HTTPException(400, str(e)) from None
    except RouterError as e:
        raise HTTPException(502, str(e)) from None
    store.add_event("reservation", mac, ip, f"Reserved {ip}" + (f" ({body.description.strip()})" if body.description.strip() else ""))
    return {"ok": True}


@app.delete("/api/reservations/{mac}")
def remove_reservation(mac: str = Path(pattern=MAC_PATTERN)):
    _require_change_permission()
    snap = router.snapshot()
    r = snap["reservations"].get(mac.lower())
    try:
        router.remove_reservation(mac)
    except ValueError as e:
        raise HTTPException(404, str(e)) from None
    except RouterError as e:
        raise HTTPException(502, str(e)) from None
    store.add_event("reservation", mac.lower(), r["ip"] if r else None, "Reservation removed")
    return {"ok": True}


def _enrich(d, snap=None):
    if snap:
        r = snap["reservations"].get(d["mac"])
        d["reserved_ip"] = r["ip"] if r else None
        d["router_name"] = (r and r["description"]) or snap["names"].get(d["mac"])
    if pihole.enabled and d.get("ip"):
        s = pihole.stats_for(d["ip"])
        if s:
            d["dns"] = {k: s[k] for k in ("queries_24h", "queries_1h", "baseline_per_hour", "chatty")}
    d["tags"] = _split_tags(d.get("tags"))
    return d


@app.get("/api/devices")
def devices():
    snap = router.snapshot() if router.enabled else None
    return {"now": time.time(), "devices": [_enrich(d, snap) for d in store.all_devices()]}


TAG_RE = re.compile(r"^[\w][\w .\-]{0,23}$")


def _split_tags(value):
    if isinstance(value, list):
        return value
    return [t for t in (value or "").split(",") if t]


def _clean_tags(tags):
    out = []
    for t in tags:
        t = " ".join(str(t).split()).lower()
        if not t:
            continue
        if not TAG_RE.match(t):
            raise HTTPException(400, f"Tag '{t[:24]}' may only use letters, numbers, spaces, . and - (max 24)")
        if t not in out:
            out.append(t)
    if len(out) > 10:
        raise HTTPException(400, "At most 10 tags per device")
    return ",".join(out)


class DeviceUpdate(BaseModel):
    nickname: str | None = Field(default=None, max_length=64)
    notify_phone: bool | None = None
    notify_email: bool | None = None
    notify_return: bool | None = None
    acknowledged: bool | None = None
    critical: bool | None = None
    tags: list[str] | None = Field(default=None, max_length=10)
    snooze_minutes: int | None = Field(default=None, ge=0, le=60 * 24 * 30)


@app.patch("/api/devices/{mac}")
def update_device(body: DeviceUpdate, mac: str = Path(pattern=MAC_PATTERN)):
    mac = mac.lower()
    if not store.get_device(mac):
        raise HTTPException(404, "Unknown device")
    fields = body.model_dump(exclude_none=True)
    if "nickname" in fields:
        fields["nickname"] = fields["nickname"].strip() or None
    for k in ("notify_phone", "notify_email", "notify_return", "acknowledged", "critical"):
        if k in fields:
            fields[k] = int(fields[k])
    if "tags" in fields:
        fields["tags"] = _clean_tags(fields["tags"])
    if "snooze_minutes" in fields:
        minutes = fields.pop("snooze_minutes")
        fields["snooze_until"] = time.time() + minutes * 60 if minutes else None
        store.add_event("snooze", mac, None,
                        f"Alerts snoozed for {minutes} min" if minutes else "Snooze cleared")
    store.update_device(mac, **fields)
    return _enrich(store.get_device(mac))


class BulkAck(BaseModel):
    macs: list[str] = Field(max_length=1000)


@app.post("/api/devices/acknowledge")
def acknowledge(body: BulkAck):
    n = 0
    for mac in body.macs:
        if re.match(MAC_PATTERN, mac):
            n += store.update_device(mac.lower(), acknowledged=1)
    return {"acknowledged": n}


class TagAlerts(BaseModel):
    notify_phone: bool
    notify_email: bool


@app.post("/api/tags/{tag}/alerts")
def tag_alerts(body: TagAlerts, tag: str = Path(max_length=24)):
    tag = tag.lower()
    n = 0
    for d in store.all_devices():
        if tag in _split_tags(d.get("tags")):
            n += store.update_device(d["mac"], notify_phone=int(body.notify_phone),
                                     notify_email=int(body.notify_email))
    return {"updated": n}


@app.get("/api/devices/{mac}/history")
def device_history(mac: str = Path(pattern=MAC_PATTERN), days: int = Query(1, ge=1, le=30)):
    mac = mac.lower()
    dev = store.get_device(mac)
    if not dev:
        raise HTTPException(404, "Unknown device")
    now = time.time()
    p = dev_history.presence(store, dev, now - days * 86400, now)
    week = dev_history.presence(store, dev, now - 7 * 86400, now) if days != 7 else p
    return {
        "now": now, "days": days, **p, "availability_7d": week["availability"],
        "ip_history": dev_history.ip_history(store, mac),
        "events": store.events(limit=60, mac=mac),
        "checks": [c for c in store.checks() if c.get("mac") == mac],
    }


@app.get("/api/devices/{mac}/dns")
def device_dns(mac: str = Path(pattern=MAC_PATTERN), hours: int = Query(24, ge=1, le=24)):
    if not pihole.enabled:
        raise HTTPException(404, "Pi-hole integration is not configured")
    dev = store.get_device(mac.lower())
    if not dev or not dev.get("ip"):
        raise HTTPException(404, "Unknown device")
    return {"stats": pihole.stats_for(dev["ip"]), **pihole.top_domains(dev["ip"], hours)}


@app.post("/api/devices/{mac}/wake")
def wake(mac: str = Path(pattern=MAC_PATTERN)):
    mac = mac.lower()
    dev = store.get_device(mac)
    if not dev:
        raise HTTPException(404, "Unknown device")
    bcast = str(monitor.network.broadcast_address) if monitor.network else "255.255.255.255"
    try:
        sent_to = wol.send(mac, bcast)
    except (OSError, ValueError) as e:
        raise HTTPException(500, f"Could not send the wake packet: {e}") from None
    store.add_event("wake", mac, dev.get("ip"), "Wake-on-LAN packet sent")
    return {"ok": True, "sent_to": sent_to}


# Export
def _csv_safe(v):
    """Stop spreadsheet apps treating device names as formulas."""
    v = "" if v is None else str(v)
    return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


def _fmt_ts(ts):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else ""


@app.get("/api/export/devices.csv")
def export_devices():
    snap = router.snapshot() if router.enabled else None
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["name", "nickname", "hostname", "vendor", "ip", "mac", "online", "connected_since",
                "first_seen", "last_seen", "tags", "alert_phone", "alert_email", "reserved_ip", "dns_queries_24h"])
    for d in sorted(store.all_devices(), key=lambda d: ipaddress.IPv4Address(d["ip"] or "0.0.0.0")):
        e = _enrich(dict(d), snap)
        w.writerow([_csv_safe(x) for x in (
            display_name(d, router), d["nickname"], d["hostname"], d["vendor"], d["ip"], d["mac"],
            "yes" if d["online"] else "no", _fmt_ts(d["online_since"]) if d["online"] else "",
            _fmt_ts(d["first_seen"]), _fmt_ts(d["last_seen"]), " ".join(e["tags"]),
            "yes" if d["notify_phone"] else "no", "yes" if d["notify_email"] else "no",
            e.get("reserved_ip") or "", (e.get("dns") or {}).get("queries_24h", ""))])
    name = time.strftime("netwatch-devices-%Y%m%d.csv")
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@app.get("/api/export/backup")
def export_backup():
    fd, path = tempfile.mkstemp(prefix="netwatch-backup-", suffix=".db")
    os.close(fd)
    store.backup_to(path)
    return FileResponse(path, media_type="application/octet-stream",
                        filename=time.strftime("netwatch-backup-%Y%m%d-%H%M.db"),
                        background=BackgroundTask(os.remove, path))


# Settings
class SettingsUpdate(BaseModel):
    quiet_enabled: bool | None = None
    quiet_start: str | None = Field(default=None, max_length=5)
    quiet_end: str | None = Field(default=None, max_length=5)
    wan_alerts: str | None = None
    chatty_alerts: str | None = None
    chatty_factor: float | None = Field(default=None, ge=2, le=100)
    chatty_min_per_hour: int | None = Field(default=None, ge=10, le=1_000_000)


@app.get("/api/settings")
def get_settings():
    return {"settings": alerts.settings(), "defaults": DEFAULT_SETTINGS,
            "quiet_now": in_quiet_hours(alerts.settings()), "held_alerts": store.count_pending()}


@app.put("/api/settings")
def put_settings(body: SettingsUpdate):
    values = body.model_dump(exclude_none=True)
    try:
        for k in ("quiet_start", "quiet_end"):
            if k in values:
                values[k] = validate_time(values[k])
    except ValueError as e:
        raise HTTPException(400, str(e)) from None
    for k in ("wan_alerts", "chatty_alerts"):
        if k in values and values[k] not in CHANNEL_CHOICES:
            raise HTTPException(400, f"{k} must be one of {', '.join(CHANNEL_CHOICES)}")
    store.set_settings(values)
    return get_settings()


# Service checks
HOST_RE = re.compile(r"^[A-Za-z0-9.\-:\[\]]{1,253}$")


class CheckIn(BaseModel):
    name: str = Field(min_length=1, max_length=48)
    kind: str
    mac: str | None = Field(default=None, pattern=MAC_PATTERN)
    host: str | None = Field(default=None, max_length=253)
    port: int | None = Field(default=None, ge=1, le=65535)
    path: str | None = Field(default=None, max_length=200)
    https: bool = False
    verify_tls: bool = True
    interval: int = Field(default=60, ge=15, le=3600)
    timeout: float = Field(default=5, ge=1, le=30)
    fail_after: int = Field(default=2, ge=1, le=10)
    notify_phone: bool = False
    notify_email: bool = False
    enabled: bool = True


def _check_fields(body):
    f = body.model_dump()
    if f["kind"] not in CHECK_KINDS:
        raise HTTPException(400, "Type must be tcp, http or ping")
    if bool(f["mac"]) == bool(f["host"]):
        raise HTTPException(400, "Choose a device or enter a host, not both")
    if f["host"] and not HOST_RE.match(f["host"]):
        raise HTTPException(400, "Host must be an IP address or hostname")
    if f["mac"]:
        f["mac"] = f["mac"].lower()
        if not store.get_device(f["mac"]):
            raise HTTPException(400, "Unknown device")
    if f["kind"] == "tcp" and not f["port"]:
        raise HTTPException(400, "A TCP check needs a port")
    if f["kind"] == "http":
        path = f["path"] or "/"
        if not path.startswith("/") or any(c in path for c in " \r\n"):
            raise HTTPException(400, "Path must start with / and contain no spaces")
        f["path"] = path
    else:
        f["path"], f["https"] = None, False
    if f["kind"] == "ping":
        f["port"] = None
    for k in ("https", "verify_tls", "notify_phone", "notify_email", "enabled"):
        f[k] = int(f[k])
    f["name"] = " ".join(f["name"].split())
    return f


def _check_out(c):
    return {**c, **checker.summary(c), "target": checker.target_for(c)[0]}


@app.get("/api/checks")
def list_checks():
    return {"checks": [_check_out(c) for c in store.checks()]}


@app.post("/api/checks")
def add_check(body: CheckIn):
    if len(store.checks()) >= 100:
        raise HTTPException(400, "At most 100 service checks")
    f = _check_fields(body)
    check_id = store.insert_check(**f, created=time.time())
    return _check_out(store.get_check(check_id))


@app.put("/api/checks/{check_id}")
def edit_check(body: CheckIn, check_id: int = Path(ge=1)):
    c = store.get_check(check_id)
    if not c:
        raise HTTPException(404, "Unknown check")
    f = _check_fields(body)
    target_changed = any(f[k] != c[k] for k in ("kind", "mac", "host", "port", "path", "https"))
    if target_changed:
        f.update(state="unknown", since=None, fails=0)
    store.update_check(check_id, **f)
    return _check_out(store.get_check(check_id))


@app.delete("/api/checks/{check_id}")
def delete_check(check_id: int = Path(ge=1)):
    if not store.delete_check(check_id):
        raise HTTPException(404, "Unknown check")
    return {"ok": True}


@app.post("/api/checks/{check_id}/run")
def run_check(check_id: int = Path(ge=1)):
    c = store.get_check(check_id)
    if not c:
        raise HTTPException(404, "Unknown check")
    result = checker.run_check(c)
    return {"result": result, "check": _check_out(store.get_check(check_id))}


# Internet
@app.get("/api/internet")
def internet(days: int = Query(30, ge=1, le=365)):
    now = time.time()
    return {"status": wan.status(now), "outages": store.outages(limit=200, since=now - days * 86400)}


@app.delete("/api/devices/{mac}")
def forget_device(mac: str = Path(pattern=MAC_PATTERN)):
    if not store.delete_device(mac.lower()):
        raise HTTPException(404, "Unknown device")
    return {"ok": True}


@app.get("/api/ips")
def ip_map():
    net = monitor.network or (ipaddress.IPv4Network(cfg.subnet, strict=False) if cfg.subnet else None)
    if net is None:
        return {"subnet": None, "ips": []}
    snap = router.snapshot() if router.enabled else None
    reserved = snap["reserved_ips"] if snap else {}
    by_ip = {}
    for d in sorted(store.all_devices(), key=lambda d: (d["online"], d["last_seen"] or 0)):
        if d["ip"]:
            by_ip[d["ip"]] = d          # online / most recent wins
    out = []
    for i, host in enumerate(net.hosts()):
        if i >= 4096:
            break
        ip = str(host)
        d = by_ip.get(ip)
        res = reserved.get(ip)
        entry = {"ip": ip, "in_pool": router.in_dhcp_pool(ip, snap) if snap else None,
                 "reserved": bool(res), "reservation": res["description"] if res else None}
        if d is not None:
            entry.update(status="online" if d["online"] else "offline", mac=d["mac"],
                         name=d["nickname"] or (res and res["description"]) or d["hostname"] or d["vendor"],
                         last_seen=d["last_seen"])
        elif res:
            entry.update(status="reserved", mac=res["mac"], name=res["description"])
        elif snap and snap["router_ip"] == ip:
            entry.update(status="online", name="Router")
        else:
            entry["status"] = "free"
        out.append(entry)
    return {"subnet": str(net), "ips": out}


@app.get("/api/events")
def events(limit: int = Query(200, ge=1, le=2000),
           mac: str | None = Query(None, pattern=MAC_PATTERN)):
    return {"events": store.events(limit, mac.lower() if mac else None)}


@app.post("/api/scan")
def scan_now():
    monitor.trigger()
    return {"ok": True}


class TestNotification(BaseModel):
    phone: bool = True
    email: bool = True


@app.post("/api/test-notification")
def test_notification(body: TestNotification):
    return notifier.send_now(
        "Test notification",
        "If you can read this, NetWatch alerts are working.",
        phone=body.phone, email=body.email, tags=["bell"],
    )
